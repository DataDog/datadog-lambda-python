import sys
from os.path import abspath
from os.path import isfile
from types import ModuleType
from typing import Optional
from typing import Set
from typing import Union

# Borrowed from the wrapt module
# https://github.com/GrahamDumpleton/wrapt/blob/df0e62c2740143cceb6cafea4c306dae1c559ef8/src/wrapt/importer.py

# if PY2 panic (sys.version_info < (3, 6)) else:
from importlib.abc import Loader
from importlib.machinery import ModuleSpec
from importlib.util import find_spec
from datadog_lambda.cold_start_tracing import push_node, pop_node


def origin(module):
    # type: (ModuleType) -> str
    """Get the origin source file of the module."""
    try:
        # DEV: Use object.__getattribute__ to avoid potential side-effects.
        orig = abspath(object.__getattribute__(module, "__file__"))
    except (AttributeError, TypeError):
        # Module is probably only partially initialised, so we look at its
        # spec instead
        try:
            # DEV: Use object.__getattribute__ to avoid potential side-effects.
            orig = abspath(object.__getattribute__(module, "__spec__").origin)
        except (AttributeError, ValueError, TypeError):
            orig = None

    if orig is not None and isfile(orig):
        if orig.endswith(".pyc"):
            orig = orig[:-1]
        return orig

    return "<unknown origin>"



class _ImportHookChainedLoader(Loader):
    def __init__(self, loader):
        # type: (Loader) -> None
        self.loader = loader

        # # DEV: load_module is deprecated so we define it at runtime if also
        # # defined by the default loader. We also check and define for the
        # # methods that are supposed to replace the load_module functionality.
        # if hasattr(loader, "load_module"):
        #     self.load_module = self._load_module  # type: ignore[assignment]
        if hasattr(loader, "create_module"):
            self.create_module = self._create_module  # type: ignore[assignment]
        if hasattr(loader, "exec_module"):
            self.exec_module = self._exec_module  # type: ignore[assignment]

    def __getattribute__(self, name):
        if name == "__class__":
            # Make isinstance believe that self is also an instance of
            # type(self.loader). This is required, e.g. by some tools, like
            # slotscheck, that can handle known loaders only.
            return self.loader.__class__

        return super(_ImportHookChainedLoader, self).__getattribute__(name)

    def __getattr__(self, name):
        # Proxy any other attribute access to the underlying loader.
        return getattr(self.loader, name)

    def _create_module(self, spec):
        # print(f"[CST] Create module for spec {spec}")
        push_node(spec)
        return self.loader.create_module(spec)

    def _exec_module(self, module):
        # print(f"[CST] Exec module for spec {module}")
        self.loader.exec_module(module)
        pop_node(module)


class ModuleWatchdog(object):

    _instance = None  # type: Optional[ModuleWatchdog]

    def __init__(self):
        self._finding = set()  # type: Set[str]

    def __repr__(self) -> str:
        return "ModuleWatchdog"

    def _add_to_meta_path(self):
        # type: () -> None
        sys.meta_path.insert(0, self)  # type: ignore[arg-type]

    @classmethod
    def _find_in_meta_path(cls):
        # type: () -> Optional[int]
        for i, meta_path in enumerate(sys.meta_path):
            if type(meta_path) is cls:
                return i
        return None

    @classmethod
    def _remove_from_meta_path(cls):
        # type: () -> None
        i = cls._find_in_meta_path()
        if i is not None:
            sys.meta_path.pop(i)

    def find_module(self, fullname, path=None):
        # type: (str, Optional[str]) -> Union[ModuleWatchdog, _ImportHookChainedLoader, None]
        if fullname in self._finding:
            return None

        self._finding.add(fullname)
        # print(f"[CST] finding module for {fullname}")
        try:
            loader = getattr(find_spec(fullname), "loader", None)
            if loader is not None:
                if not isinstance(loader, _ImportHookChainedLoader):
                    loader = _ImportHookChainedLoader(loader)

                return loader
        finally:
            self._finding.remove(fullname)

        return None

    def find_spec(self, fullname, path=None, target=None):
        # type: (str, Optional[str], Optional[ModuleType]) -> Optional[ModuleSpec]
        if fullname in self._finding:
            return None

        self._finding.add(fullname)
        # print(f"[CST] finding spec for {fullname} ")
        try:
            spec = find_spec(fullname)
            if spec is None:
                return None
            loader = getattr(spec, "loader", None)

            if loader is not None:
                if not isinstance(loader, _ImportHookChainedLoader):
                    spec.loader = _ImportHookChainedLoader(loader)
                # push_node(spec)
                # cast(_ImportHookChainedLoader, spec.loader).add_callback(type(self), self.after_import)

            return spec

        finally:
            self._finding.remove(fullname)


    @classmethod
    def _check_installed(cls):
        # type: () -> None
        if not cls.is_installed():
            raise RuntimeError("%s is not installed" % cls.__name__)

    @classmethod
    def install(cls):
        # type: () -> None
        """Install the module watchdog."""
        if cls.is_installed():
            raise RuntimeError("%s is already installed" % cls.__name__)
        this = cls()
        cls._instance = this
        this._add_to_meta_path()

    @classmethod
    def is_installed(cls):
        """Check whether this module watchdog class is installed."""
        return cls._instance is not None and type(cls._instance) is cls

    @classmethod
    def uninstall(cls):
        cls._check_installed()
        cls._remove_from_meta_path()
        cls._instance = None


