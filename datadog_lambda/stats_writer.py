class StatsWriter:
    def distribution(self, metric_name, value, tags=[], timestamp=None):
        raise NotImplementedError()

    def flush(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()