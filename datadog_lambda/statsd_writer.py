from datadog_lambda.stats_writer import StatsWriter
from datadog import initialize, statsd


class StatsDWriter(StatsWriter):
    """
    Writes distribution metrics using StatsD protocol
    """

    def __init__(self):
        options = {"statsd_host": "127.0.0.1", "statsd_port": 8125}
        initialize(**options)

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        statsd.distribution(metric_name, value, tags=tags)

    def flush(self):
        pass

    def stop(self):
        pass
