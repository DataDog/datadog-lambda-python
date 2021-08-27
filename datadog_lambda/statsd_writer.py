from datadog_lambda.stats_writer import StatsWriter
from datadog.dogstatsd import statsd


class StatsDWriter(StatsWriter):
    """
    Writes distribution metrics using StatsD protocol
    """

    def __init__(self):
        statsd.host = "127.0.0.1"
        statsd.port = 8125

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        statsd.distribution(metric_name, value, tags=tags)

    def flush(self):
        pass

    def stop(self):
        pass
