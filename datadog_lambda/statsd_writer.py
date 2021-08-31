from datadog_lambda.stats_writer import StatsWriter
from datadog_lambda.dogstatsd import statsd


class StatsDWriter(StatsWriter):
    """
    Writes distribution metrics using StatsD protocol
    """

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        statsd.distribution(metric_name, value, tags=tags)

    def flush(self):
        pass

    def stop(self):
        pass
