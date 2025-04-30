from datadog_lambda.dogstatsd import statsd
from datadog_lambda.stats_writer import StatsWriter


class StatsDWriter(StatsWriter):
    """
    Writes distribution metrics using StatsD protocol
    """

    def distribution(self, metric_name, value, tags=None, timestamp=None):
        statsd.distribution(metric_name, value, tags=tags, timestamp=timestamp)

    def flush(self):
        pass

    def stop(self):
        pass
