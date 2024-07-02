import logging

# Make sure that this package would always be lazy-loaded/outside from the critical path
# since underlying packages are quite heavy to load and useless when the extension is present
from datadog.threadstats import ThreadStats
from datadog_lambda.stats_writer import StatsWriter

logger = logging.getLogger(__name__)


class ThreadStatsWriter(StatsWriter):
    """
    Writes distribution metrics using the ThreadStats class
    """

    def __init__(self, flush_in_thread):
        self.thread_stats = ThreadStats(compress_payload=True)
        self.thread_stats.start(flush_in_thread=flush_in_thread)

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        self.thread_stats.distribution(
            metric_name, value, tags=tags, timestamp=timestamp
        )

    def flush(self, tags=None):
        """ "Flush distributions from ThreadStats to Datadog.
        Modified based on `datadog.threadstats.base.ThreadStats.flush()`,
        to gain better control over exception handling.
        """
        if tags:
            self.thread_stats.constant_tags = self.thread_stats.constant_tags + tags
        _, dists = self.thread_stats._get_aggregate_metrics_and_dists(float("inf"))
        count_dists = len(dists)
        if not count_dists:
            logger.debug("No distributions to flush. Continuing.")

        self.thread_stats.flush_count += 1
        logger.debug(
            "Flush #%s sending %s distributions",
            self.thread_stats.flush_count,
            count_dists,
        )
        try:
            self.thread_stats.reporter.flush_distributions(dists)
        except Exception as e:
            # The nature of the root issue https://bugs.python.org/issue41345 is complex,
            # but comprehensive tests suggest that it is safe to retry on this specific error.
            if type(e).__name__ == "ClientError" and "RemoteDisconnected" in str(e):
                logger.debug(
                    "Retry flush #%s due to RemoteDisconnected",
                    self.thread_stats.flush_count,
                )
                try:
                    self.thread_stats.reporter.flush_distributions(dists)
                except Exception:
                    logger.debug(
                        "Flush #%s failed after retry",
                        self.thread_stats.flush_count,
                        exc_info=True,
                    )
            else:
                logger.debug(
                    "Flush #%s failed", self.thread_stats.flush_count, exc_info=True
                )

    def stop(self):
        self.thread_stats.stop()
