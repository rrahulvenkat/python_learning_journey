"""Robust statistics for baselines: copied from python_learning_journey/fundamentals/statistics_and_baselines.py, where it's explained step by step.

robust_z uses the median and MAD, which a few attack days in the history
can't drag around the way they drag a mean. When more than half the
history is one value the MAD is 0, so it falls back to the mean absolute
deviation.
"""

import math
import statistics
from collections import Counter

def mad(history):
    centre = statistics.median(history)
    return statistics.median(abs(x - centre) for x in history)


def robust_z(value, history):
    centre = statistics.median(history)
    spread = mad(history)
    if spread:
        return 0.6745 * (value - centre) / spread
    mean_ad = statistics.fmean(abs(x - centre) for x in history)
    if mean_ad:
        return (value - centre) / (1.2533 * mean_ad)
    return 0.0 if value == centre else math.inf


def active_hours(login_hours, min_share=0.02):
    """Hours that make up at least `min_share` of this user's logins."""
    counts = Counter(login_hours)
    total = sum(counts.values())
    return {h for h, n in counts.items() if n / total >= min_share}
