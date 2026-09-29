"""Shannon entropy: how unpredictable a string is, in bits per character.

Random keys score high (around 4 to 6); words and repeated characters score low.
"""

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of `value` in bits per character (0.0 for an empty string)."""
    if not value:
        return 0.0
    length = len(value)
    return sum(count / length * math.log2(length / count) for count in Counter(value).values())
