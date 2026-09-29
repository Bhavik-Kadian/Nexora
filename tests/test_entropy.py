"""Shannon entropy in bits per character."""

import math
import string

import pytest

from securegate.entropy import shannon_entropy


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("aabb", 1.0), ("abcd", 2.0), ("abcdefgh", 3.0)],
)
def test_known_values(value: str, expected: float) -> None:
    assert shannon_entropy(value) == pytest.approx(expected)


def test_order_of_characters_does_not_matter() -> None:
    assert shannon_entropy("abcabc") == pytest.approx(shannon_entropy("aabbcc"))
    assert shannon_entropy("abcabc") == pytest.approx(shannon_entropy("cbacba"))


def test_more_variety_means_higher_entropy() -> None:
    all_distinct = string.ascii_letters + string.digits  # 62 different characters
    assert shannon_entropy(all_distinct) == pytest.approx(math.log2(62))
    assert shannon_entropy(all_distinct) > shannon_entropy("aaaaaaaabbbbbbbb")


def test_zero_is_never_negative() -> None:
    assert math.copysign(1.0, shannon_entropy("zzzz")) == 1.0
