import pytest

from app.collectors.domain import DomainCollector


def test_normalizes_domain() -> None:
    assert DomainCollector.normalize_target("Example.COM.") == "example.com"


@pytest.mark.parametrize("value", [
    "http://example.com",
    "example.com/path",
    "user@example.com",
    "127.0.0.1",
    "localhost",
    "-invalid.example",
])
def test_rejects_invalid_or_non_domain_targets(value: str) -> None:
    with pytest.raises(ValueError):
        DomainCollector.normalize_target(value)
