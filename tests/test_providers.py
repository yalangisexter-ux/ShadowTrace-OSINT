import pytest
from app.providers import validate_username, PROVIDERS

def test_valid_username(): assert validate_username("octocat_42") == "octocat_42"
@pytest.mark.parametrize("value", ["", "a", "two words", "../admin", "x"*31, "user?x=1"])
def test_invalid_username(value):
    with pytest.raises(ValueError): validate_username(value)
def test_fixed_https_allowlist():
    assert len(PROVIDERS) >= 5
    assert all(p.url_template.startswith("https://") and "{username}" in p.url_template for p in PROVIDERS)
