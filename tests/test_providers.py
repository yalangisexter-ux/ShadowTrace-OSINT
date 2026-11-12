import pytest
from app.providers import validate_username, PROVIDERS, provider_count

def test_valid_username():
    assert validate_username("octocat_42") == "octocat_42"

@pytest.mark.parametrize("value", ["", "a", "two words", "../admin", "x"*31, "user?x=1"])
def test_invalid_username(value):
    with pytest.raises(ValueError):
        validate_username(value)

def test_fixed_https_allowlist():
    assert provider_count() >= 15
    assert all(p.url_template.startswith("https://") and "{username}" in p.url_template for p in PROVIDERS)

def test_categories_present():
    cats = {p.category for p in PROVIDERS}
    assert "code" in cats
    assert "social" in cats
