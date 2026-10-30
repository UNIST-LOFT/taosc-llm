"""Consumer-visible explicit-loading and child isolation guarantees."""

import json
from dataclasses import FrozenInstanceError

import pytest
from taosc_llm.provider import (
    ProviderConfig,
    ProviderConfigError,
    load_provider,
    native_environment,
)

SECRET = "offline-test-secret-never-real"


def provider_file(tmp_path, extra=""):
    path = tmp_path / "explicit-provider.conf"
    path.write_text(f'OPENAI_API_KEY="{SECRET}"\n'
                    "OPENAI_BASE_URL=https://ollama.com/v1\n"
                    "OPENAI_MODEL=deepseek-v4.1-flash:1017\n" + extra)
    return path


def test_explicit_loading_ignores_ambient_and_redacts(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "ambient-secret")
    monkeypatch.setenv("OPENAI_MODEL", "ambient-model")
    config = load_provider(provider_file(tmp_path))
    assert config.api_key == SECRET
    assert config.model == "deepseek-v4.1-flash:1017"
    assert SECRET not in repr(config)
    assert SECRET not in json.dumps(config.public_dict())
    assert "api_key" not in config.public_dict()
    with pytest.raises(FrozenInstanceError):
        setattr(config, "model", "changed")


def test_nonsecret_override_precedence(tmp_path):
    config = load_provider(provider_file(tmp_path, "TAOSC_LLM_WORKERS=2\nTAOSC_LLM_MAX_IN_FLIGHT=2\n"),
                           workers=5, max_in_flight=3,
                           base_url="https://ollama.com/v1", model="deepseek-v4.1-flash:1017")
    assert config.workers == 5
    assert config.max_in_flight == 3


@pytest.mark.parametrize("extra", [
    "OPENAI_API_KEY=another-secret\n", "UNRECOGNIZED=secret-value\n",
    "export OPENAI_API_KEY=secret-value\n", "TAOSC_LLM_WORKERS=0\n",
    "TAOSC_LLM_MAX_IN_FLIGHT=0\n", "TAOSC_LLM_MAX_IN_FLIGHT=4\n",
    "TAOSC_LLM_MAX_IN_FLIGHT=-1\n", "TAOSC_LLM_WORKERS=inf\n",
    "TAOSC_LLM_TIMEOUT_SECONDS=1.5\n",
])
def test_invalid_fields_do_not_echo_values(tmp_path, extra):
    with pytest.raises(ProviderConfigError) as error:
        load_provider(provider_file(tmp_path, extra))
    assert SECRET not in str(error.value)
    assert "secret-value" not in str(error.value)
    assert "another-secret" not in str(error.value)


@pytest.mark.parametrize("value", ["", "your-api-key", "<key>", "${OPENAI_API_KEY}",
                                    "$(touch /tmp/not-executed)", "`command`", "changeme"])
def test_placeholders_and_shell_substitutions_rejected(tmp_path, value):
    path = provider_file(tmp_path)
    path.write_text(path.read_text().replace(SECRET, value))
    with pytest.raises(ProviderConfigError) as error:
        load_provider(path)
    assert str(error.value) == "invalid api_key"


@pytest.mark.parametrize("overrides", [
    {"base_url": "https://openai.com/v1"},
    {"base_url": "https://ollama.com/v1/"},
    {"model": "deepseek-v4.1-flash:cloud"},
    {"workers": True}, {"max_in_flight": -1},
])
def test_unsupported_routing_and_invalid_overrides(tmp_path, overrides):
    with pytest.raises(ProviderConfigError):
        load_provider(provider_file(tmp_path), **overrides)


@pytest.mark.parametrize("output_tokens", [64000, 64001])
def test_output_budget_respects_explicit_context(tmp_path, output_tokens):
    path = provider_file(tmp_path, "TAOSC_LLM_CONTEXT_WINDOW=64000\n"
                         f"TAOSC_LLM_MAX_TOKENS={output_tokens}\n")
    if output_tokens > 64000:
        with pytest.raises(ProviderConfigError):
            load_provider(path)
    else:
        config = load_provider(path)
        assert config.max_tokens == config.context_window == 64000


def test_no_ambient_fallback_for_missing_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    path = provider_file(tmp_path)
    path.write_text("OPENAI_BASE_URL=https://ollama.com/v1\nOPENAI_MODEL=deepseek-v4.1-flash:1017\n")
    with pytest.raises(ProviderConfigError, match="missing api_key"):
        load_provider(path)


def test_native_environment_is_nonsecret_allowlist(monkeypatch):
    monkeypatch.setenv("PATH", "/explicit/bin")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("E9TOOL", "/explicit/e9tool")
    monkeypatch.setenv("E9COMPILE", "/explicit/e9compile")
    for name in ("OPENAI_API_KEY", "OLLAMA_API_KEY", "AWS_SECRET_ACCESS_KEY",
                 "NODE_OPTIONS", "LD_PRELOAD", "HOME", "PYTHONPATH", "SDK_ROOT"):
        monkeypatch.setenv(name, SECRET)
    environment = native_environment()
    assert SECRET not in json.dumps(environment)
    assert not set(environment).intersection({"OPENAI_API_KEY", "OLLAMA_API_KEY",
        "AWS_SECRET_ACCESS_KEY", "NODE_OPTIONS", "LD_PRELOAD", "HOME", "PYTHONPATH", "SDK_ROOT"})


def test_explicit_generic_profile_admits_custom_model_and_cap_zero(tmp_path):
    path = provider_file(tmp_path, "TAOSC_LLM_PROFILE=openai-compatible\n"
                                   "TAOSC_LLM_MAX_IN_FLIGHT=0\nTAOSC_LLM_WORKERS=4\n")
    loaded = load_provider(path, base_url="https://provider.example/api/v1",
                           model="explicit-opaque-model:revision")
    assert loaded.base_url == "https://provider.example/api/v1"
    assert loaded.model == "explicit-opaque-model:revision"
    assert loaded.max_in_flight == 0
    assert loaded.workers == 4


@pytest.mark.parametrize("extra", ["TAOSC_LLM_PROFILE=unknown-profile\n",
                                    "TAOSC_LLM_PROFILE=ollama-dev\nTAOSC_LLM_PROFILE=openai-compatible\n"])
def test_unknown_and_duplicate_profiles_fail_closed(tmp_path, extra):
    with pytest.raises(ProviderConfigError):
        load_provider(provider_file(tmp_path, extra))


def test_explicit_dev_profile_preserves_exact_route(tmp_path):
    path = provider_file(tmp_path, "TAOSC_LLM_PROFILE=ollama-dev\n")
    assert load_provider(path).model == "deepseek-v4.1-flash:1017"
    with pytest.raises(ProviderConfigError):
        load_provider(path, base_url="https://provider.example/v1")


@pytest.mark.parametrize("endpoint", [
    "http://provider.example/v1", "https://user:password@provider.example/v1",
    "https://user@provider.example/v1", "https://provider.example/v1?token=secret",
    "https://provider.example/v1#secret", "https://provider.example/v1?",
    "https://provider.example/v1#", "https:///v1", "https://provider.example:bad/v1",
    "https://provider.example:0/v1", "https://provider.example:65536/v1",
    "https://ollama%2ecom/v1",
    "https://provider.example /v1", "https://provider.example\\\\other/v1",
])
def test_generic_profile_rejects_unsafe_urls(tmp_path, endpoint):
    path = provider_file(tmp_path, "TAOSC_LLM_PROFILE=openai-compatible\n")
    with pytest.raises(ProviderConfigError) as error:
        load_provider(path, base_url=endpoint)
    assert str(error.value) == "invalid base_url"


@pytest.mark.parametrize("overrides", [
    {"max_in_flight": 0}, {"max_in_flight": 4}, {"model": "substitute-model"},
    {"base_url": "https://OLLAMA.COM/v1"},
    {"base_url": "https://ollama.com./v1"},
    {"base_url": "https://ollama.com:443/v1"},
    {"base_url": "https://ollama.com/different-path"},
])
def test_generic_profile_cannot_bypass_known_ollama_account_policy(tmp_path, overrides):
    path = provider_file(tmp_path, "TAOSC_LLM_PROFILE=openai-compatible\n")
    with pytest.raises(ProviderConfigError):
        load_provider(path, **overrides)


@pytest.mark.parametrize("overrides", [
    {"max_in_flight": 0}, {"max_in_flight": 4}, {"model": "substitute-model"},
    {"base_url": "https://subdomain.ollama.com/v1", "max_in_flight": 0},
])
def test_direct_api_cannot_bypass_known_account_policy(overrides):
    with pytest.raises(ProviderConfigError):
        ProviderConfig(api_key=SECRET, **overrides)
