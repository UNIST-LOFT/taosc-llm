"""Explicit, data-only provider configuration and nonsecret child environments."""

import os
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class ProviderConfigError(ValueError):
    """Invalid provider input; messages identify fields, never supplied values."""


@dataclass(frozen=True)
class ProviderConfig:
    api_key: str = field(repr=False)
    base_url: str = "https://ollama.com/v1"
    model: str = "deepseek-v4.1-flash:1017"
    max_in_flight: int = 3
    workers: int = 3
    context_window: int = 32768
    max_tokens: int = 8192
    timeout_seconds: int = 600
    max_turns: int = 16
    max_tool_calls: int = 64

    def __post_init__(self):
        for name in ("api_key", "base_url", "model"):
            _validate_text(name, getattr(self, name))
        _validate_url(self.base_url)
        for name in ("max_in_flight", "workers", "context_window", "max_tokens",
                     "timeout_seconds", "max_turns", "max_tool_calls"):
            value = getattr(self, name)
            if type(value) is not int or value < (0 if name == "max_in_flight" else 1):
                raise ProviderConfigError(f"invalid {name}")
        if self.max_tokens > self.context_window:
            raise ProviderConfigError("invalid max_tokens")
        hostname = urlsplit(self.base_url).hostname
        assert hostname is not None
        hostname = hostname.rstrip(".").lower()
        if hostname == "ollama.com" or hostname.endswith(".ollama.com"):
            if self.base_url != "https://ollama.com/v1":
                raise ProviderConfigError("unsupported base_url")
            if self.model != "deepseek-v4.1-flash:1017":
                raise ProviderConfigError("unsupported model")
            if not 1 <= self.max_in_flight <= 3:
                raise ProviderConfigError("invalid max_in_flight")

    def public_dict(self) -> dict:
        """Client bounds are not assertions about provider capabilities."""
        return {item.name: getattr(self, item.name) for item in fields(self)
                if item.name != "api_key"}


_FIELDS = {
    "OPENAI_API_KEY": "api_key",
    "OPENAI_BASE_URL": "base_url",
    "OPENAI_MODEL": "model",
    "TAOSC_LLM_PROFILE": "profile",
    **{f"TAOSC_LLM_{name.upper()}": name for name in (
        "max_in_flight", "workers", "context_window", "max_tokens",
        "timeout_seconds", "max_turns", "max_tool_calls")},
}
_PLACEHOLDERS = {"changeme", "change-me", "replace-me", "replace_me", "your-api-key",
                 "your_api_key", "your-key", "your_key", "placeholder", "todo", "xxx",
                 "example", "...", "sk-...", "your_ollama_api_key", "your-ollama-api-key"}


def _validate_text(name: str, value: str) -> None:
    if (not isinstance(value, str) or len(value) > 4096 or not value.strip() or value != value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or value.lower() in _PLACEHOLDERS
            or any(token in value for token in ("${", "$(", "`", "<", ">"))
            or value.lower().startswith(("replace_", "replace-", "your_", "your-"))):
        raise ProviderConfigError(f"invalid {name}")


def _validate_url(value: str) -> None:
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or "@" in parsed.netloc or "%" in parsed.netloc
                or "?" in value or "#" in value or "\\" in value
                or any(char.isspace() for char in value)
                or parsed.port == 0):
            raise ValueError
    except ValueError:
        raise ProviderConfigError("invalid base_url") from None


def load_provider(path: Path, *, base_url=None, model=None,
                  max_in_flight=None, workers=None) -> ProviderConfig:
    """Load only the selected file; CLI nonsecret overrides take precedence.

    TAOSC_LLM_PROFILE defaults to ollama-dev. Explicit openai-compatible admits
    another HTTPS endpoint/model and cap zero; it never relaxes Ollama policy.
    Profile is loader policy only and is not forwarded to the adapter.

    Syntax: blank lines, full-line comments, and KEY=value assignments. A pair
    of matching quotes is removed literally; interpolation/escapes/export and
    inline comments are not shell syntax and are not evaluated.
    """
    try:
        with Path(path).open(encoding="utf-8") as stream:
            text = stream.read(65537)
        if len(text) > 65536:
            raise ProviderConfigError("provider configuration exceeds size bound")
    except (OSError, UnicodeError):
        raise ProviderConfigError("cannot read provider configuration") from None
    values: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in _FIELDS:
            raise ProviderConfigError("invalid provider configuration field")
        name = _FIELDS[key]
        if name in values:
            raise ProviderConfigError(f"duplicate {name}")
        value = value.strip()
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ProviderConfigError(f"invalid {name}")
            value = value[1:-1]
        _validate_text(name, value)
        values[name] = value
    for name in ("api_key", "base_url", "model"):
        if name not in values:
            raise ProviderConfigError(f"missing {name}")
    for name, value in (("base_url", base_url), ("model", model),
                        ("max_in_flight", max_in_flight), ("workers", workers)):
        if value is not None:
            values[name] = value
    for name in ("max_in_flight", "workers", "context_window", "max_tokens",
                 "timeout_seconds", "max_turns", "max_tool_calls"):
        if name in values and isinstance(values[name], str):
            if not re.fullmatch(r"[0-9]+", values[name]):
                raise ProviderConfigError(f"invalid {name}")
            try:
                values[name] = int(values[name])
            except ValueError:
                raise ProviderConfigError(f"invalid {name}") from None
    profile = values.pop("profile", "ollama-dev")
    if profile not in ("ollama-dev", "openai-compatible"):
        raise ProviderConfigError("unsupported profile")
    config = ProviderConfig(**values)
    # Default profile never silently routes to a different provider. Known
    # Ollama endpoint/model/cap invariants also hold for direct API construction.
    if profile == "ollama-dev" and config.base_url != "https://ollama.com/v1":
        raise ProviderConfigError("unsupported base_url")
    return config


def native_environment() -> dict[str, str]:
    """Do not inherit credentials, HOME, preload hooks, or SDK discovery state."""
    allowed = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_MESSAGES",
               "LC_NUMERIC", "LC_TIME", "E9TOOL", "E9COMPILE",
               "C_INCLUDE_PATH", "LIBRARY_PATH")
    return {name: os.environ[name] for name in allowed if name in os.environ}
