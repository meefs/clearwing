from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from langchain_core.language_models import BaseChatModel

from .env import LLMEndpoint, resolve_llm_endpoint

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider."""

    name: str  # anthropic, openai, google, ollama, bedrock
    model: str  # model identifier
    api_key: str = ""  # empty = use env var
    base_url: str = ""  # for custom endpoints (Ollama, etc.)
    max_tokens: int = 4096
    temperature: float = 0.0


@dataclass
class ModelRoute:
    """Maps a task type to a specific provider/model."""

    task: str  # recon, exploit, report, planning, default
    provider: str
    model: str
    reason: str = ""  # why this model for this task


PROVIDER_PRESETS = {
    "anthropic": {
        "class": "langchain_anthropic.ChatAnthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "models": ["claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
    },
    "openai": {
        "class": "langchain_openai.ChatOpenAI",
        "env_key": "OPENAI_API_KEY",
        "models": ["gpt-4o", "gpt-4o-mini", "o1-preview"],
    },
    "google": {
        "class": "langchain_google_genai.ChatGoogleGenerativeAI",
        "env_key": "GOOGLE_API_KEY",
        "models": ["gemini-2.0-flash", "gemini-2.5-pro"],
    },
    "ollama": {
        "class": "langchain_ollama.ChatOllama",
        "env_key": "",
        "models": [],  # dynamic
        "default_base_url": "http://localhost:11434",
    },
}

DEFAULT_ROUTES = [
    ModelRoute(
        task="recon",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="Fast, cheap for scanning",
    ),
    ModelRoute(
        task="exploit",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Strong reasoning for exploitation",
    ),
    ModelRoute(
        task="report",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="Report generation doesn't need top model",
    ),
    ModelRoute(
        task="planning",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Good planning capabilities",
    ),
    ModelRoute(
        task="default", provider="anthropic", model="claude-sonnet-4-6", reason="Default model"
    ),
    # Sourcehunt routes — see plan §Provider routing.
    # Hunter and verifier are deliberately different tiers from the same provider:
    # independence comes from tier, not provider, so users with only ANTHROPIC_API_KEY
    # get sensible defaults without needing a second account. YAML config can upgrade.
    ModelRoute(
        task="ranker",
        provider="anthropic",
        model="claude-haiku-4-5-20251001",
        reason="File ranking is simple classification",
    ),
    ModelRoute(
        task="hunter",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Core vuln-finding reasoning",
    ),
    ModelRoute(
        task="verifier",
        provider="anthropic",
        model="claude-sonnet-4-6",
        reason="Independent verification — different tier from hunter",
    ),
    ModelRoute(
        task="sourcehunt_exploit",
        provider="anthropic",
        model="claude-opus-4-6",
        reason="Exploit generation is hardest reasoning",
    ),
]


class ProviderManager:
    """Manages multiple LLM providers with task-based routing.

    There are three ways to construct a ProviderManager:

    1. `ProviderManager()` — default constructor with no overrides.
       Every task routes to its `DEFAULT_ROUTES` entry, which means
       Anthropic direct via `ANTHROPIC_API_KEY`.

    2. `ProviderManager.for_endpoint(endpoint)` — one endpoint routes
       every task. Used when the operator wants ONE model/backend for
       everything (the common case: OpenRouter, Ollama, LM Studio).
       The `endpoint` arg comes from `resolve_llm_endpoint()`, which
       merges CLI / env / config / default.

    3. `ProviderManager.from_config(cfg)` — multi-provider routing
       from a `~/.clearwing/config.yaml` `providers:` + `routes:`
       section. Each task can land on a different provider. This is
       the power-user case (e.g., "hunter uses OpenRouter Opus,
       verifier uses local Qwen, ranker uses Haiku direct").
    """

    def __init__(
        self,
        configs: list[ProviderConfig] | None = None,
        routes: list[ModelRoute] | None = None,
        endpoint: LLMEndpoint | None = None,
    ):
        self._configs: dict[str, ProviderConfig] = {}
        self._routes: dict[str, ModelRoute] = {}
        self._llm_cache: dict[str, BaseChatModel] = {}
        # When `endpoint` is set, every get_llm() call returns the
        # same ChatOpenAI (or ChatAnthropic) instance regardless of
        # task. This is the "one endpoint for everything" mode.
        self._global_endpoint: LLMEndpoint | None = endpoint

        if configs:
            for c in configs:
                self._configs[c.name] = c

        # Set up routes
        for route in routes or DEFAULT_ROUTES:
            self._routes[route.task] = route

    # --- Constructors -----------------------------------------------------

    @classmethod
    def for_endpoint(cls, endpoint: LLMEndpoint) -> ProviderManager:
        """Build a ProviderManager that routes every task to one endpoint.

        The common case: operator sets `--base-url https://openrouter.ai/api/v1
        --model anthropic/claude-opus-4 --api-key sk-or-...` (or the
        `CLEARWING_BASE_URL` / `CLEARWING_MODEL` / `CLEARWING_API_KEY`
        env triple), and every sourcehunt task (ranker / hunter /
        verifier / sourcehunt_exploit / default) dispatches against
        that same endpoint.
        """
        return cls(endpoint=endpoint)

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> ProviderManager:
        """Build a ProviderManager from a parsed YAML config dict.

        Expected shape (all fields optional):

            provider:                  # single-endpoint mode
              base_url: https://...
              api_key: ${ENV_VAR}
              model: anthropic/claude-opus-4

            # OR

            providers:                 # multi-endpoint routing mode
              openrouter:
                base_url: https://openrouter.ai/api/v1
                api_key: ${OPENROUTER_API_KEY}
              local_llama:
                base_url: http://localhost:11434/v1
                api_key: ollama

            routes:
              default: openrouter
              hunter: openrouter
              verifier: local_llama       # independence via tier
              ranker: openrouter
              sourcehunt_exploit: openrouter

            task_models:
              hunter: anthropic/claude-opus-4
              verifier: qwen2.5-coder:32b
              ranker: anthropic/claude-haiku-4-5
        """
        # Single-endpoint mode
        single = cfg.get("provider")
        if single:
            endpoint = resolve_llm_endpoint(config_provider=single)
            return cls.for_endpoint(endpoint)

        # Multi-endpoint routing mode
        providers_cfg = cfg.get("providers", {})
        routes_cfg = cfg.get("routes", {})
        models_cfg = cfg.get("task_models", {})

        configs: list[ProviderConfig] = []
        for name, pcfg in providers_cfg.items():
            base_url = pcfg.get("base_url", "")
            raw_key = pcfg.get("api_key")
            api_key = _expand_env(raw_key) if raw_key else ""
            configs.append(
                ProviderConfig(
                    name=name,
                    model=pcfg.get("model", ""),
                    api_key=api_key,
                    base_url=base_url,
                )
            )

        routes: list[ModelRoute] = list(DEFAULT_ROUTES)
        # Override any task that has a routes: entry
        for task, target_provider in routes_cfg.items():
            model = (
                models_cfg.get(task)
                or providers_cfg.get(target_provider, {}).get("model")
                or "default"
            )
            # Replace any existing default for this task
            routes = [r for r in routes if r.task != task]
            routes.append(
                ModelRoute(
                    task=task,
                    provider=target_provider,
                    model=model,
                    reason=f"Configured via ~/.clearwing/config.yaml routes:{task}",
                )
            )

        return cls(configs=configs, routes=routes)

    # --- Get an LLM for a task --------------------------------------------

    def get_llm(self, task: str = "default") -> BaseChatModel:
        """Get the appropriate LLM for a task type."""
        # Single-endpoint mode: every task gets the same LLM
        if self._global_endpoint is not None:
            cache_key = f"_global_:{self._global_endpoint.model}"
            if cache_key not in self._llm_cache:
                self._llm_cache[cache_key] = self._create_llm_from_endpoint(self._global_endpoint)
            return self._llm_cache[cache_key]

        route = self._routes.get(task, self._routes.get("default"))
        if not route:
            raise ValueError(f"No route configured for task: {task}")

        cache_key = f"{route.provider}:{route.model}"
        if cache_key not in self._llm_cache:
            self._llm_cache[cache_key] = self._create_llm(route.provider, route.model)

        return self._llm_cache[cache_key]

    def _create_llm_from_endpoint(self, endpoint: LLMEndpoint) -> BaseChatModel:
        """Build a BaseChatModel from a resolved LLMEndpoint."""
        if endpoint.is_openai_compat:
            from langchain_openai import ChatOpenAI

            kwargs: dict[str, Any] = {
                "model": endpoint.model,
                "base_url": endpoint.base_url,
            }
            if endpoint.api_key:
                kwargs["api_key"] = endpoint.api_key
            return ChatOpenAI(**kwargs)

        # Anthropic direct (the default fallback path)
        from langchain_anthropic import ChatAnthropic

        kwargs = {"model": endpoint.model}
        if endpoint.api_key:
            kwargs["api_key"] = endpoint.api_key
        return ChatAnthropic(**kwargs)

    def _create_llm(self, provider: str, model: str) -> BaseChatModel:
        """Create an LLM instance for a given provider and model."""
        config = self._configs.get(provider)
        preset = PROVIDER_PRESETS.get(provider)

        if provider == "anthropic":
            from langchain_anthropic import ChatAnthropic

            kwargs = {"model": model}
            if config and config.api_key:
                kwargs["api_key"] = config.api_key
            if config and config.max_tokens:
                kwargs["max_tokens"] = config.max_tokens
            return ChatAnthropic(**kwargs)

        elif provider == "openai":
            try:
                from langchain_openai import ChatOpenAI
            except ImportError as e:
                raise ImportError("Install langchain-openai: pip install langchain-openai") from e
            kwargs = {"model": model}
            if config and config.api_key:
                kwargs["api_key"] = config.api_key
            if config and config.base_url:
                kwargs["base_url"] = config.base_url
            return ChatOpenAI(**kwargs)

        elif provider == "google":
            try:
                from langchain_google_genai import ChatGoogleGenerativeAI
            except ImportError as e:
                raise ImportError(
                    "Install langchain-google-genai: pip install langchain-google-genai"
                ) from e
            kwargs = {"model": model}
            if config and config.api_key:
                kwargs["google_api_key"] = config.api_key
            return ChatGoogleGenerativeAI(**kwargs)

        elif provider == "ollama":
            try:
                from langchain_ollama import ChatOllama
            except ImportError as e:
                raise ImportError("Install langchain-ollama: pip install langchain-ollama") from e
            kwargs = {"model": model}
            base_url = (
                config.base_url
                if config and config.base_url
                else preset.get("default_base_url", "http://localhost:11434")
            )
            kwargs["base_url"] = base_url
            return ChatOllama(**kwargs)

        else:
            raise ValueError(f"Unknown provider: {provider}")

    def list_providers(self) -> list[str]:
        """List all configured provider names."""
        return list(self._configs.keys())

    def list_routes(self) -> list[ModelRoute]:
        """List all configured routes."""
        return list(self._routes.values())

    def set_route(self, task: str, provider: str, model: str, reason: str = ""):
        """Update or add a route for a task type."""
        self._routes[task] = ModelRoute(task=task, provider=provider, model=model, reason=reason)
        # Invalidate cache for this route
        cache_key = f"{provider}:{model}"
        self._llm_cache.pop(cache_key, None)

    def get_route_info(self) -> str:
        """Human-readable summary of current routing."""
        if self._global_endpoint is not None:
            return (
                "Model Routing:\n"
                f"  (all tasks) → {self._global_endpoint.describe()}\n"
                f"  provider: {self._global_endpoint.provider}"
            )
        lines = ["Model Routing:"]
        for task, route in sorted(self._routes.items()):
            lines.append(f"  {task}: {route.provider}/{route.model} ({route.reason})")
        return "\n".join(lines)


def _expand_env(value: Any) -> str:
    """Expand `${ENV_VAR}` in a config string. Empty string if unset.

    Kept module-private so `from_config` can reuse the same expansion
    rule as `providers.env._resolve_config_secret` without either
    module depending on the other.
    """
    import os

    if value is None:
        return ""
    s = str(value).strip()
    if s.startswith("${") and s.endswith("}"):
        return os.environ.get(s[2:-1], "")
    return s
