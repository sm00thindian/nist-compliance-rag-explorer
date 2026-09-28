"""
One small interface for text-completion providers, so the model is a config
choice rather than a code change.

    LLM_PROVIDER=anthropic   ANTHROPIC_API_KEY, ANTHROPIC_MODEL (default claude-sonnet-5)
    LLM_PROVIDER=bedrock     AWS credentials, AWS_REGION, BEDROCK_MODEL_ID (required)
    LLM_PROVIDER=openai      OPENAI_API_KEY, OPENAI_MODEL (required), OPENAI_BASE_URL (optional)
    LLM_PROVIDER=xai         XAI_API_KEY, XAI_MODEL (required), XAI_BASE_URL (default https://api.x.ai/v1)

Which provider you may use for which data is a policy decision. In this
project only the check generator calls a model, and it only sends public
STIG text (see generator.PublicRequirement).
"""
import os
from typing import Optional, Protocol


class LLMClient(Protocol):
    name: str

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str: ...


class AnthropicClient:
    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None):
        import anthropic  # imported lazily so the rest of the project doesn't need the SDK
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")
        self._client = anthropic.Anthropic(api_key=api_key or os.getenv("ANTHROPIC_API_KEY"))
        self.name = f"anthropic:{self.model}"

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        msg = self._client.messages.create(model=self.model, max_tokens=max_tokens, system=system,
                                           messages=[{"role": "user", "content": user}])
        return "".join(block.text for block in msg.content if getattr(block, "type", "") == "text")


class BedrockClient(AnthropicClient):
    """Claude through AWS Bedrock (for example in GovCloud). Uses the standard AWS credential chain."""

    def __init__(self, model: Optional[str] = None, region: Optional[str] = None):
        import anthropic
        self.model = model or _required_env("BEDROCK_MODEL_ID")
        self._client = anthropic.AnthropicBedrock(aws_region=region or os.getenv("AWS_REGION"))
        self.name = f"bedrock:{self.model}"


class OpenAICompatibleClient:
    """OpenAI's API, or any service that speaks it (xAI's Grok API does)."""

    def __init__(self, model: str, api_key: Optional[str], base_url: Optional[str] = None, label: str = "openai"):
        import openai
        self.model = model
        self._client = openai.OpenAI(api_key=api_key, base_url=base_url)
        self.name = f"{label}:{model}"

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        # OpenAI's current models take max_completion_tokens; other compatible APIs take max_tokens.
        limit = {"max_completion_tokens": max_tokens} if self.name.startswith("openai:") else {"max_tokens": max_tokens}
        resp = self._client.chat.completions.create(
            model=self.model, messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            **limit)
        return resp.choices[0].message.content or ""


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Set {name} to choose a model for this provider.")
    return value


def make_client(provider: Optional[str] = None) -> LLMClient:
    provider = (provider or os.getenv("LLM_PROVIDER", "anthropic")).lower()
    if provider == "anthropic":
        return AnthropicClient()
    if provider == "bedrock":
        return BedrockClient()
    if provider == "openai":
        return OpenAICompatibleClient(_required_env("OPENAI_MODEL"), os.getenv("OPENAI_API_KEY"),
                                      os.getenv("OPENAI_BASE_URL"), "openai")
    if provider == "xai":
        return OpenAICompatibleClient(_required_env("XAI_MODEL"), os.getenv("XAI_API_KEY"),
                                      os.getenv("XAI_BASE_URL", "https://api.x.ai/v1"), "xai")
    raise ValueError(f"Unknown LLM_PROVIDER {provider!r}; use anthropic, bedrock, openai or xai")
