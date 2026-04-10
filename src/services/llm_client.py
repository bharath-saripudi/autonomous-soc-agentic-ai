"""Anthropic LLM Client — the sole LLM provider for all agents.

Uses Claude Sonnet 4 via the Anthropic SDK for:
  - Triage Agent: ReAct severity scoring
  - Hunting Agent: RAG-based historical analysis
  - Learning Agent: Feedback pattern analysis
  - Response Agent: Action justification

All agent prompts flow through this single client.
"""

import json
import time
from typing import Any, Dict, Optional

import structlog
from anthropic import AsyncAnthropic

from src.config import get_settings

logger = structlog.get_logger()


class LLMClient:
    """Async Anthropic client with structured JSON output."""

    def __init__(self):
        settings = get_settings()
        self.client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        self.model = "claude-sonnet-4-20250514"
        self.max_tokens = 2000
        self._total_calls = 0
        self._total_tokens = 0
        self._total_latency = 0.0

    async def reason(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Send a prompt to Claude and return parsed JSON response.

        Args:
            system_prompt: System instructions (agent role + output format)
            user_prompt: The actual alert/data to analyze
            temperature: 0.0–1.0, lower = more deterministic (default 0.1)
            max_tokens: Override default max tokens if needed

        Returns:
            Parsed JSON dict from Claude's response

        Raises:
            LLMError: If API call fails or response isn't valid JSON
        """
        start_time = time.time()

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
            )

            # Track metrics
            latency = time.time() - start_time
            self._total_calls += 1
            self._total_latency += latency
            input_tokens = response.usage.input_tokens
            output_tokens = response.usage.output_tokens
            self._total_tokens += input_tokens + output_tokens

            logger.info(
                "llm_call_complete",
                model=self.model,
                latency_sec=round(latency, 2),
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            )

            # Extract text content from response
            raw_text = response.content[0].text

            # Parse JSON — strip markdown fences if present
            cleaned = raw_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            parsed = json.loads(cleaned)
            return parsed

        except json.JSONDecodeError as e:
            logger.error(
                "llm_json_parse_error",
                error=str(e),
                raw_response=raw_text[:500] if 'raw_text' in dir() else "no response",
            )
            raise LLMError(f"Failed to parse LLM JSON response: {e}")

        except Exception as e:
            latency = time.time() - start_time
            logger.error(
                "llm_call_failed",
                model=self.model,
                latency_sec=round(latency, 2),
                error=str(e),
                error_type=type(e).__name__,
            )
            raise LLMError(f"Anthropic API call failed: {e}")

    async def reason_text(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Send a prompt and return raw text response (no JSON parsing).

        Useful for free-form analysis, summaries, or explanations.
        """
        start_time = time.time()

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ],
            )

            latency = time.time() - start_time
            self._total_calls += 1
            self._total_latency += latency
            self._total_tokens += response.usage.input_tokens + response.usage.output_tokens

            return response.content[0].text

        except Exception as e:
            logger.error("llm_text_call_failed", error=str(e))
            raise LLMError(f"Anthropic API call failed: {e}")

    @property
    def stats(self) -> Dict[str, Any]:
        """Return LLM usage statistics."""
        return {
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "total_latency_sec": round(self._total_latency, 2),
            "avg_latency_sec": round(
                self._total_latency / self._total_calls, 2
            ) if self._total_calls > 0 else 0,
            "model": self.model,
        }


class LLMError(Exception):
    """Raised when LLM call fails or returns unparseable response."""
    pass


# ── Singleton instance ──
_llm_instance: Optional[LLMClient] = None


def get_llm() -> LLMClient:
    """Get or create the singleton LLM client."""
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = LLMClient()
    return _llm_instance