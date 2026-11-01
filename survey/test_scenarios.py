"""Six ways a secret reaches an instrumented OpenAI SDK call. Each test plants a canary and lets
traceleakcheck decide leak / clean / incomplete. A "failing" test here is a finding, not a bug.
"""

import json

import openai
import pytest
from conftest import completion

MODEL = "gpt-4o-mini"


def _ask(c, text="hi"):
    return c.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": text}])


def test_secret_in_prompt(canary, fake, client):
    """A user pastes a key into the chat."""
    secret = canary().value
    fake.reply(200, completion({"role": "assistant", "content": "Looks fine."}))
    _ask(client(), f"why does this fail? OPENAI_API_KEY={secret}")


def test_secret_in_completion(canary, fake, client):
    """The model repeats a secret it saw in its context (e.g. from a retrieved document)."""
    secret = canary().value
    fake.reply(200, completion({"role": "assistant", "content": f"The key in the doc is {secret}."}))
    _ask(client())


def test_secret_in_tool_call_arguments(canary, fake, client):
    """The model calls a tool and passes a credential as an argument."""
    secret = canary().value
    call = {"id": "call_1", "type": "function",
            "function": {"name": "deploy", "arguments": json.dumps({"token": secret})}}
    fake.reply(200, completion({"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"))
    _ask(client())


def test_api_key_in_auth_header(canary, fake, client):
    """The client's own API key, sent as `Authorization: Bearer`."""
    secret = canary().value
    fake.reply(200, completion({"role": "assistant", "content": "ok"}))
    _ask(client(api_key=secret))


def test_api_key_in_query_string(canary, fake, client):
    """Gateway-style auth via `?key=...` (default_query)."""
    secret = canary().value
    fake.reply(200, completion({"role": "assistant", "content": "ok"}))
    _ask(client(default_query={"key": secret}))


def test_error_message_echoes_key(canary, fake, client):
    """A gateway's 401 error body echoes the key it rejected."""
    secret = canary().value
    fake.reply(401, {"error": {"message": f"Invalid API key: {secret}", "type": "invalid_request_error",
                               "code": "invalid_api_key"}})
    with pytest.raises(openai.AuthenticationError):
        _ask(client(api_key=secret))
