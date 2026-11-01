"""Run: pytest examples/demo_agent --traceleak

test_redaction_works passes. test_agent_does_not_leak_key fails and names the exact span fields.
"""

from app import redact, run_agent


def test_redaction_works():
    assert "sk-" not in redact("summarize this; key=sk-proj-" + "a" * 40)


def test_agent_does_not_leak_key(canary):
    key = canary("openai").value
    assert run_agent(f"summarize this; key={key}", key) == "sorry, the model is unavailable"
