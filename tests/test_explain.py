from traceleakcheck.explain import explain, terminal_lines
from traceleakcheck.html_report import render


def _leak(path, signal="traces", span="llm.call", variant="raw", kind="openai"):
    f = {"canary_kind": kind, "variant": variant, "signal": signal, "span": span, "path": path}
    return {"nodeid": "t.py::test_x", "status": "leak", "findings": [f], "detail": ""}


def test_places_named_in_plain_english():
    cases = {
        "a.spans[0].events[0].attributes[exception.message].stringValue": ("the error message", "Hide secrets before raising"),
        "a.spans[0].status.message": ("the step's status message", "Hide secrets before raising"),
        "a.spans[0].attributes[http.url].stringValue": ("the request web address", "request header"),
        "a.spans[0].attributes[gen_ai.input.messages].stringValue": ("the saved prompt", "content capture"),
        "a.spans[0].attributes[llm.output_messages.0.message.content].stringValue": ("the saved AI reply", "content capture"),
        "<raw body: field not decoded>": ("a field the decoder couldn't name", "custom exporters"),
    }
    for path, (what, tip) in cases.items():
        e = explain(_leak(path))
        (place,) = e.steps["llm.call"]
        assert place.what.startswith(what), (path, place.what)
        assert tip in e.tips[0].text, (path, e.tips[0].text)


def test_variant_and_kind_wording():
    e = explain(_leak("x.attributes[p].stringValue", variant="base64[1]", kind="aws"))
    assert "AWS access key" in e.headline and e.steps["llm.call"][0].how == "base64-encoded"


def test_terminal_lines_ascii_and_verbose_paths():
    r = _leak("x.attributes[p].stringValue")
    lines = terminal_lines(r)
    assert all(line.isascii() for line in lines)
    assert not any("attributes[p]" in line for line in lines)
    assert any("attributes[p]" in line for line in terminal_lines(r, verbose=True))


def test_html_escapes_and_orders_leaks_first():
    leak = _leak("x.attributes[<script>].stringValue")
    clean = {"nodeid": "t.py::test_ok", "status": "clean", "findings": [], "detail": ""}
    html = render({"summary": {"clean": 1, "leak": 1, "incomplete": 0, "error": 0}, "results": [clean, leak]})
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert html.index("test_x") < html.index("test_ok")
