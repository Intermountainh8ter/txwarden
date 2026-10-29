"""redact_url and Redactor: what may be shown, and what must disappear."""
import pytest

from txwarden.redact import GENERIC, PLACEHOLDER, Redactor, redact_url

KEY = "sk_live_Zx81QpLm0aa93kd7"


@pytest.mark.parametrize("url,shown", [
    (f"https://node.example/v2/{KEY}", "https://node.example"),
    (f"https://node.example:8443/{KEY}?x=1#frag", "https://node.example:8443"),
    (f"https://user:{KEY}@node.example/rpc", "https://node.example"),
    (f"https://{KEY}@node.example", "https://node.example"),
    (f"http://127.0.0.1:8545/{KEY}", "http://127.0.0.1:8545"),
    (f"HTTP://Node.Example/{KEY}", "http://node.example"),
    (f"http://[::1]:8545/{KEY}", "http://[::1]:8545"),
    (f"wss://node.example/ws/{KEY}", "wss://node.example"),
    (f"  https://node.example/{KEY}\n", "https://node.example"),
    (f"https://node.example/?apikey={KEY}", "https://node.example"),
])
def test_only_scheme_host_and_port_survive(url, shown):
    assert redact_url(url) == shown and KEY not in redact_url(url)


@pytest.mark.parametrize("junk", [
    KEY, "", "   ", None, 12345, f"ftp://node.example/{KEY}", f"//node.example/{KEY}",
    f"https:///{KEY}", f"http://node.example:99999999/{KEY}", f"mailto:{KEY}@example.com",
    f"node.example/{KEY}",
])
def test_anything_that_is_not_a_url_becomes_the_generic_label(junk):
    assert redact_url(junk) == GENERIC


def test_redactor_removes_the_url_its_parts_and_decoded_forms():
    url = f"https://user:{KEY}@node.example:8443/v2/{KEY}/rpc?apikey={KEY}&chain=eth#frag99"
    r = Redactor(url)
    for text in (url, f"GET /v2/{KEY}/rpc failed", f"apikey={KEY}", f"login user:{KEY}@node",
                 f"/v2/{KEY}/rpc?apikey={KEY}&chain=eth", f"bad key {KEY}"):
        assert KEY not in r.scrub(text), text
    assert "node.example:8443" in r.scrub("cannot reach https://node.example:8443")


def test_redactor_handles_percent_encoded_secrets():
    r = Redactor("https://node.example/key%2Fwith%2Fslashes1234")
    assert "slashes1234" not in r.scrub("path was key/with/slashes1234 ok")
    assert "slashes1234" not in r.scrub("path was key%2Fwith%2Fslashes1234 ok")


def test_short_generic_path_segments_are_left_alone():
    r = Redactor(f"https://node.example/v1/rpc/{KEY}")
    assert r.scrub("GET /v1/rpc/ failed") == "GET /v1/rpc/ failed"
    assert r.scrub(f"GET /v1/rpc/{KEY}") == f"GET /{PLACEHOLDER}"  # the path goes as one unit


def test_the_host_is_not_a_secret():
    assert Redactor(f"https://node.example/{KEY}").scrub("cannot reach node.example") == \
        "cannot reach node.example"


def test_longest_piece_is_replaced_first_so_nothing_is_left_behind():
    url = f"https://node.example/abcd1234/{KEY}"
    out = Redactor(url).scrub(f"see {url} now")
    assert out == f"see {PLACEHOLDER} now"


def test_several_secrets_at_once_and_empty_ones():
    r = Redactor(f"https://a.example/{KEY}", None, "", "https://b.example/other_secret_9")
    assert KEY not in r.scrub(KEY) and "other_secret_9" not in r.scrub("other_secret_9")


def test_a_redactor_with_nothing_to_hide_changes_nothing():
    assert Redactor().scrub("anything at all") == "anything at all"
    assert Redactor("https://node.example").scrub("https://node.example/x") == \
        "https://node.example/x"


def test_a_value_that_is_not_a_url_is_still_scrubbed_whole():
    assert KEY not in Redactor(KEY).scrub(f"unknown url type: '{KEY}'")


def test_exception_formatting_names_the_type_and_scrubs_the_message():
    r = Redactor(f"https://node.example/{KEY}")
    text = r.exception(ValueError(f"bad url https://node.example/{KEY}"))
    assert text == f"ValueError: bad url {PLACEHOLDER}"


def test_non_string_input_is_converted():
    assert Redactor(KEY).scrub(ValueError(KEY)) == PLACEHOLDER


@pytest.mark.parametrize("weird", ["   ", "http://[::1", "http://node.example:99999999/key_value_123"])
def test_unparseable_secrets_do_not_crash_the_redactor(weird):
    r = Redactor(weird)
    r.scrub("whatever")
    if weird.strip():
        assert weird.strip() not in r.scrub(f"saw {weird.strip()} here")
