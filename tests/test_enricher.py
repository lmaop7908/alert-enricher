"""Offline tests: providers are exercised against fake HTTP responses."""

import json

import pytest

from enricher import report
from enricher.cache import Cache
from enricher.core import enrich
from enricher.http import ProviderError, request_with_retry
from enricher.indicators import classify, refang
from enricher.providers import AbuseIPDB, ProviderResult, URLhaus, VirusTotal
from enricher.scoring import combine


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}

    def json(self):
        return self._body


class FakeSession:
    """Returns queued responses in order and records calls."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


# ---------- indicators ----------

@pytest.mark.parametrize(
    "raw,kind,subtype",
    [
        ("8.8.8.8", "ip", "ipv4"),
        ("2001:4860:4860::8888", "ip", "ipv6"),
        ("Example.COM", "domain", ""),
        ("https://evil.example/path", "url", ""),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash", "md5"),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "hash", "sha1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "hash", "sha256"),
        ("not an indicator", "unknown", ""),
        ("", "unknown", ""),
    ],
)
def test_classify(raw, kind, subtype):
    ind = classify(raw)
    assert (ind.kind, ind.subtype) == (kind, subtype)


def test_refang_and_classify_defanged():
    assert refang("hxxps://evil[.]example/a") == "https://evil.example/a"
    assert classify("evil[.]example").kind == "domain"
    assert classify("1[.]2[.]3[.]4").value == "1.2.3.4"


def test_private_ip_not_public():
    assert not classify("10.0.0.5").is_public_ip
    assert not classify("127.0.0.1").is_public_ip
    assert classify("8.8.8.8").is_public_ip


# ---------- http retry ----------

def test_retry_on_429_then_success():
    session = FakeSession(FakeResponse(429, headers={"Retry-After": "1"}), FakeResponse(200))
    slept = []
    resp = request_with_retry(session, "GET", "http://x", sleep=slept.append)
    assert resp.status_code == 200
    assert slept == [1]


def test_retry_gives_up():
    session = FakeSession(*[FakeResponse(503) for _ in range(4)])
    with pytest.raises(ProviderError):
        request_with_retry(session, "GET", "http://x", sleep=lambda s: None)
    assert len(session.calls) == 4


# ---------- providers ----------

def test_virustotal_malicious():
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 8, "suspicious": 1, "harmless": 60, "undetected": 20},
        "reputation": -5}}}
    vt = VirusTotal("key", FakeSession(FakeResponse(200, body)))
    result = vt.lookup(classify("8.8.4.4"))
    assert result.status == "ok"
    assert result.score == 100  # 8*12 + 5 capped at 100
    assert "8 malicious" in result.summary


def test_virustotal_not_found_and_auth_error():
    vt = VirusTotal("key", FakeSession(FakeResponse(404)))
    assert vt.lookup(classify("example.com")).status == "not_found"
    vt = VirusTotal("bad", FakeSession(FakeResponse(401)))
    assert vt.lookup(classify("example.com")).status == "error"


def test_virustotal_url_id_is_unpadded_base64():
    session = FakeSession(FakeResponse(404))
    VirusTotal("key", session).lookup(classify("https://example.com/"))
    called_url = session.calls[0][1]
    assert called_url.endswith("/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8")


def test_abuseipdb_score():
    body = {"data": {"abuseConfidenceScore": 85, "totalReports": 42,
                     "countryCode": "RU", "isp": "ExampleNet"}}
    result = AbuseIPDB("key", FakeSession(FakeResponse(200, body))).lookup(classify("8.8.4.4"))
    assert result.score == 85
    assert "42 reports" in result.summary


def test_provider_skips_without_key_and_unsupported_type():
    assert AbuseIPDB(None).lookup(classify("8.8.8.8")).status == "skipped"
    assert AbuseIPDB("key").lookup(classify("example.com")).status == "skipped"


def test_urlhaus_listed_and_clean():
    listed = {"query_status": "ok", "url_status": "online", "threat": "malware_download"}
    r = URLhaus("key", FakeSession(FakeResponse(200, listed))).lookup(classify("http://bad.example/x"))
    assert r.score == 95
    r = URLhaus("key", FakeSession(FakeResponse(200, {"query_status": "no_results"}))).lookup(
        classify("good.example"))
    assert r.status == "not_found"


# ---------- scoring ----------

def _ok(score):
    return ProviderResult("p", "ok", score=score)


def test_combine_verdicts():
    assert combine([]) == (None, "unknown")
    assert combine([ProviderResult("p", "not_found")]) == (None, "unknown")
    assert combine([_ok(5)]) == (5, "clean")
    assert combine([_ok(40)]) == (40, "suspicious")
    assert combine([_ok(75)]) == (75, "malicious")


def test_combine_corroboration_bonus():
    assert combine([_ok(35), _ok(40)]) == (50, "suspicious")
    assert combine([_ok(65), _ok(60)]) == (75, "malicious")  # bonus tips it over
    assert combine([_ok(95), _ok(90)])[0] == 100  # capped


# ---------- cache + orchestration ----------

class CountingProvider(AbuseIPDB):
    def __init__(self):
        super().__init__("key")
        self.calls = 0

    def _lookup(self, ind):
        self.calls += 1
        return ProviderResult(self.name, "ok", score=10, summary="ok")


def test_cache_prevents_repeat_lookups(tmp_path):
    provider = CountingProvider()
    cache = Cache(tmp_path / "c.json")
    enrich("8.8.8.8", [provider], cache)
    enrich("8.8.8.8", [provider], cache)
    assert provider.calls == 1
    cache.save()
    assert Cache(tmp_path / "c.json").get("AbuseIPDB", "8.8.8.8").score == 10


def test_cache_expiry_and_errors_not_cached(tmp_path):
    clock = [1000.0]
    cache = Cache(None, ttl=60, now=lambda: clock[0])
    cache.put("P", "x", ProviderResult("P", "ok", score=1))
    cache.put("P", "y", ProviderResult("P", "error"))
    assert cache.get("P", "x") is not None
    assert cache.get("P", "y") is None
    clock[0] += 61
    assert cache.get("P", "x") is None


def test_private_ip_never_sent_to_providers():
    provider = CountingProvider()
    result = enrich("192.168.1.10", [provider])
    assert provider.calls == 0
    assert "private" in result.note


# ---------- reports ----------

def test_reports_render_and_escape():
    provider = CountingProvider()
    items = [enrich("8.8.8.8", [provider]), enrich("<script>alert(1)</script>", [provider])]
    assert json.loads(report.as_json(items))[0]["verdict"] == "clean"
    assert "8.8.8.8" in report.as_text(items)
    page = report.as_html(items)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


# ---------- file hashing ----------

def test_hash_file_matches_known_digests(tmp_path):
    from enricher.indicators import hash_file

    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert hash_file(empty) == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    abc = tmp_path / "abc.txt"
    abc.write_bytes(b"abc")
    assert hash_file(abc) == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_hash_file_chunking_gives_same_result(tmp_path):
    from enricher.indicators import hash_file

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 10_000)
    assert hash_file(big, chunk_size=7) == hash_file(big)


def test_cli_hash_file_end_to_end(tmp_path, monkeypatch, capsys):
    import hashlib

    from enricher import cli

    sample = tmp_path / "invoice.exe"
    sample.write_bytes(b"not really malware")
    digest = hashlib.sha256(b"not really malware").hexdigest()

    seen = []

    class FakeVT(VirusTotal):
        def _lookup(self, ind):
            seen.append(ind.value)
            return ProviderResult(self.name, "ok", score=80, summary="fake detections")

    monkeypatch.setattr(cli, "build_providers", lambda env: [FakeVT("key")])
    monkeypatch.chdir(tmp_path)  # no stray .env
    code = cli.main(["--hash-file", str(sample), "--no-cache"])
    out = capsys.readouterr().out

    assert code == 0
    assert seen == [digest]  # only the hash is looked up
    assert "invoice.exe" in out and digest in out
    assert "MALICIOUS" in out


def test_cli_hash_file_missing_file(tmp_path, monkeypatch, capsys):
    from enricher import cli

    monkeypatch.chdir(tmp_path)
    assert cli.main(["--hash-file", str(tmp_path / "nope.bin")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_virustotal_file_facts_and_report_detail():
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 2, "suspicious": 0, "undetected": 70},
        "last_analysis_results": {
            "EngineA": {"category": "malicious", "result": "Trojan.Fake"},
            "EngineB": {"category": "malicious", "result": "<b>Gen</b>"},
            "EngineC": {"category": "undetected", "result": None},
        },
        "type_description": "Win32 EXE",
        "size": 2048,
        "names": ["setup.exe", "installer.exe"],
        "signature_info": {"verified": "Signed", "signers": "Example Corp; Root CA"},
        "popular_threat_classification": {"suggested_threat_label": "trojan.fake"},
        "first_submission_date": 1700000000,
        "times_submitted": 3}}}
    vt = VirusTotal("key", FakeSession(FakeResponse(200, body)))
    item = enrich(digest, [vt], label="setup.exe", source="C:\\tmp\\setup.exe (2.0 KB)")

    facts = item.results[0].facts
    assert "type: Win32 EXE, 2.0 KB" in facts
    assert "known as: setup.exe, installer.exe" in facts
    assert "signature: Signed (Example Corp)" in facts
    assert "threat label: trojan.fake" in facts
    assert "flagged by: EngineA: Trojan.Fake; EngineB: <b>Gen</b>" in facts
    assert "history: first seen 2023-11-14, submitted 3 time(s)" in facts
    assert facts[-1] == f"report: https://www.virustotal.com/gui/file/{digest}"

    text = report.as_text([item])
    assert "file: C:\\tmp\\setup.exe (2.0 KB)" in text
    assert "EngineA: Trojan.Fake" in text and "meaning:" in text
    assert "<b>Gen</b>" not in report.as_html([item])  # facts are escaped
    assert json.loads(report.as_json([item]))[0]["providers"][0]["facts"] == facts


def test_explain_unknown_is_not_safe():
    vt = VirusTotal("key", FakeSession(FakeResponse(404)))
    item = enrich("d41d8cd98f00b204e9800998ecf8427e", [vt])
    assert item.results[0].facts == []
    assert "not safe" in report.explain(item)
    assert report.explain(enrich("192.168.1.10", [vt])) == ""  # note already explains


def test_malwarebazaar_listed_and_not_found():
    from enricher.providers import MalwareBazaar

    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    body = {"query_status": "ok", "data": [{
        "sha256_hash": digest, "signature": "AgentTesla", "tags": ["exe", "stealer"],
        "file_name": "invoice.exe", "file_type": "exe", "first_seen": "2024-01-02 03:04:05"}]}
    session = FakeSession(FakeResponse(200, body))
    r = MalwareBazaar("key", session).lookup(classify(digest))
    assert r.score == 95 and "AgentTesla" in r.summary
    assert "tags: exe, stealer" in r.facts and "seen as: invoice.exe, exe" in r.facts
    assert session.calls[0][2]["data"] == {"query": "get_info", "hash": digest}

    missing = FakeSession(FakeResponse(200, {"query_status": "hash_not_found"}))
    assert MalwareBazaar("key", missing).lookup(classify(digest)).status == "not_found"
    assert MalwareBazaar(None).lookup(classify(digest)).status == "skipped"
    assert not MalwareBazaar("key").supports(classify("8.8.8.8"))


def test_team_cymru_whois_replies():
    from enricher.providers import TeamCymru

    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    ind = classify(md5)
    listed = TeamCymru(query=lambda q: f"# hash Unix-Epoch AV-Hit-%\n{md5} 1700000000 82\n")
    r = listed.lookup(ind)  # works with no API key
    assert (r.status, r.score) == ("ok", 82)
    assert "82%" in r.summary and r.facts == ["last seen: 2023-11-14"]

    low = TeamCymru(query=lambda q: f"{md5} 1700000000 12\n").lookup(ind)
    assert low.score == 30  # listed at all is at least suspicious
    none = TeamCymru(query=lambda q: f"{md5} 1700000000 NO_DATA\n").lookup(ind)
    assert none.status == "not_found"
    assert TeamCymru(query=lambda q: f"{md5} NO_DATA\n").lookup(ind).status == "not_found"

    def offline(q):
        raise OSError("blocked")

    assert TeamCymru(query=offline).lookup(ind).status == "error"
    assert TeamCymru(query=lambda q: "garbage").lookup(ind).status == "error"


def test_local_real_type_and_disguise_warnings():
    from enricher.localfile import sniff, type_facts

    assert sniff(b"MZ\x90\x00")[1] == "pe"
    assert sniff(b"%PDF-1.7")[1] == "pdf"
    assert sniff(b"plain words\n")[1] == "text"
    assert sniff(b"\x00\x01\x02")[1] == "binary"
    assert sniff(b"")[1] == "empty"

    facts, kind = type_facts("setup.exe", b"MZ")
    assert kind == "pe" and facts == ["real type: Windows executable (PE)"]
    facts, _ = type_facts("report.pdf", b"MZ")
    assert any("disguised" in f for f in facts)
    facts, _ = type_facts("invoice.pdf.exe", b"MZ")
    assert any("double extension" in f for f in facts)


def test_local_signature_and_origin_facts():
    from enricher.localfile import origin_fact, signature_fact

    fact, signer = signature_fact(
        "Valid", "Authenticode", 'CN="Example, Inc.", O=Example, C=US', "CN=Example CA, O=CA")
    assert signer == "Example, Inc."
    assert fact == "signature: valid, signed by Example, Inc., certificate issued by Example CA"
    assert signature_fact("NotSigned", "None", None, None) == ("signature: not signed", "")
    fact, signer = signature_fact("HashMismatch", "Authenticode", "CN=Example", None)
    assert "INVALID" in fact and signer == ""  # a broken signature vouches for nothing
    assert signature_fact("NotTrusted", "Authenticode", "CN=Self", None)[1] == ""

    mark = "[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://site.example/\nHostUrl=https://dl.example/a.exe\n"
    assert origin_fact(mark) == (
        "origin: downloaded from the internet - https://dl.example/a.exe "
        "(linked from https://site.example/)"
    )


def test_inspect_file_and_report_local_facts(tmp_path):
    from enricher.localfile import LocalFile, inspect_file

    sample = tmp_path / "notes.txt"
    sample.write_text("hello")
    # Non-Windows platform: no signature or origin checks are attempted.
    assert inspect_file(sample, platform="linux").facts == ["real type: text"]

    vt = VirusTotal("key", FakeSession(FakeResponse(404)))
    local = LocalFile(facts=["real type: <b>x</b>"], signed_by="Example Corp")
    item = enrich("d41d8cd98f00b204e9800998ecf8427e", [vt], source="a.exe (1 bytes)", local=local)
    assert "      real type: <b>x</b>" in report.as_text([item])
    assert "valid signature from Example Corp" in report.explain(item)
    assert "<b>x</b>" not in report.as_html([item])
    assert json.loads(report.as_json([item]))[0]["local"] == ["real type: <b>x</b>"]


def test_report_shows_label():
    provider = CountingProvider()
    item = enrich("d41d8cd98f00b204e9800998ecf8427e", [provider], label="sample.exe")
    assert "sample.exe" in report.as_text([item])
    assert "sample.exe" in report.as_html([item])
    assert json.loads(report.as_json([item]))[0]["label"] == "sample.exe"
