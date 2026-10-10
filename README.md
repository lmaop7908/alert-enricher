# alert-enricher

A command-line tool that takes the indicators from a security alert (IPs, domains, URLs, file hashes), checks them against threat-intel APIs, and produces a single verdict with the evidence behind it. It automates the "look this up in three tabs" step that SOC analysts repeat dozens of times a shift.

```
 indicators ──► classify ──► providers (cached) ──► score ──► report
 (args/file)   IP/domain/    VirusTotal                       text / JSON / HTML
               URL/hash      AbuseIPDB
               + refang      URLhaus
```

## Features

- **Auto-detects indicator type** (IPv4/IPv6, domain, URL, MD5/SHA-1/SHA-256) and accepts **defanged** input like `hxxps://evil[.]example`.
- **Five providers**: VirusTotal, AbuseIPDB, URLhaus, plus MalwareBazaar and Team Cymru's Malware Hash Registry for file hashes. Works with any subset of keys.
- **Explainable scoring**: every provider returns 0-100; the overall score is the highest one, plus a small bonus when two providers independently agree (see [Scoring](#scoring)).
- **Rate-limit friendly**: retries on HTTP 429/5xx with backoff (honors `Retry-After`) and caches results for an hour so reruns don't burn free-tier quota.
- **Safe by default**: private/reserved IPs are never sent to third parties, API keys come from the environment, and HTML output is escaped.
- **Batch mode**: read indicators from a `.txt` or `.csv`; output as text, JSON, or a standalone HTML report.
- **Check files directly**: `--hash-file` computes a file's SHA-256 locally and looks up the hash. The file itself is never uploaded.
- **Local file checks**: `--hash-file` also reports the file's real type (from its content, with a warning if the name disguises a program), and on Windows its digital signature and where it was downloaded from. These run offline.
- **37 offline tests** that mock all network calls, so they run without keys or network.

## Quick start

Requires Python 3.10 or newer.

**Windows (PowerShell):**

```powershell
git clone https://github.com/lmaop7908/alert-enricher.git
cd alert-enricher
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # then add at least one API key (all have free tiers)
```

**macOS / Linux:**

```bash
git clone https://github.com/lmaop7908/alert-enricher.git
cd alert-enricher
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then add at least one API key (all have free tiers)
```

Then look something up:

```bash
python -m enricher 8.8.8.8 example.com
python -m enricher -f sample_iocs.txt --format html -o report.html
```

### One-command scans on Windows

`scan.cmd` wraps all of the above: it uses the project's `.venv` and `.env` no matter which folder you run it from, hashes anything that is an existing file, and looks everything else up as an indicator.

```powershell
.\scan.cmd 8.8.8.8
.\scan.cmd "C:\Downloads\setup.exe" example.com
```

Add the project folder to your `PATH` to type just `scan <target>` from anywhere.

### Checking files

Hash local files and look them up in one step (repeat the flag for several files):

```bash
python -m enricher --hash-file suspicious.exe
python -m enricher --hash-file a.dll --hash-file b.exe --format html -o files.html
```

Windows paths with spaces need quotes: `--hash-file "C:\Users\me\Downloads\my file.exe"`.

Only the SHA-256 hash leaves your machine. The file's real type, signature and download origin are checked locally (signature and origin on Windows only). A file nobody has submitted before returns `not_found`, which means "no record", not "safe". `--hash-file` can be combined with plain indicators and `-f`.

### Example output

From a real run of `scan 8.8.8.8 10.0.0.5 C:\Windows\System32\notepad.exe`:

```
8.8.8.8  [ip]
  verdict: CLEAN  (score 0/100)
  - VirusTotal: ok - 0 malicious / 0 suspicious of 92 engines
  - AbuseIPDB: ok - abuse confidence 0%, 235 reports (US, Google LLC)
  - URLhaus: not_found - no malware URLs on record
  meaning: Providers have data on this indicator and none of it points to abuse.

10.0.0.5  [ip]
  verdict: UNKNOWN  (score n/a/100)
  note: private/reserved IP, not sent to external services

notepad.exe  468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e  [hash]
  verdict: CLEAN  (score 0/100)
  file: C:\Windows\System32\notepad.exe (352.0 KB)
      real type: Windows executable (PE)
      signature: valid, signed by Microsoft Windows via Windows catalog, certificate issued by Microsoft Windows Production PCA 2011
      origin: no download mark (made locally, unpacked from an archive, or mark removed)
  - VirusTotal: ok - 0 malicious / 0 suspicious of 75 engines
      type: Win32 EXE, 352.0 KB
      known as: notepad.exe, AGSService.exe, Notepad, NOTEPAD.EXE, unknown, notepad_copia.exe, 000001.exe, np.exe
      history: first seen 2026-08-27, last scanned 2026-10-09, submitted 124 time(s)
      report: https://www.virustotal.com/gui/file/468ffe129c395abf6b21a09efdf261910a95fb98aa982ead73caa7b2b684577e
  - MalwareBazaar: not_found - not a known malware sample
  - Team Cymru MHR: not_found - not in the malware registry
  meaning: Known file and no engine flagged it. Low risk, though a hash lookup cannot catch brand-new or modified malware.
```

Every result ends with a plain-English `meaning` line. For a file with detections, the VirusTotal block also lists the threat label and which engines flagged it.

## API keys (all free)

| Provider | Where to get a key | Free limits | Env var |
|---|---|---|---|
| VirusTotal | virustotal.com → profile → API key | 4 req/min, 500/day | `VT_API_KEY` |
| AbuseIPDB | abuseipdb.com → account → API | 1,000 checks/day | `ABUSEIPDB_API_KEY` |
| URLhaus | auth.abuse.ch | free Auth-Key | `URLHAUS_AUTH_KEY` |
| MalwareBazaar | auth.abuse.ch (same key as URLhaus) | free Auth-Key | `URLHAUS_AUTH_KEY`, or `MALWAREBAZAAR_AUTH_KEY` to override |
| Team Cymru MHR | no key needed (WHOIS, port 43) | max 1,000 hashes per request | none |

Keys are read from environment variables or a local `.env` file, which is git-ignored. Never commit real keys.

## Scoring

| Provider | How its 0-100 score is derived |
|---|---|
| VirusTotal | `min(100, malicious_engines × 12 + suspicious_engines × 5)` |
| AbuseIPDB | the abuse confidence score as returned |
| URLhaus | 95 for an online listed URL, 80 for offline, 90 for a host serving malware URLs |
| MalwareBazaar | 95 if the hash is a listed malware sample |
| Team Cymru MHR | its antivirus detection rate, with a floor of 30 because only malware is listed |

Local file checks (type, signature, origin) are shown as evidence but do not change the score.

The overall score is the **highest** provider score, with **+10** if two or more providers each score ≥ 30. Verdicts: **malicious** ≥ 70, **suspicious** ≥ 30, otherwise **clean**.

**"Unknown" is deliberate.** If no provider has data, the verdict is *unknown*, not *clean*. A brand-new malicious domain has no reports yet, and absence of evidence is not evidence of safety.

## Design decisions and limitations

- **Max, not average.** Averaging would let a clean AbuseIPDB result dilute a strong VirusTotal detection. For triage, one credible hit deserves attention.
- **Thresholds are heuristics**, not ground truth. Tune them in `enricher/scoring.py` for your tolerance for false positives.
- **Only definitive answers are cached.** Errors and skips are retried next run.
- **Privacy:** indicators are sent to third-party services. Don't submit sensitive internal hostnames or URLs. Private IPs are filtered automatically, but domains and URLs are not.
- **Hash lookups only.** `--hash-file` does not upload or execute files and does no local analysis, so it can't detect new or modified malware.
- **Not covered yet:** async lookups for large batches, additional providers (Shodan, GreyNoise, OTX), and a Slack/Discord alert integration.

## Project layout

```
enricher/
  indicators.py   classify + refang
  providers.py    VirusTotal, AbuseIPDB, URLhaus, MalwareBazaar, Team Cymru
  localfile.py    offline file checks: real type, signature, download origin
  scoring.py      combine provider scores into a verdict
  cache.py        JSON file cache with TTL
  http.py         retry/backoff helper
  core.py         orchestration
  report.py       text / JSON / HTML output
  cli.py          argparse CLI
tests/            offline tests with mocked HTTP
scan.cmd          Windows one-command wrapper
```

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

## Roadmap

- [ ] Concurrent lookups (`asyncio`/`httpx`)
- [ ] Slack/Discord webhook output
- [ ] MITRE ATT&CK tags for matched malware families
- [ ] Optional GreyNoise and OTX providers

## License

MIT
