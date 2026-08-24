# 🛡️ APK Sentinel

**A testing platform for Android apps.** Upload an `.apk` and get back a
complete security & quality report — every issue graded by severity, with
evidence and a **step-by-step guide (with code) on exactly how to fix it**.

It works two ways:

* **Web app** — a drag-and-drop upload page. Any user drops their APK and gets
  an interactive report they can view and download (HTML / Markdown / JSON).
* **CLI** — `python -m apk_sentinel app.apk` for local scans and CI gating.

The analysis engine is **pure Python standard library** — no Android SDK, no
`aapt`, no third-party packages. It decodes Android's binary manifest format
itself, so it runs anywhere Python does. Flask is used *only* for the optional
web UI.

---

## What it checks

APK Sentinel performs **static analysis** (it inspects the app without running
it), covering the areas a real mobile security review starts with:

| Area | Examples of what's detected |
| --- | --- |
| **Manifest / configuration** | `debuggable=true`, `allowBackup`, low `minSdk`, outdated `targetSdk`, WebView debugging |
| **Exported components** | Activities / services / receivers / providers reachable by other apps without permission protection |
| **Permissions** | High-risk permissions (overlay, install-packages, all-files), dangerous runtime permissions, weak custom permissions |
| **Network security** | Cleartext HTTP enabled, missing Network Security Config, `http://` endpoints in code, disabled TLS validation |
| **Signing** | Unsigned APKs, legacy v1-only signing (Janus), weak cert algorithms (SHA-1/MD5), debug-key signing |
| **Secrets in code** | Hard-coded AWS / Google / Stripe / Slack keys, JWTs, private keys, generic tokens (scanned from DEX bytecode) |
| **Cryptography** | Use of DES/3DES/RC4, ECB mode, and other weak primitives |
| **Packaging** | Source / mapping / test artifacts accidentally shipped in the release |

Each finding gets a **severity** (Critical → Info), a **CWE** and **OWASP
MASVS** mapping, the **evidence** that triggered it, and a long-form remediation
guide from the built-in knowledge base — 25 issue types, each with fix steps, a
copy-pasteable code example, and how to verify the fix.

The report also gives the app an overall **letter grade (A+ → F)** and a
**0–100 risk score**.

---

## Quick start

### 1. Install (only needed for the web UI)

```bash
pip install -r requirements.txt
```

The CLI/engine needs nothing beyond Python 3.9+. Flask is only for the web app.

### 2. Run the web platform

```bash
python -m webapp
# → open http://127.0.0.1:5000
```

Drag an APK onto the page, wait for the scan, and view/download the report.
Uploaded APKs are deleted right after the report is generated.

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `5000` | Web server port |
| `APK_SENTINEL_MAX_MB` | `350` | Max upload size (MB) |
| `APK_SENTINEL_DATA` | temp dir | Where generated reports are stored |

### 3. Or use the CLI

```bash
# Analyse and write html + md + json into reports/
python -m apk_sentinel app.apk

# Choose output dir / format
python -m apk_sentinel app.apk -o out --format html

# Print JSON to stdout (for piping into other tools)
python -m apk_sentinel app.apk --stdout --format json

# CI gate: exit non-zero if any High+ finding exists
python -m apk_sentinel app.apk --fail-on high
```

### 4. Try it on the built-in sample

No APK handy? Generate a deliberately-vulnerable one and scan it:

```bash
python tools/make_sample_apk.py sample.apk
python -m apk_sentinel sample.apk
```

You should get **Grade F** with critical, high, medium and low findings — a good
tour of the report.

---

## What a report looks like

```
  APK Sentinel 1.0.0  |  app-release.apk
  Package : com.example.app  v1.0
  Grade   : F   Risk 100/100
  Findings: 2 critical | 5 high | 7 medium | 3 low | 1 info

    [CRIT] Application is debuggable (android:debuggable="true")
    [CRIT] Hard-coded credentials / API keys found
    [HIGH] Cleartext (HTTP) network traffic is explicitly enabled
    [HIGH] Content provider exported without permission protection
    ...
```

The HTML report is a **single self-contained file** (no external assets) with an
executive summary, a prioritized action plan, app metadata, permissions,
components, all findings with fix guides, and any detected secrets.

---

## How it works

```
                ┌─────────────────────────────────────────────┐
   your.apk ──▶ │  APKFile (zip)                              │
                │    ├─ AndroidManifest.xml ─▶ axml ─▶ manifest│
                │    ├─ classes*.dex ─────────▶ dex strings    │
                │    ├─ META-INF / sig block ─▶ certificate    │
                │    └─ file inventory                         │
                │                     │                        │
                │                     ▼                        │
                │              RuleContext ─▶ rules (catalog)  │
                │                     │                        │
                │                     ▼                        │
                │              AnalysisResult                  │
                │            (findings + metadata)             │
                └──────────────────────┬──────────────────────┘
                                       ▼
                    report.py  ──▶  HTML / Markdown / JSON
                (findings merged with knowledge-base fix guides)
```

Key modules (`apk_sentinel/`):

| Module | Responsibility |
| --- | --- |
| `axml.py` | Decodes Android binary XML (`AndroidManifest.xml`) — no SDK needed |
| `apkfile.py` | ZIP wrapper: hashing, inventory, DEX/native-lib access |
| `dex.py` | Extracts string constants from DEX bytecode |
| `certificate.py` | Detects v1/v2/v3 signing; reads cert details via `keytool` if present |
| `manifest.py` | Turns the decoded XML into a structured `ManifestInfo` |
| `secrets.py` | Regex catalog for hard-coded secrets and cleartext URLs |
| `rules.py` | The security/quality rule catalog (each rule → `Finding`s) |
| `knowledge.py` + `knowledge_data.py` | Long-form remediation guides per finding id |
| `report.py` | Renders JSON / Markdown / self-contained HTML |
| `analyzer.py` | Orchestrates everything into an `AnalysisResult` |

---

## Running the tests

```bash
python -m unittest discover -s tests
# or, if you have pytest:
python -m pytest tests
```

The suite builds a synthetic vulnerable APK on the fly (which also round-trips
the binary-XML writer against the parser), then asserts the right findings fire,
secrets are detected and masked, and all three report formats render correctly.

---

## Scope & limitations

APK Sentinel does **static** analysis only. It is a strong, fast first pass, but
it is **not** a substitute for a full assessment:

* It does not run the app, so runtime-only issues (business-logic flaws, live
  API behaviour, deobfuscated logic) are out of scope.
* String-based heuristics (weak crypto, TLS, secrets) can produce false
  positives/negatives — findings should be confirmed in context.
* Certificate *details* require the JDK `keytool`; if it is absent, signing
  *scheme* detection still works but subject/algorithm details are skipped.

For high-assurance needs, pair this with dynamic analysis and a manual review
against the [OWASP MASTG](https://mas.owasp.org/MASTG/).

---

## License

Provided as-is for security testing and educational use. You are responsible for
only analysing APKs you are authorized to test.
