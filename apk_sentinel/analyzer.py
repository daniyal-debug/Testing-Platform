"""Top-level orchestration: take an APK path, return an :class:`AnalysisResult`.

This is the one function most callers need. It wires together the manifest
decoder, DEX string extraction, secret scanning, certificate inspection and the
rule engine, and never lets a single sub-analysis failure abort the whole scan.
"""
from __future__ import annotations

import datetime
from typing import List, Optional

from . import __version__, certificate, dex, manifest as manifest_mod, secrets
from .apkfile import APKFile
from .models import AnalysisResult, ManifestInfo
from .rules import RuleContext, run_all


def analyze_apk(path: str, *, deep: bool = True) -> AnalysisResult:
    """Analyse the APK at ``path``.

    ``deep`` controls DEX string extraction (secret hunting, weak-crypto and
    TLS heuristics). Turn it off for a fast manifest-only scan.
    """
    with APKFile(path) as apk:
        hashes = apk.hashes()
        result = AnalysisResult(
            file_name=_basename(path),
            file_size=int(hashes["size"]),
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            engine_version=__version__,
            analyzed_at=_now(),
        )

        # -- manifest ----------------------------------------------------
        m: ManifestInfo
        try:
            m = manifest_mod.from_bytes(apk.manifest_bytes())
        except Exception as exc:
            m = ManifestInfo()
            m.warnings.append(f"Failed to decode AndroidManifest.xml: {exc!r}")
        result.manifest = m

        # -- packaging inventory ----------------------------------------
        result.files = apk.inventory()
        result.native_libs = apk.native_libs()
        result.dex_count = len(apk.dex_names())
        result.total_uncompressed = apk.total_uncompressed()

        # -- certificate ------------------------------------------------
        try:
            result.certificate = certificate.analyze(apk)
        except Exception as exc:
            result.certificate.warnings.append(f"Certificate analysis failed: {exc!r}")

        # -- DEX strings, secrets, cleartext ----------------------------
        dex_strings: List[str] = []
        if deep:
            try:
                dex_strings = dex.iter_all_strings(
                    (apk.read(n) for n in apk.dex_names())
                )
            except Exception as exc:
                m.warnings.append(f"DEX string extraction failed: {exc!r}")

        result.secrets = secrets.scan_strings(dex_strings) if dex_strings else []
        cleartext_urls = secrets.find_cleartext_urls(dex_strings) if dex_strings else []

        # -- rules ------------------------------------------------------
        ctx = RuleContext(
            manifest=m,
            certificate=result.certificate,
            dex_strings=dex_strings,
            secrets=result.secrets,
            cleartext_urls=cleartext_urls,
            native_libs=result.native_libs,
            dex_count=result.dex_count,
            file_names=[f.name for f in result.files],
            total_uncompressed=result.total_uncompressed,
        )
        result.findings = run_all(ctx)
        return result


def _basename(path: str) -> str:
    import os
    return os.path.basename(path)


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
