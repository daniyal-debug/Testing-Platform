"""APK signing inspection.

Two independent signals are combined:

1. Which signature schemes are present (v1 JAR signing, v2/v3 APK Signing
   Block) — determined by inspecting the ZIP structure directly.
2. Signer certificate details (subject, validity, signature algorithm) — read
   with the JDK ``keytool`` when it is available. This only covers v1-signed
   APKs, so it is best-effort and never fatal.
"""
from __future__ import annotations

import re
import shutil
import struct
import subprocess
from typing import List, Optional

from .apkfile import APKFile
from .models import CertificateInfo

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_ID_V2 = 0x7109871A
_ID_V3 = 0xF05368C0
_ID_V31 = 0x1B93AD61

_WEAK_SIG_ALGOS = ("MD5", "SHA1WITH", "SHA1WITHRSA", "MD2", "MD5WITHRSA")


def _find_eocd_cd_offset(data: bytes) -> Optional[int]:
    """Return the byte offset of the ZIP central directory, or None."""
    # End Of Central Directory record signature.
    idx = data.rfind(b"PK\x05\x06")
    if idx < 0 or idx + 20 > len(data):
        return None
    (cd_offset,) = struct.unpack_from("<I", data, idx + 16)
    return cd_offset


def detect_signing_schemes(raw: bytes) -> CertificateInfo:
    info = CertificateInfo()
    cd_off = _find_eocd_cd_offset(raw)
    # Need at least the trailing size(8) + magic(16) before the central dir.
    if cd_off is None or cd_off < 24 or cd_off > len(raw):
        return info
    # The APK Signing Block sits immediately before the central directory; its
    # trailing 16 bytes are the magic.
    magic_pos = cd_off - 16
    if raw[magic_pos:cd_off] != APK_SIG_BLOCK_MAGIC:
        return info
    info.v2_signed = True  # a v2+ block exists; refine to v2/v3 below.
    try:
        # block size (u64) is stored 8 bytes before the magic's block end.
        (block_size,) = struct.unpack_from("<Q", raw, cd_off - 24)
        block_start = cd_off - 8 - block_size
        # Validate the computed block start is sane before walking it.
        if 0 <= block_start < cd_off - 24 and block_size < len(raw):
            pos = block_start + 8  # skip the leading size field
            end = cd_off - 24
            while pos + 12 <= end:
                (pair_len,) = struct.unpack_from("<Q", raw, pos)
                if pair_len < 4 or pos + 8 + pair_len > cd_off:
                    break
                (pair_id,) = struct.unpack_from("<I", raw, pos + 8)
                if pair_id == _ID_V3 or pair_id == _ID_V31:
                    info.v3_signed = True
                pos += 8 + pair_len
    except struct.error:
        pass
    return info


def _run_keytool(apk_path: str) -> List[dict]:
    keytool = shutil.which("keytool")
    if not keytool:
        return []
    try:
        proc = subprocess.run(
            [keytool, "-printcert", "-jarfile", apk_path],
            capture_output=True, text=True, timeout=45,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    out = proc.stdout or ""
    signers: List[dict] = []
    # keytool prints one block per signer, separated by blank lines / headers.
    blocks = re.split(r"\n\s*\n", out)
    for block in blocks:
        if "Owner:" not in block and "Signature algorithm" not in block:
            continue
        signer = {}
        for pattern, key in (
            (r"Owner:\s*(.+)", "subject"),
            (r"Issuer:\s*(.+)", "issuer"),
            (r"Serial number:\s*(.+)", "serial"),
            (r"Valid from:\s*(.+?)\s+until:\s*(.+)", "validity"),
            (r"Signature algorithm name:\s*(.+)", "sig_algorithm"),
            (r"Subject Public Key Algorithm:\s*(.+)", "key_algorithm"),
            (r"SHA256:\s*([0-9A-Fa-f:]+)", "sha256"),
        ):
            m = re.search(pattern, block)
            if m:
                if key == "validity":
                    signer["valid_from"] = m.group(1).strip()
                    signer["valid_until"] = m.group(2).strip()
                else:
                    signer[key] = m.group(1).strip()
        if signer:
            signers.append(signer)
    return signers


def analyze(apk: APKFile) -> CertificateInfo:
    raw = apk.raw_bytes()
    info = detect_signing_schemes(raw)
    info.v1_signed = bool(apk.signature_files())

    if not (info.v1_signed or info.v2_signed or info.v3_signed):
        info.warnings.append("No APK signature could be detected (unsigned APK).")

    info.signers = _run_keytool(apk.path)
    for signer in info.signers:
        algo = (signer.get("sig_algorithm") or "").upper().replace(" ", "")
        if any(w in algo for w in _WEAK_SIG_ALGOS):
            signer["weak_signature"] = True
        subject = (signer.get("subject") or "")
        if "Android Debug" in subject or "CN=Android Debug" in subject:
            signer["debug_certificate"] = True
    if not info.signers and (info.v2_signed or info.v3_signed) and not info.v1_signed:
        info.warnings.append(
            "APK is signed with scheme v2/v3 only; certificate details require "
            "apksigner (not available) and could not be extracted."
        )
    return info
