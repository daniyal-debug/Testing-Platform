"""Best-effort DEX string-pool extraction.

Reading every string constant out of ``classes*.dex`` lets us hunt for
hard-coded secrets, endpoints, cleartext URLs and other sensitive material
without a full bytecode disassembler. The DEX layout (header -> string_ids ->
string_data_item) is documented at
https://source.android.com/docs/core/runtime/dex-format.

The parser is deliberately forgiving: a malformed or truncated DEX yields the
strings it could recover rather than raising.
"""
from __future__ import annotations

import struct
from typing import Iterator, List

DEX_MAGIC = b"dex\n"


def _read_uleb128(data: bytes, off: int):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 35:
            break
    return result, off


def extract_strings(data: bytes, limit: int = 200000) -> List[str]:
    """Extract UTF (MUTF-8) string constants from one DEX blob."""
    if len(data) < 0x70 or data[:4] != DEX_MAGIC:
        return []
    try:
        # header: magic(8) checksum(4) signature(20) file_size(4) header_size(4)
        # endian_tag(4) link_size(4) link_off(4) map_off(4)
        # string_ids_size(4) string_ids_off(4) ...
        string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
        string_ids_off = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return []

    out: List[str] = []
    n = min(string_ids_size, limit)
    for i in range(n):
        try:
            (data_off,) = struct.unpack_from("<I", data, string_ids_off + i * 4)
            _utf16_len, p = _read_uleb128(data, data_off)
            end = data.find(b"\x00", p)
            if end < 0:
                end = min(p + 4096, len(data))
            raw = data[p:end]
            out.append(_decode_mutf8(raw))
        except (struct.error, IndexError):
            continue
    return out


def _decode_mutf8(raw: bytes) -> str:
    # MUTF-8 is close enough to UTF-8 for our string-scanning purposes.
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def iter_all_strings(dex_blobs: Iterator[bytes], limit_per_dex: int = 200000) -> List[str]:
    seen = set()
    out: List[str] = []
    for blob in dex_blobs:
        for s in extract_strings(blob, limit=limit_per_dex):
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out
