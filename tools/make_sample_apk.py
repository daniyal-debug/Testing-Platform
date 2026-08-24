"""Generate a deliberately-vulnerable sample APK for demos and tests.

This does NOT need the Android SDK. It hand-encodes:

* a binary ``AndroidManifest.xml`` (AXML) — the inverse of
  :mod:`apk_sentinel.axml`, so the analyzer reads it back exactly;
* a minimal ``classes.dex`` whose string pool contains planted secrets and
  weak-crypto markers;
* a fake v1 signature block so the APK looks signed.

The resulting APK is intentionally insecure (debuggable, cleartext, exported
components, hard-coded keys) so every major rule fires. Run::

    python tools/make_sample_apk.py [output.apk]
"""
from __future__ import annotations

import struct
import sys
import zipfile
import zlib

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Res_value data types
T_REFERENCE = 0x01
T_STRING = 0x03
T_INT_DEC = 0x10
T_INT_BOOLEAN = 0x12


# ---------------------------------------------------------------------------
# AXML encoder
# ---------------------------------------------------------------------------

class _Pool:
    def __init__(self):
        self.items = []
        self.index = {}

    def add(self, s):
        if s is None:
            return -1
        if s not in self.index:
            self.index[s] = len(self.items)
            self.items.append(s)
        return self.index[s]


def _len8(n):
    if n < 0x80:
        return bytes([n])
    return bytes([(n >> 8) | 0x80, n & 0xFF])


def _string_pool_chunk(pool):
    data = b""
    offsets = []
    for s in pool.items:
        offsets.append(len(data))
        b = s.encode("utf-8")
        # UTF-8 pool string: <char count><byte count><bytes><00>
        data += _len8(len(s)) + _len8(len(b)) + b + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    offs = b"".join(struct.pack("<I", o) for o in offsets)
    header_size = 28
    strings_start = header_size + len(offs)
    chunk_size = header_size + len(offs) + len(data)
    header = struct.pack("<HHI", 0x0001, header_size, chunk_size)
    body = struct.pack("<IIIII", len(pool.items), 0, 0x100, strings_start, 0)  # UTF8_FLAG
    return header + body + offs + data


def _ns_chunk(ctype, prefix, uri):
    body = struct.pack("<ii", 1, -1) + struct.pack("<ii", prefix, uri)
    return struct.pack("<HHI", ctype, 16, 8 + len(body)) + body


def _start_elem(ns, name, attrs):
    # attrs: list of (a_ns, a_name, a_raw, a_type, a_data)
    attr_bytes = b"".join(
        struct.pack("<iiiHBBI", a_ns, a_name, a_raw, 8, 0, a_type, a_data)
        for (a_ns, a_name, a_raw, a_type, a_data) in attrs
    )
    ext = struct.pack("<iiHHHHHH", ns, name, 20, 20, len(attrs), 0, 0, 0)
    body = struct.pack("<ii", 1, -1) + ext + attr_bytes
    return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body


def _end_elem(ns, name):
    body = struct.pack("<ii", 1, -1) + struct.pack("<ii", ns, name)
    return struct.pack("<HHI", 0x0103, 16, 8 + len(body)) + body


class El:
    def __init__(self, tag, attrs=None, children=None):
        self.tag = tag
        # attrs: list of (name, value, kind, android)
        self.attrs = attrs or []
        self.children = children or []


def _encode_axml(root: El) -> bytes:
    pool = _Pool()
    ns_uri = pool.add(ANDROID_NS)
    ns_prefix = pool.add("android")

    # Pre-register all tag names, attribute names and string values.
    def walk(el):
        pool.add(el.tag)
        for (name, value, kind, android) in el.attrs:
            pool.add(name)
            if kind == "str":
                pool.add(value)
        for c in el.children:
            walk(c)
    walk(root)

    def elem_chunks(el):
        attrs = []
        for (name, value, kind, android) in el.attrs:
            a_ns = ns_uri if android else -1
            a_name = pool.index[name]
            if kind == "str":
                idx = pool.index[value]
                attrs.append((a_ns, a_name, idx, T_STRING, idx))
            elif kind == "bool":
                attrs.append((a_ns, a_name, -1, T_INT_BOOLEAN, 0xFFFFFFFF if value else 0))
            elif kind == "int":
                attrs.append((a_ns, a_name, -1, T_INT_DEC, int(value) & 0xFFFFFFFF))
            elif kind == "ref":
                attrs.append((a_ns, a_name, -1, T_REFERENCE, int(value) & 0xFFFFFFFF))
        out = _start_elem(-1, pool.index[el.tag], attrs)
        for c in el.children:
            out += elem_chunks(c)
        out += _end_elem(-1, pool.index[el.tag])
        return out

    body = _string_pool_chunk(pool)
    body += _ns_chunk(0x0100, ns_prefix, ns_uri)  # START_NAMESPACE
    body += elem_chunks(root)
    body += _ns_chunk(0x0101, ns_prefix, ns_uri)  # END_NAMESPACE

    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


# ---------------------------------------------------------------------------
# Minimal DEX with planted strings
# ---------------------------------------------------------------------------

def _uleb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


PLANTED_STRINGS = [
    "AKIAIOSFODNN7EXAMPLE",                              # AWS access key id
    "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",           # Google API key (exactly 39 chars)
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",  # JWT
    "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH",           # Stripe live secret
    "-----BEGIN RSA PRIVATE KEY-----",                    # PEM private key marker
    "http://api.insecure-example.com/v1/login",           # cleartext endpoint
    "http://tracker.ads-example.net/collect",             # cleartext endpoint
    "DES/CBC/PKCS5Padding",                               # weak cipher
    "AES/ECB/PKCS5Padding",                               # ECB mode
    "RC4",                                                # weak cipher
    "ALLOW_ALL_HOSTNAME_VERIFIER",                        # disabled TLS validation
    "setWebContentsDebuggingEnabled",                     # webview debug
    "addJavascriptInterface",                             # js bridge
    "password=SuperSecret123!",                           # generic secret
    "Lcom/example/vulnerableapp/MainActivity;",           # a normal class string
    "Hello from the vulnerable sample app",
]


def _build_dex() -> bytes:
    strings = PLANTED_STRINGS
    header_size = 0x70
    string_ids_off = header_size
    ids_size = len(strings)
    data_off = string_ids_off + ids_size * 4

    data = b""
    id_offsets = []
    for s in strings:
        id_offsets.append(data_off + len(data))
        b = s.encode("utf-8")
        data += _uleb128(len(s)) + b + b"\x00"

    ids = b"".join(struct.pack("<I", o) for o in id_offsets)

    header = bytearray(header_size)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 0x20, header_size)              # file_size (approx)
    struct.pack_into("<I", header, 0x24, header_size)              # header_size
    struct.pack_into("<I", header, 0x28, 0x12345678)              # endian tag
    struct.pack_into("<I", header, 0x38, ids_size)                # string_ids_size
    struct.pack_into("<I", header, 0x3C, string_ids_off)          # string_ids_off

    blob = bytes(header) + ids + data
    # patch a believable file_size and adler32 checksum (not verified by us).
    blob = bytearray(blob)
    struct.pack_into("<I", blob, 0x20, len(blob))
    checksum = zlib.adler32(bytes(blob[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", blob, 0x08, checksum)
    return bytes(blob)


# ---------------------------------------------------------------------------
# Manifest tree — intentionally insecure
# ---------------------------------------------------------------------------

def _build_manifest() -> El:
    pkg = "com.example.vulnerableapp"

    def perm(name):
        return El("uses-permission", [("name", name, "str", True)])

    app_children = [
        El("activity", [
            ("name", f"{pkg}.MainActivity", "str", True),
            ("exported", True, "bool", True),
        ], [
            El("intent-filter", [], [
                El("action", [("name", "android.intent.action.MAIN", "str", True)]),
                El("category", [("name", "android.intent.category.LAUNCHER", "str", True)]),
            ]),
        ]),
        El("activity", [
            ("name", f"{pkg}.SecretActivity", "str", True),
            ("exported", True, "bool", True),
        ]),
        El("service", [
            ("name", f"{pkg}.ExportedService", "str", True),
            ("exported", True, "bool", True),
        ]),
        El("receiver", [
            ("name", f"{pkg}.BootReceiver", "str", True),
            ("exported", True, "bool", True),
        ], [
            El("intent-filter", [], [
                El("action", [("name", "android.intent.action.BOOT_COMPLETED", "str", True)]),
            ]),
        ]),
        El("provider", [
            ("name", f"{pkg}.DataProvider", "str", True),
            ("authorities", f"{pkg}.provider", "str", True),
            ("exported", True, "bool", True),
            ("grantUriPermissions", True, "bool", True),
        ]),
    ]

    application = El("application", [
        ("label", "Vulnerable Sample", "str", True),
        ("debuggable", True, "bool", True),
        ("allowBackup", True, "bool", True),
        ("usesCleartextTraffic", True, "bool", True),
    ], app_children)

    manifest = El("manifest", [
        ("package", pkg, "str", False),
        ("versionCode", 1, "int", True),
        ("versionName", "1.0", "str", True),
    ], [
        El("uses-sdk", [("minSdkVersion", 19, "int", True), ("targetSdkVersion", 26, "int", True)]),
        # protectionLevel is a flags attribute: real aapt compiles "normal" to
        # the integer 0. Encode it that way so the sample matches real APKs.
        El("permission", [("name", f"{pkg}.CUSTOM", "str", True), ("protectionLevel", 0, "int", True)]),
        perm("android.permission.INTERNET"),
        perm("android.permission.WRITE_EXTERNAL_STORAGE"),
        perm("android.permission.READ_SMS"),
        perm("android.permission.SYSTEM_ALERT_WINDOW"),
        perm("android.permission.REQUEST_INSTALL_PACKAGES"),
        perm("android.permission.ACCESS_FINE_LOCATION"),
        application,
    ])
    return manifest


def build_apk(path: str) -> None:
    manifest = _encode_axml(_build_manifest())
    dex = _build_dex()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr("resources.arsc", b"\x02\x00\x0c\x00" + b"\x00" * 8)  # stub
        z.writestr("res/xml/placeholder.xml", b"<x/>")
        z.writestr("assets/config.json", b'{"api":"http://api.insecure-example.com"}')
        # fake v1 signature so the APK reads as signed (keytool cannot parse it,
        # which the engine handles gracefully).
        z.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n\r\n")
        z.writestr("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n\r\n")
        z.writestr("META-INF/CERT.RSA", b"\x30\x82\x01\x00" + b"\x00" * 64)


def main(argv):
    out = argv[1] if len(argv) > 1 else "sample-vulnerable.apk"
    build_apk(out)
    print(f"Wrote sample vulnerable APK -> {out}")


if __name__ == "__main__":
    main(sys.argv)
