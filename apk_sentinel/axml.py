"""A dependency-free parser for Android binary XML (AXML).

``AndroidManifest.xml`` inside an APK is not text — it is compiled into a
chunk-based binary format ("AXML"). This module decodes it into a lightweight
element tree without needing aapt, the Android SDK or any third-party library.

The format is documented in the AOSP ``ResourceTypes.h`` header. Only the
subset needed to read a manifest is implemented, but it is implemented
defensively so it degrades gracefully on unusual / obfuscated inputs.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# -- Chunk type constants ------------------------------------------------
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# String pool flags
UTF8_FLAG = 1 << 8

# Res_value data types
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_DIMENSION = 0x05
TYPE_FRACTION = 0x06
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12
TYPE_FIRST_COLOR_INT = 0x1C
TYPE_LAST_COLOR_INT = 0x1F

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Framework attribute resource-id -> name. Used only as a fallback for APKs
# whose attribute name strings were stripped (some obfuscators do this). These
# ids are stable public framework resource identifiers.
_ATTR_RES_IDS: Dict[int, str] = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010006: "permission",
    0x01010009: "protectionLevel",
    0x0101000E: "enabled",
    0x0101000F: "debuggable",
    0x01010010: "exported",
    0x01010018: "authorities",
    0x0101001B: "grantUriPermissions",
    0x0101001C: "priority",
    0x0101001D: "launchMode",
    0x01010021: "targetActivity",
    0x0101020C: "minSdkVersion",
    0x0101020D: "maxSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010280: "allowBackup",
    0x0101048F: "usesCleartextTraffic",
    0x01010572: "networkSecurityConfig",
    0x01010603: "roundIcon",
    0x0101055B: "installLocation",
}


class AXMLParseError(Exception):
    """Raised when the input is not decodable as Android binary XML."""


@dataclass
class XMLAttribute:
    namespace: Optional[str]
    name: str
    value: str
    raw_type: int

    @property
    def is_android(self) -> bool:
        return self.namespace == ANDROID_NS


@dataclass
class XMLElement:
    tag: str
    attributes: List[XMLAttribute] = field(default_factory=list)
    children: List["XMLElement"] = field(default_factory=list)
    parent: Optional["XMLElement"] = None

    def attr(self, name: str, android: bool = True) -> Optional[str]:
        """Return the value of an attribute by local name.

        When ``android`` is True the android-namespaced attribute wins, but a
        namespace-less attribute with the same name is accepted as a fallback.
        """
        fallback = None
        for a in self.attributes:
            if a.name != name:
                continue
            if android and a.is_android:
                return a.value
            if not android and a.namespace is None:
                return a.value
            fallback = a.value
        return fallback

    def iter(self, tag: Optional[str] = None):
        """Depth-first iterator over this element and its descendants."""
        stack = [self]
        while stack:
            el = stack.pop()
            if tag is None or el.tag == tag:
                yield el
            # preserve document order for children
            stack.extend(reversed(el.children))

    def findall(self, tag: str) -> List["XMLElement"]:
        return [c for c in self.children if c.tag == tag]


class _StringPool:
    """Decodes a RES_STRING_POOL chunk into a list of strings."""

    def __init__(self, data: bytes, chunk_off: int):
        self.strings: List[str] = []
        self._parse(data, chunk_off)

    def _parse(self, data: bytes, off: int) -> None:
        (_type, header_size, size) = struct.unpack_from("<HHI", data, off)
        (string_count, style_count, flags, strings_start, styles_start) = \
            struct.unpack_from("<IIIII", data, off + 8)
        is_utf8 = bool(flags & UTF8_FLAG)
        offsets_base = off + header_size
        data_base = off + strings_start
        # string_count is an untrusted u32; cap it to the offsets that actually
        # fit in the buffer so a corrupt/huge count can't blow up or hang.
        max_by_buffer = max(0, (len(data) - offsets_base) // 4)
        for i in range(min(string_count, max_by_buffer)):
            try:
                (str_off,) = struct.unpack_from("<I", data, offsets_base + i * 4)
                self.strings.append(self._decode_string(data, data_base + str_off, is_utf8))
            except Exception:
                self.strings.append("")

    @staticmethod
    def _decode_len8(data: bytes, off: int) -> Tuple[int, int]:
        n = data[off]
        off += 1
        if n & 0x80:
            n = ((n & 0x7F) << 8) | data[off]
            off += 1
        return n, off

    @staticmethod
    def _decode_len16(data: bytes, off: int) -> Tuple[int, int]:
        n = data[off] | (data[off + 1] << 8)
        off += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | (data[off] | (data[off + 1] << 8))
            off += 2
        return n, off

    def _decode_string(self, data: bytes, off: int, is_utf8: bool) -> str:
        if is_utf8:
            # UTF-8: <char count><byte count><bytes><00>
            _char_count, off = self._decode_len8(data, off)
            byte_count, off = self._decode_len8(data, off)
            raw = data[off:off + byte_count]
            return raw.decode("utf-8", errors="replace")
        # UTF-16LE: <char count><units...><0000>
        char_count, off = self._decode_len16(data, off)
        raw = data[off:off + char_count * 2]
        return raw.decode("utf-16-le", errors="replace")

    def get(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""


def _fmt_value(raw_type: int, data: int, pool: _StringPool) -> str:
    """Format a Res_value into a human/comparable string."""
    if raw_type == TYPE_STRING:
        return pool.get(data)
    if raw_type == TYPE_INT_BOOLEAN:
        return "true" if data != 0 else "false"
    if raw_type == TYPE_INT_HEX:
        return "0x%X" % (data & 0xFFFFFFFF)
    if raw_type in (TYPE_INT_DEC,):
        # interpret as signed 32-bit
        return str(struct.unpack("<i", struct.pack("<I", data & 0xFFFFFFFF))[0])
    if raw_type == TYPE_REFERENCE:
        return "@0x%08X" % (data & 0xFFFFFFFF)
    if raw_type == TYPE_ATTRIBUTE:
        return "?0x%08X" % (data & 0xFFFFFFFF)
    if raw_type == TYPE_FLOAT:
        return str(struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0])
    if TYPE_FIRST_COLOR_INT <= raw_type <= TYPE_LAST_COLOR_INT:
        return "#%08X" % (data & 0xFFFFFFFF)
    # signed fallback
    return str(struct.unpack("<i", struct.pack("<I", data & 0xFFFFFFFF))[0])


def parse(data: bytes) -> XMLElement:
    """Parse Android binary XML bytes and return the root :class:`XMLElement`.

    Raises :class:`AXMLParseError` if the input is not binary XML.
    """
    if len(data) < 8:
        raise AXMLParseError("file too small to be AXML")
    (magic, _header_size, _total) = struct.unpack_from("<HHI", data, 0)
    if magic != RES_XML_TYPE:
        raise AXMLParseError(
            "not Android binary XML (magic=0x%04X, expected 0x%04X)" % (magic, RES_XML_TYPE)
        )

    pool: Optional[_StringPool] = None
    res_map: List[int] = []

    off = 8  # skip the outer RES_XML chunk header
    root: Optional[XMLElement] = None
    current: Optional[XMLElement] = None
    ns_map: Dict[str, str] = {}  # prefix-uri map keyed by uri actually
    size = len(data)

    while off + 8 <= size:
        (ctype, header_size, csize) = struct.unpack_from("<HHI", data, off)
        # A chunk must be at least a header, must fit in the buffer, and must
        # advance. Any violation means the stream is malformed — stop with what
        # we have rather than reading out of bounds.
        if csize < 8 or off + csize > size or header_size < 8:
            break
        next_off = off + csize

        try:
            if ctype == RES_STRING_POOL_TYPE:
                pool = _StringPool(data, off)
            elif ctype == RES_XML_RESOURCE_MAP_TYPE:
                count = max(0, (csize - header_size) // 4)
                for i in range(count):
                    (rid,) = struct.unpack_from("<I", data, off + header_size + i * 4)
                    res_map.append(rid)
            elif ctype == RES_XML_START_NAMESPACE_TYPE:
                if pool is not None:
                    (prefix_ref, uri_ref) = struct.unpack_from("<ii", data, off + header_size)
                    if uri_ref >= 0:
                        ns_map[pool.get(uri_ref)] = pool.get(prefix_ref) if prefix_ref >= 0 else ""
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                if pool is None:
                    raise AXMLParseError("start element before string pool")
                el = _parse_start_element(data, off, header_size, pool, res_map)
                if root is None:
                    root = el
                if current is not None:
                    el.parent = current
                    current.children.append(el)
                current = el
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                if current is not None:
                    current = current.parent
            # namespaces-end / cdata: ignored for manifest purposes
        except AXMLParseError:
            raise
        except (struct.error, IndexError):
            # a single corrupt chunk shouldn't abort the whole parse
            pass

        if next_off <= off:
            break
        off = next_off

    if root is None:
        raise AXMLParseError("no XML elements found")
    return root


def _parse_start_element(
    data: bytes, off: int, header_size: int, pool: _StringPool, res_map: List[int]
) -> XMLElement:
    # ResXMLTree_node: lineNumber(u32) comment(u32) then attrExt
    ext = off + header_size
    (ns_ref, name_ref, attr_start, attr_size, attr_count) = \
        struct.unpack_from("<iiHHH", data, ext)
    # idIndex, classIndex, styleIndex follow (3 x u16) but are not needed.
    tag = pool.get(name_ref) if name_ref >= 0 else ""
    el = XMLElement(tag=tag)

    attr_base = ext + attr_start
    stride = attr_size if attr_size else 20
    # cap attr_count to what actually fits, so a corrupt count can't iterate
    # over unrelated buffer bytes as if they were attributes.
    max_attrs = max(0, (len(data) - attr_base) // stride)
    for i in range(min(attr_count, max_attrs)):
        a_off = attr_base + i * stride
        (a_ns, a_name, a_rawval, val_size, _res0, val_type, val_data) = \
            struct.unpack_from("<iiiHBBI", data, a_off)
        name = pool.get(a_name) if a_name >= 0 else ""
        if not name and 0 <= a_name < len(res_map):
            # attribute name string was stripped; recover from resource map id
            name = _ATTR_RES_IDS.get(res_map[a_name], "")
        namespace = pool.get(a_ns) if a_ns >= 0 else None
        if a_rawval >= 0 and val_type == TYPE_STRING:
            value = pool.get(a_rawval)
        else:
            value = _fmt_value(val_type, val_data, pool)
        el.attributes.append(
            XMLAttribute(namespace=namespace, name=name, value=value, raw_type=val_type)
        )
    return el


def is_binary_xml(data: bytes) -> bool:
    if len(data) < 4:
        return False
    (magic,) = struct.unpack_from("<H", data, 0)
    return magic == RES_XML_TYPE
