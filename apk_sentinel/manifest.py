"""Interpret a decoded AndroidManifest.xml element tree into ``ManifestInfo``.

This is the semantic layer on top of :mod:`apk_sentinel.axml`: it knows what a
``<uses-permission>`` means, how to resolve a relative component name against
the package, and how the runtime decides whether a component is exported.
"""
from __future__ import annotations

from typing import Optional

from . import axml
from .axml import XMLElement
from .models import Component, ManifestInfo

_COMPONENT_TAGS = {
    "activity": "activity",
    "activity-alias": "activity-alias",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


def _to_bool(v: Optional[str]) -> Optional[bool]:
    if v is None:
        return None
    v = v.strip().lower()
    if v in ("true", "1", "0xffffffff", "-1"):
        return True
    if v in ("false", "0"):
        return False
    return None


def _to_int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    v = v.strip()
    try:
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v)
    except ValueError:
        return None


def _resolve_name(name: Optional[str], package: Optional[str]) -> str:
    if not name:
        return ""
    if name.startswith(".") and package:
        return package + name
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def _parse_component(el: XMLElement, kind: str, package: Optional[str]) -> Component:
    filters = el.findall("intent-filter")
    actions = []
    categories = []
    for f in filters:
        for act in f.findall("action"):
            a = act.attr("name")
            if a:
                actions.append(a)
        for cat in f.findall("category"):
            c = cat.attr("name")
            if c:
                categories.append(c)
    comp = Component(
        kind=kind,
        name=_resolve_name(el.attr("name"), package),
        exported=_to_bool(el.attr("exported")),
        permission=el.attr("permission"),
        has_intent_filter=bool(filters),
        intent_actions=actions,
        intent_categories=categories,
    )
    if kind == "provider":
        comp.authorities = el.attr("authorities")
        comp.grant_uri_permissions = _to_bool(el.attr("grantUriPermissions"))
    # capture a couple of extra attributes seen on receivers/providers
    for extra_attr in ("readPermission", "writePermission", "launchMode"):
        val = el.attr(extra_attr)
        if val is not None:
            comp.extra[extra_attr] = val
    return comp


def build(root: XMLElement) -> ManifestInfo:
    info = ManifestInfo()
    if root.tag != "manifest":
        info.warnings.append(f"root element is <{root.tag}>, expected <manifest>")

    info.package = root.attr("package", android=False)
    info.version_code = _to_int(root.attr("versionCode"))
    info.version_name = root.attr("versionName")
    info.compile_sdk = _to_int(root.attr("compileSdkVersion"))

    for el in root.iter("uses-sdk"):
        info.min_sdk = _to_int(el.attr("minSdkVersion"))
        info.target_sdk = _to_int(el.attr("targetSdkVersion"))
        info.max_sdk = _to_int(el.attr("maxSdkVersion"))
        break

    for el in root.iter("uses-permission"):
        name = el.attr("name")
        if name and name not in info.permissions:
            info.permissions.append(name)
    # uses-permission-sdk-23 and similar variants
    for el in root.iter("uses-permission-sdk-23"):
        name = el.attr("name")
        if name and name not in info.permissions:
            info.permissions.append(name)

    for el in root.findall("permission"):
        info.custom_permissions.append({
            "name": el.attr("name"),
            "protectionLevel": el.attr("protectionLevel"),
            "permissionGroup": el.attr("permissionGroup"),
        })

    for el in root.iter("uses-feature"):
        name = el.attr("name")
        if name:
            info.features.append(name)

    app = next(root.iter("application"), None)
    if app is not None:
        info.debuggable = _to_bool(app.attr("debuggable"))
        info.allow_backup = _to_bool(app.attr("allowBackup"))
        info.uses_cleartext_traffic = _to_bool(app.attr("usesCleartextTraffic"))
        info.network_security_config = app.attr("networkSecurityConfig")
        info.has_code = _to_bool(app.attr("hasCode"))
        info.app_label = app.attr("label")

        for child in app.iter():
            kind = _COMPONENT_TAGS.get(child.tag)
            if not kind or child is app:
                continue
            comp = _parse_component(child, kind, info.package)
            if kind in ("activity", "activity-alias"):
                info.activities.append(comp)
            elif kind == "service":
                info.services.append(comp)
            elif kind == "receiver":
                info.receivers.append(comp)
            elif kind == "provider":
                info.providers.append(comp)

    return info


def from_bytes(data: bytes) -> ManifestInfo:
    root = axml.parse(data)
    return build(root)
