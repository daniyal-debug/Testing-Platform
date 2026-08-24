"""The security & quality rule catalog.

Each rule is a small function that receives a :class:`RuleContext` and returns
zero or more :class:`Finding` objects. Rules are grouped only for readability;
the engine simply runs them all. Every rule aims to be low-false-positive: it
fires on evidence actually present in the APK, and its ``id`` keys into the
remediation knowledge base (:mod:`apk_sentinel.knowledge`) for the long-form
fix guide shown in the report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .models import (
    CertificateInfo,
    Component,
    Finding,
    ManifestInfo,
    SecretMatch,
    Severity,
)

# Latest-ish Android platform targets (as of 2024-2025). Play Store requires
# targeting within roughly one year of the newest release.
RECOMMENDED_TARGET_SDK = 34
CURRENT_TARGET_SDK = 35


@dataclass
class RuleContext:
    manifest: ManifestInfo
    certificate: CertificateInfo
    dex_strings: List[str] = field(default_factory=list)
    secrets: List[SecretMatch] = field(default_factory=list)
    cleartext_urls: List[str] = field(default_factory=list)
    native_libs: List[str] = field(default_factory=list)
    dex_count: int = 0
    file_names: List[str] = field(default_factory=list)
    total_uncompressed: int = 0

    # cheap lowercase index of dex strings for substring checks
    _lower_join: Optional[str] = None

    def dex_contains(self, needle: str) -> bool:
        if self._lower_join is None:
            self._lower_join = "\n".join(self.dex_strings).lower()
        return needle.lower() in self._lower_join


_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.CALL_PHONE",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE", "android.permission.GET_ACCOUNTS",
    "android.permission.BODY_SENSORS", "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR", "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
}

_HIGH_RISK_PERMISSIONS = {
    "android.permission.REQUEST_INSTALL_PACKAGES": "can prompt the user to install arbitrary APKs",
    "android.permission.SYSTEM_ALERT_WINDOW": "can draw overlays over other apps (tapjacking / overlay attacks)",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility services can observe and act on all screen content",
    "android.permission.WRITE_SETTINGS": "can modify global system settings",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "grants broad ('all files') storage access",
    "android.permission.QUERY_ALL_PACKAGES": "can enumerate every installed app (privacy sensitive)",
    "android.permission.READ_PHONE_NUMBERS": "reads the device phone number",
    "android.permission.RECEIVE_BOOT_COMPLETED": "runs code automatically at device boot",
}


def _launcher(comp: Component) -> bool:
    """A home-screen launcher entry needs BOTH the MAIN action and the LAUNCHER
    category. LEANBACK_LAUNCHER (Android TV) counts too."""
    return "android.intent.action.MAIN" in comp.intent_actions and (
        "android.intent.category.LAUNCHER" in comp.intent_categories
        or "android.intent.category.LEANBACK_LAUNCHER" in comp.intent_categories
    )


# Base protection levels: normal=0, dangerous=1 are "weak"; signature=2 and
# above are strong. Higher bits are flags (privileged, development, ...).
_PROTECTION_NAMES = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}


def _protection_base(value) -> Optional[int]:
    """Parse a protectionLevel attribute (string OR aapt-compiled integer) into
    its base level 0-3, or None if it is a non-numeric symbolic string."""
    if value is None:
        return 0  # attribute absent -> defaults to 'normal'
    v = str(value).strip().lower()
    if v == "":
        return 0
    try:
        n = int(v, 16) if v.startswith("0x") else int(v)
        return n & 0x0F
    except ValueError:
        return None


def _protection_is_weak(value) -> bool:
    base = _protection_base(value)
    if base is not None:
        return base in (0, 1)
    v = str(value).strip().lower()
    if "signature" in v or "internal" in v or "knownsigner" in v:
        return False
    return "normal" in v or "dangerous" in v


def _protection_label(value) -> str:
    base = _protection_base(value)
    if base is not None:
        name = _PROTECTION_NAMES.get(base, f"level {base}")
        return f"{name} (default)" if (value is None or str(value).strip() == "") else name
    return str(value)


def _provider_effective_exported(c: Component, target_sdk: Optional[int]) -> bool:
    """A <provider> with no explicit exported attribute is exported by default
    when targetSdk < 17; from 17+ the default is not-exported."""
    if c.exported is not None:
        return c.exported
    return target_sdk is None or target_sdk < 17


# ---------------------------------------------------------------------------
# Configuration rules
# ---------------------------------------------------------------------------

def rule_debuggable(ctx: RuleContext) -> List[Finding]:
    if ctx.manifest.debuggable is True:
        return [Finding(
            id="android-debuggable",
            title="Application is debuggable (android:debuggable=\"true\")",
            severity=Severity.CRITICAL,
            category="Configuration",
            description=(
                "The application manifest sets android:debuggable=\"true\". Any user "
                "with USB/ADB access can attach a debugger (jdb), read process memory, "
                "invoke arbitrary methods and run code as the app — bypassing most "
                "client-side protections."
            ),
            evidence=["<application android:debuggable=\"true\">"],
            remediation=(
                "Remove android:debuggable from the manifest (Android sets it "
                "automatically per build type) or set it to \"false\" for release. "
                "Ensure your release build is not built with a debug variant."
            ),
            references=[
                "https://developer.android.com/privacy-and-security/risks/android-debuggable",
                "OWASP MASVS-RESILIENCE-1",
            ],
            cwe="CWE-489", masvs="MASVS-RESILIENCE-1",
        )]
    return []


def rule_allow_backup(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    # allowBackup defaults to true. Flag when explicitly true, or defaulted true
    # on a target that still honours it (< 31 disables auto-backup key material
    # concerns differently, but data backup still applies).
    explicit_true = m.allow_backup is True
    defaulted = m.allow_backup is None
    if explicit_true or defaulted:
        sev = Severity.MEDIUM if explicit_true else Severity.LOW
        state = "android:allowBackup=\"true\"" if explicit_true else "android:allowBackup not set (defaults to true)"
        return [Finding(
            id="app-backup-allowed",
            title="Application data backup is allowed",
            severity=sev,
            category="Configuration",
            description=(
                "With allowBackup enabled, an attacker with ADB access can extract the "
                "app's private data via `adb backup`, and Auto Backup may copy data to "
                "the cloud. Sensitive local data (tokens, PII, databases) can leak."
            ),
            evidence=[state],
            remediation=(
                "Set android:allowBackup=\"false\" if the app stores sensitive data, or "
                "define android:fullBackupContent / android:dataExtractionRules to "
                "exclude secrets from backups."
            ),
            references=[
                "https://developer.android.com/guide/topics/data/autobackup",
                "OWASP MASVS-STORAGE-2",
            ],
            cwe="CWE-530", masvs="MASVS-STORAGE-2",
        )]
    return []


def rule_cleartext_traffic(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    out = []
    if m.uses_cleartext_traffic is True:
        out.append(Finding(
            id="cleartext-traffic-enabled",
            title="Cleartext (HTTP) network traffic is explicitly enabled",
            severity=Severity.HIGH,
            category="Network Security",
            description=(
                "android:usesCleartextTraffic=\"true\" allows the app to send traffic "
                "over unencrypted HTTP. This exposes data to interception and "
                "manipulation by any network attacker (public Wi-Fi, rogue router)."
            ),
            evidence=["<application android:usesCleartextTraffic=\"true\">"],
            remediation=(
                "Set usesCleartextTraffic=\"false\" and migrate all endpoints to HTTPS. "
                "If specific hosts genuinely require cleartext, allow only those in a "
                "network_security_config.xml domain-config instead of enabling it globally."
            ),
            references=[
                "https://developer.android.com/privacy-and-security/security-config",
                "OWASP MASVS-NETWORK-1",
            ],
            cwe="CWE-319", masvs="MASVS-NETWORK-1",
        ))
    elif (
        m.uses_cleartext_traffic is None
        and not m.network_security_config
        and (m.target_sdk is not None and m.target_sdk < 28)
    ):
        out.append(Finding(
            id="cleartext-traffic-default",
            title="Cleartext traffic allowed by default (targetSdk < 28)",
            severity=Severity.MEDIUM,
            category="Network Security",
            description=(
                f"The app targets API {m.target_sdk}. Before API 28 (Android 9) cleartext "
                "HTTP is permitted by default, so any accidental http:// request will be "
                "sent unencrypted."
            ),
            evidence=[f"targetSdkVersion={m.target_sdk}, no usesCleartextTraffic, no networkSecurityConfig"],
            remediation=(
                "Raise targetSdkVersion to 28+ (cleartext blocked by default), or add a "
                "network_security_config.xml that sets cleartextTrafficPermitted=\"false\"."
            ),
            references=["OWASP MASVS-NETWORK-1"],
            cwe="CWE-319", masvs="MASVS-NETWORK-1",
        ))
    return out


def rule_network_security_config(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    if not m.network_security_config and (m.target_sdk is None or m.target_sdk >= 24):
        return [Finding(
            id="no-network-security-config",
            title="No Network Security Configuration is defined",
            severity=Severity.LOW,
            category="Network Security",
            description=(
                "The app does not declare a networkSecurityConfig. A Network Security "
                "Config lets you enforce HTTPS, pin certificates, and control trust "
                "anchors declaratively — a strong, low-effort hardening measure."
            ),
            evidence=["<application> has no android:networkSecurityConfig"],
            remediation=(
                "Add res/xml/network_security_config.xml, reference it from the manifest, "
                "set cleartextTrafficPermitted=\"false\" as the base config, and consider "
                "certificate pinning for your API domains."
            ),
            references=[
                "https://developer.android.com/privacy-and-security/security-config",
                "OWASP MASVS-NETWORK-2",
            ],
            cwe="CWE-295", masvs="MASVS-NETWORK-2",
        )]
    return []


def rule_exported_components(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    findings: List[Finding] = []

    # Providers are the highest risk when exported without permission. Their
    # implicit-export default is target-SDK dependent (exported when target<17).
    bad_providers = [
        c for c in m.providers
        if _provider_effective_exported(c, m.target_sdk) and not c.permission
        and not c.extra.get("readPermission") and not c.extra.get("writePermission")
    ]
    if bad_providers:
        findings.append(Finding(
            id="exported-content-provider",
            title="Content provider exported without permission protection",
            severity=Severity.HIGH,
            category="Configuration",
            description=(
                "An exported <provider> with no permission lets any other app on the "
                "device read/write its data or reach its URIs, a classic path to data "
                "leakage and SQL injection via the provider interface."
            ),
            evidence=[
                f"{c.name or '(unnamed)'} authorities={c.authorities or '?'} "
                f"exported={c.exported if c.exported is not None else 'implicit'}"
                for c in bad_providers
            ],
            remediation=(
                "Set android:exported=\"false\" unless the provider must be shared. If it "
                "must be exported, guard it with a signature-level permission and validate "
                "every incoming URI/selection argument (use parameterised queries)."
            ),
            references=[
                "https://developer.android.com/guide/topics/manifest/provider-element",
                "OWASP MASVS-PLATFORM-1",
            ],
            cwe="CWE-926", masvs="MASVS-PLATFORM-1",
        ))

    # Activities/services/receivers exported without permission (excluding the
    # launcher activity, which is expected to be exported).
    bad_others: List[Component] = []
    for c in m.activities + m.services + m.receivers:
        if not c.effective_exported or c.permission:
            continue
        if c.kind in ("activity", "activity-alias") and _launcher(c):
            continue
        bad_others.append(c)
    if bad_others:
        findings.append(Finding(
            id="exported-component-no-permission",
            title="Components exported without permission protection",
            severity=Severity.MEDIUM,
            category="Configuration",
            description=(
                "These components are reachable by any other app on the device. Exported "
                "activities/services/receivers without a permission can be invoked with "
                "attacker-controlled Intents, enabling data leakage, state manipulation "
                "or denial of service."
            ),
            evidence=[
                f"{c.kind}: {c.name or '(unnamed)'} "
                f"(exported={'explicit' if c.exported is not None else 'implicit via intent-filter'}"
                f"{', has intent-filter' if c.has_intent_filter else ''})"
                for c in bad_others
            ],
            remediation=(
                "Set android:exported=\"false\" for components that are not meant to be "
                "used by other apps. For components that must stay exported, require a "
                "custom signature-level permission and rigorously validate all incoming "
                "Intent extras and data URIs."
            ),
            references=[
                "https://developer.android.com/guide/topics/manifest/activity-element#exported",
                "OWASP MASVS-PLATFORM-1",
            ],
            cwe="CWE-926", masvs="MASVS-PLATFORM-1",
        ))
    return findings


def rule_implicit_export_target31(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    if m.target_sdk is None or m.target_sdk < 31:
        return []
    implicit = [
        c for c in m.all_components
        if c.exported is None and c.has_intent_filter and not _launcher(c)
    ]
    if implicit:
        return [Finding(
            id="implicit-exported-component",
            title="Component has an intent-filter but no explicit android:exported",
            severity=Severity.LOW,
            category="Best Practices",
            description=(
                "On Android 12+ (API 31) every component with an intent-filter must "
                "declare android:exported explicitly. Relying on the implicit default is "
                "error-prone and, on API 31+, will fail installation."
            ),
            evidence=[f"{c.kind}: {c.name or '(unnamed)'}" for c in implicit],
            remediation="Add an explicit android:exported=\"true\" or \"false\" to each listed component.",
            references=["https://developer.android.com/about/versions/12/behavior-changes-12#exported"],
            cwe="CWE-1188", masvs="MASVS-PLATFORM-1",
        )]
    return []


# ---------------------------------------------------------------------------
# Permission rules
# ---------------------------------------------------------------------------

def rule_high_risk_permissions(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    hits = [(p, why) for p, why in _HIGH_RISK_PERMISSIONS.items() if p in m.permissions]
    if hits:
        return [Finding(
            id="high-risk-permissions",
            title="High-risk permissions requested",
            severity=Severity.MEDIUM,
            category="Permissions",
            description=(
                "The app requests permissions that materially expand its attack surface "
                "or privacy impact. Each should be justified and, where possible, removed."
            ),
            evidence=[f"{p} — {why}" for p, why in hits],
            remediation=(
                "Remove any permission the app does not strictly need. For those that are "
                "required, document the justification, request them at runtime with clear "
                "rationale, and follow the principle of least privilege."
            ),
            references=[
                "https://developer.android.com/training/permissions/usage-notes",
                "OWASP MASVS-PLATFORM-1",
            ],
            cwe="CWE-250", masvs="MASVS-PLATFORM-1",
        )]
    return []


def rule_dangerous_permissions(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    hits = [p for p in m.permissions if p in _DANGEROUS_PERMISSIONS]
    if hits:
        return [Finding(
            id="dangerous-permissions",
            title="Dangerous (runtime) permissions requested",
            severity=Severity.INFO,
            category="Permissions",
            description=(
                "The app declares runtime ('dangerous') permissions that grant access to "
                "sensitive user data or device capabilities. This is informational — "
                "verify each is actually used and requested with proper rationale."
            ),
            evidence=sorted(hits),
            remediation=(
                "Audit each dangerous permission against real feature usage. Request at "
                "runtime only when the feature is used, handle denial gracefully, and drop "
                "any that are unused."
            ),
            references=["https://developer.android.com/guide/topics/permissions/overview#dangerous_permissions"],
            masvs="MASVS-PLATFORM-1",
        )]
    return []


def rule_custom_permission_weak(ctx: RuleContext) -> List[Finding]:
    weak = []
    for p in ctx.manifest.custom_permissions:
        # protectionLevel is a flags attribute: aapt compiles it to an integer
        # ("0"/"1"/"2"), while an un-compiled manifest carries the symbolic name.
        # _protection_is_weak handles both forms.
        raw = p.get("protectionLevel")
        if _protection_is_weak(raw):
            weak.append(f"{p.get('name') or '(unnamed)'} protectionLevel={_protection_label(raw)}")
    if weak:
        return [Finding(
            id="weak-custom-permission",
            title="Custom permission uses a weak protection level",
            severity=Severity.MEDIUM,
            category="Permissions",
            description=(
                "A custom permission defined at protectionLevel 'normal' (or unset) is "
                "granted to any app that requests it, so it provides no real access "
                "control for the components it guards."
            ),
            evidence=weak,
            remediation=(
                "Set android:protectionLevel=\"signature\" so only apps signed with the "
                "same key are granted the permission. Register custom permissions before "
                "the components that use them."
            ),
            references=["https://developer.android.com/guide/topics/permissions/defining"],
            cwe="CWE-280", masvs="MASVS-PLATFORM-1",
        )]
    return []


# ---------------------------------------------------------------------------
# SDK / platform rules
# ---------------------------------------------------------------------------

def rule_min_sdk(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    if m.min_sdk is not None and m.min_sdk < 24:
        sev = Severity.MEDIUM if m.min_sdk >= 21 else Severity.HIGH
        return [Finding(
            id="low-min-sdk",
            title=f"minSdkVersion is low (API {m.min_sdk})",
            severity=sev,
            category="Configuration",
            description=(
                f"Supporting API {m.min_sdk} exposes the app to a large population of "
                "unpatched OS versions that lack modern TLS defaults, scoped storage, and "
                "numerous platform security fixes. Older WebView and crypto providers on "
                "these versions have known vulnerabilities."
            ),
            evidence=[f"minSdkVersion={m.min_sdk}"],
            remediation=(
                "Raise minSdkVersion to at least 24 (Android 7.0) — ideally 26+ — unless "
                "you have a specific, measured reason to support older devices."
            ),
            references=["https://developer.android.com/google/play/requirements/target-sdk"],
            masvs="MASVS-PLATFORM-2",
        )]
    return []


def rule_target_sdk(ctx: RuleContext) -> List[Finding]:
    m = ctx.manifest
    if m.target_sdk is None:
        return []
    if m.target_sdk < RECOMMENDED_TARGET_SDK:
        sev = Severity.MEDIUM if m.target_sdk >= 30 else Severity.HIGH
        return [Finding(
            id="outdated-target-sdk",
            title=f"targetSdkVersion is outdated (API {m.target_sdk})",
            severity=sev,
            category="Configuration",
            description=(
                f"The app targets API {m.target_sdk}, below the recommended "
                f"API {RECOMMENDED_TARGET_SDK}+. A low target SDK opts the app out of "
                "modern security defaults (scoped storage, restricted broadcasts, "
                "cleartext blocking, stricter PendingIntent mutability) and blocks Play "
                "Store updates."
            ),
            evidence=[f"targetSdkVersion={m.target_sdk}"],
            remediation=(
                f"Update targetSdkVersion to {CURRENT_TARGET_SDK} (or the latest stable "
                "API), test against the associated behaviour changes, and re-release."
            ),
            references=["https://developer.android.com/google/play/requirements/target-sdk"],
            masvs="MASVS-PLATFORM-2",
        )]
    return []


# ---------------------------------------------------------------------------
# Signing rules
# ---------------------------------------------------------------------------

def rule_unsigned(ctx: RuleContext) -> List[Finding]:
    c = ctx.certificate
    if not (c.v1_signed or c.v2_signed or c.v3_signed):
        return [Finding(
            id="unsigned-apk",
            title="APK is not signed",
            severity=Severity.CRITICAL,
            category="Signing",
            description=(
                "No signature scheme (v1/v2/v3) was detected. An unsigned APK cannot be "
                "installed on a normal device and offers no integrity or authenticity "
                "guarantee — its contents could have been tampered with."
            ),
            evidence=["No META-INF signature files and no APK Signing Block found"],
            remediation=(
                "Sign the release APK with your upload/signing key using apksigner and "
                "enable the v2/v3 signature schemes (v3 recommended)."
            ),
            references=["https://developer.android.com/studio/publish/app-signing"],
            cwe="CWE-347", masvs="MASVS-RESILIENCE-3",
        )]
    return []


def rule_v1_only(ctx: RuleContext) -> List[Finding]:
    c = ctx.certificate
    if c.v1_signed and not c.v2_signed and not c.v3_signed:
        return [Finding(
            id="v1-only-signature",
            title="APK uses only the legacy v1 (JAR) signature scheme",
            severity=Severity.MEDIUM,
            category="Signing",
            description=(
                "The APK is signed only with the legacy JAR signature (v1). v1 is "
                "vulnerable to the Janus attack (CVE-2017-13156) on Android 5.0–7.0, "
                "where a DEX file can be prepended without invalidating the signature."
            ),
            evidence=["META-INF/*.RSA present but no APK Signing Block (v2/v3)"],
            remediation=(
                "Re-sign enabling the v2 and v3 signature schemes (apksigner does this by "
                "default). Keep v1 only if you must support Android < 7.0."
            ),
            references=["https://source.android.com/docs/security/features/apksigning/v2"],
            cwe="CWE-347", masvs="MASVS-RESILIENCE-3",
        )]
    return []


def rule_cert_quality(ctx: RuleContext) -> List[Finding]:
    out = []
    for signer in ctx.certificate.signers:
        if signer.get("weak_signature"):
            out.append(Finding(
                id="weak-cert-signature",
                title="Signing certificate uses a weak signature algorithm",
                severity=Severity.HIGH,
                category="Signing",
                description=(
                    "The signing certificate uses a broken/weak hash "
                    f"({signer.get('sig_algorithm')}). SHA-1 and MD5 are collision-prone, "
                    "weakening the integrity guarantee of the signature."
                ),
                evidence=[f"Signature algorithm: {signer.get('sig_algorithm')}", f"Subject: {signer.get('subject')}"],
                remediation="Generate a new signing certificate using SHA-256 (RSA-2048/3072 or EC P-256) and re-sign.",
                references=["https://developer.android.com/studio/publish/app-signing"],
                cwe="CWE-327", masvs="MASVS-RESILIENCE-3",
            ))
        if signer.get("debug_certificate"):
            out.append(Finding(
                id="debug-certificate",
                title="APK is signed with the Android debug certificate",
                severity=Severity.HIGH,
                category="Signing",
                description=(
                    "The APK is signed with the public, well-known Android debug key "
                    "(CN=Android Debug). Anyone can forge updates or impersonate the app; "
                    "it must never be used for distribution."
                ),
                evidence=[f"Subject: {signer.get('subject')}"],
                remediation="Sign the release build with a private release keystore, not the debug key.",
                references=["https://developer.android.com/studio/publish/app-signing"],
                cwe="CWE-321", masvs="MASVS-RESILIENCE-3",
            ))
    return out


# ---------------------------------------------------------------------------
# Code & secrets rules
# ---------------------------------------------------------------------------

def rule_hardcoded_secrets(ctx: RuleContext) -> List[Finding]:
    if not ctx.secrets:
        return []
    # High-signal secret kinds get CRITICAL; generic ones HIGH.
    generic = {"Generic Secret Assignment", "Generic Bearer Token", "Firebase Database URL", "Stripe Publishable Key"}
    critical = [s for s in ctx.secrets if s.kind not in generic]
    findings = []
    if critical:
        findings.append(Finding(
            id="hardcoded-secret",
            title="Hard-coded credentials / API keys found",
            severity=Severity.CRITICAL,
            category="Code & Secrets",
            description=(
                "High-confidence secrets were found embedded in the app's DEX bytecode. "
                "Anyone can unzip the APK and read these values, so they must be treated "
                "as compromised and rotated immediately."
            ),
            evidence=[f"{s.kind}: {s.value_preview} (in {s.source})" for s in critical],
            remediation=(
                "Rotate every exposed key now. Never ship secrets in the client: move "
                "privileged calls behind your backend, use short-lived tokens, restrict "
                "API keys by package name + SHA-256 signature, and keep server secrets "
                "server-side. Client obfuscation is not a substitute."
            ),
            references=[
                "https://developer.android.com/privacy-and-security/security-tips#Credentials",
                "OWASP MASVS-STORAGE-1",
            ],
            cwe="CWE-798", masvs="MASVS-STORAGE-1",
        ))
    weak = [s for s in ctx.secrets if s.kind in generic]
    if weak:
        findings.append(Finding(
            id="possible-hardcoded-secret",
            title="Possible hard-coded secrets (lower confidence)",
            severity=Severity.MEDIUM,
            category="Code & Secrets",
            description=(
                "Strings matching secret-like patterns were found. These may be false "
                "positives (placeholders, sample values) but should be reviewed."
            ),
            evidence=[f"{s.kind}: {s.value_preview} (in {s.source})" for s in weak],
            remediation="Review each match. If it is a real credential, rotate and remove it from the client per the guidance for hard-coded secrets.",
            references=["OWASP MASVS-STORAGE-1"],
            cwe="CWE-798", masvs="MASVS-STORAGE-1",
        ))
    return findings


def rule_cleartext_urls(ctx: RuleContext) -> List[Finding]:
    if ctx.cleartext_urls:
        return [Finding(
            id="cleartext-url-in-code",
            title="Cleartext HTTP endpoints referenced in code",
            severity=Severity.MEDIUM,
            category="Network Security",
            description=(
                "The bytecode references http:// URLs. Traffic to these endpoints is "
                "unencrypted and can be read or modified by a network attacker."
            ),
            evidence=ctx.cleartext_urls[:25],
            remediation="Switch these endpoints to HTTPS. If an endpoint cannot support TLS, isolate it in a network security config domain-config and document the risk.",
            references=["OWASP MASVS-NETWORK-1"],
            cwe="CWE-319", masvs="MASVS-NETWORK-1",
        )]
    return []


def rule_weak_crypto(ctx: RuleContext) -> List[Finding]:
    hits = []
    for token, label in (
        ("DES/", "DES cipher"),
        ("DESede", "3DES (Triple DES) cipher"),
        ("/ECB/", "ECB block-cipher mode (leaks plaintext patterns)"),
        ("AES/ECB", "AES in ECB mode"),
        ("RC4", "RC4 stream cipher"),
    ):
        if ctx.dex_contains(token):
            hits.append(f"{token} — {label}")
    if hits:
        return [Finding(
            id="weak-cryptography",
            title="References to weak cryptographic primitives",
            severity=Severity.MEDIUM,
            category="Cryptography",
            description=(
                "Strings associated with broken or weak cryptography were found in the "
                "bytecode. DES/3DES/RC4 are broken ciphers, ECB mode leaks plaintext "
                "structure, and MD5/SHA-1 are unsuitable for integrity or password "
                "hashing. (These are string matches — confirm the actual usage.)"
            ),
            evidence=hits,
            remediation=(
                "Use AES-256 in GCM (authenticated) mode for encryption, SHA-256+ for "
                "hashing, and Argon2/scrypt/bcrypt/PBKDF2 for passwords. Prefer the "
                "Jetpack Security / Tink libraries over hand-rolled crypto."
            ),
            references=[
                "https://developer.android.com/privacy-and-security/cryptography",
                "OWASP MASVS-CRYPTO-1",
            ],
            cwe="CWE-327", masvs="MASVS-CRYPTO-1",
        )]
    return []


def rule_insecure_tls(ctx: RuleContext) -> List[Finding]:
    # Only strong, unambiguous signals — a bare setHostnameVerifier reference is
    # used by many legitimate libraries and is too noisy to flag.
    hits = []
    for token, label in (
        ("ALLOW_ALL_HOSTNAME_VERIFIER", "ALLOW_ALL_HOSTNAME_VERIFIER (disables hostname checks)"),
        ("NullHostnameVerifier", "NullHostnameVerifier"),
        ("AllowAllHostnameVerifier", "AllowAllHostnameVerifier"),
        ("trustAllCerts", "trust-all TrustManager"),
        ("TrustAllCerts", "trust-all TrustManager"),
        ("TrustAllX509", "trust-all X509TrustManager"),
    ):
        if ctx.dex_contains(token):
            hits.append(label)
    if hits:
        return [Finding(
            id="insecure-tls-validation",
            title="Possible disabled/weakened TLS certificate validation",
            severity=Severity.HIGH,
            category="Network Security",
            description=(
                "The bytecode references APIs commonly used to disable TLS certificate or "
                "hostname verification. If the app trusts all certificates it is trivially "
                "vulnerable to man-in-the-middle attacks."
            ),
            evidence=sorted(set(hits)),
            remediation=(
                "Never override TrustManager/HostnameVerifier to accept everything. Use the "
                "platform trust store, and pin certificates via Network Security Config or "
                "OkHttp CertificatePinner instead of custom validation."
            ),
            references=[
                "https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager",
                "OWASP MASVS-NETWORK-2",
            ],
            cwe="CWE-295", masvs="MASVS-NETWORK-2",
        )]
    return []


def rule_webview_debug(ctx: RuleContext) -> List[Finding]:
    if ctx.dex_contains("setWebContentsDebuggingEnabled"):
        return [Finding(
            id="webview-debugging",
            title="WebView remote debugging may be enabled",
            severity=Severity.LOW,
            category="Configuration",
            description=(
                "A call to setWebContentsDebuggingEnabled was found. If enabled in "
                "production, any app/user with ADB can inspect and manipulate WebView "
                "contents via Chrome DevTools."
            ),
            evidence=["setWebContentsDebuggingEnabled referenced in bytecode"],
            remediation="Guard setWebContentsDebuggingEnabled(true) behind BuildConfig.DEBUG so it is never enabled in release builds.",
            references=["https://developer.android.com/reference/android/webkit/WebView#setWebContentsDebuggingEnabled(boolean)"],
            cwe="CWE-489", masvs="MASVS-RESILIENCE-1",
        )]
    return []


def rule_js_interface(ctx: RuleContext) -> List[Finding]:
    if ctx.dex_contains("addJavascriptInterface"):
        return [Finding(
            id="webview-js-interface",
            title="WebView addJavascriptInterface in use",
            severity=Severity.LOW,
            category="Code & Secrets",
            description=(
                "addJavascriptInterface exposes native methods to JavaScript running in a "
                "WebView. If the WebView loads untrusted or http content, malicious JS can "
                "reach native code (RCE on API < 17; still risky above)."
            ),
            evidence=["addJavascriptInterface referenced in bytecode"],
            remediation=(
                "Only bridge to trusted, HTTPS content you control. Annotate exposed "
                "methods with @JavascriptInterface, minimise the exposed surface, and never "
                "attach the bridge to a WebView that can navigate to attacker content."
            ),
            references=["https://developer.android.com/privacy-and-security/risks/webview-unsafe-use"],
            cwe="CWE-749", masvs="MASVS-PLATFORM-2",
        )]
    return []


# ---------------------------------------------------------------------------
# Packaging rules
# ---------------------------------------------------------------------------

def rule_debug_artifacts(ctx: RuleContext) -> List[Finding]:
    suspicious = [
        n for n in ctx.file_names
        if n.endswith((".java", ".kt", ".map", ".bak"))
        or "/test/" in n.lower()
        or n.lower().endswith("proguardmapping.txt")
    ]
    if suspicious:
        return [Finding(
            id="debug-artifacts",
            title="Debug / source artifacts shipped in the APK",
            severity=Severity.LOW,
            category="Packaging",
            description="Files that normally should not ship in a release build were found inside the APK; they may leak source structure or aid reverse engineering.",
            evidence=suspicious[:20],
            remediation="Exclude source, mapping and test files from the packaged APK. Verify your build's packagingOptions and that R8/ProGuard mapping files are kept out of the archive.",
            references=["https://developer.android.com/build/shrink-code"],
            masvs="MASVS-RESILIENCE-4",
        )]
    return []


def rule_no_native_no_obfuscation(ctx: RuleContext) -> List[Finding]:
    # Heuristic: presence of many long, human-readable class names suggests no
    # obfuscation. We keep this INFO to avoid over-claiming.
    return []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_RULES: List[Callable[[RuleContext], List[Finding]]] = [
    rule_debuggable,
    rule_allow_backup,
    rule_cleartext_traffic,
    rule_network_security_config,
    rule_exported_components,
    rule_implicit_export_target31,
    rule_high_risk_permissions,
    rule_dangerous_permissions,
    rule_custom_permission_weak,
    rule_min_sdk,
    rule_target_sdk,
    rule_unsigned,
    rule_v1_only,
    rule_cert_quality,
    rule_hardcoded_secrets,
    rule_cleartext_urls,
    rule_weak_crypto,
    rule_insecure_tls,
    rule_webview_debug,
    rule_js_interface,
    rule_debug_artifacts,
]


def run_all(ctx: RuleContext) -> List[Finding]:
    findings: List[Finding] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(ctx))
        except Exception as exc:  # a broken rule must never abort the scan
            findings.append(Finding(
                id="rule-error",
                title=f"Internal rule error in {rule.__name__}",
                severity=Severity.INFO,
                category="Engine",
                description=f"A rule raised an exception and was skipped: {exc!r}",
            ))
    return findings
