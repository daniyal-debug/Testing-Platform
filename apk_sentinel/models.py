"""Core data models shared across the analysis engine.

Everything here is a plain dataclass so results serialise cleanly to JSON and
are trivial to unit test. Nothing in this module imports the rest of the
package, keeping it a dependency-free leaf.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Ordered severity levels. The string value is what shows up in reports."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def rank(self) -> int:
        """Lower rank == more severe. Used for sorting."""
        return list(Severity).index(self)


@dataclass
class Finding:
    """A single issue discovered by a rule.

    ``id`` is a stable slug (e.g. ``android-debuggable``) that also keys into the
    remediation knowledge base for the long-form fix guide.
    """

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    masvs: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Component:
    """An Android component declared in the manifest."""

    kind: str  # activity | activity-alias | service | receiver | provider
    name: str
    exported: Optional[bool] = None      # None => not explicitly set
    permission: Optional[str] = None
    has_intent_filter: bool = False
    intent_actions: List[str] = field(default_factory=list)
    intent_categories: List[str] = field(default_factory=list)
    # provider-only
    authorities: Optional[str] = None
    grant_uri_permissions: Optional[bool] = None
    # extra attributes captured for reference
    extra: Dict[str, str] = field(default_factory=dict)

    @property
    def effective_exported(self) -> bool:
        """Resolve the exported state the way the Android runtime would.

        If ``exported`` is explicitly set, honour it. Otherwise an
        activity/service/receiver is exported implicitly when it declares at
        least one intent-filter.

        Note: ``<provider>`` uses a different default (it exports implicitly when
        ``targetSdk < 17``, regardless of intent-filters). That target-aware
        determination is handled in the export rule, which has the SDK context;
        this property models the common activity/service/receiver case.
        """
        if self.exported is not None:
            return self.exported
        return self.has_intent_filter

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["effective_exported"] = self.effective_exported
        return d


@dataclass
class ManifestInfo:
    """Structured view of a decoded AndroidManifest.xml."""

    package: Optional[str] = None
    version_code: Optional[int] = None
    version_name: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    max_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None

    debuggable: Optional[bool] = None
    allow_backup: Optional[bool] = None
    uses_cleartext_traffic: Optional[bool] = None
    network_security_config: Optional[str] = None
    has_code: Optional[bool] = None
    app_label: Optional[str] = None

    permissions: List[str] = field(default_factory=list)
    custom_permissions: List[Dict[str, Any]] = field(default_factory=list)
    features: List[str] = field(default_factory=list)

    activities: List[Component] = field(default_factory=list)
    services: List[Component] = field(default_factory=list)
    receivers: List[Component] = field(default_factory=list)
    providers: List[Component] = field(default_factory=list)

    # Raw parse warnings (e.g. attributes that could not be resolved).
    warnings: List[str] = field(default_factory=list)

    @property
    def all_components(self) -> List[Component]:
        return self.activities + self.services + self.receivers + self.providers

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        for key in ("activities", "services", "receivers", "providers"):
            d[key] = [c.to_dict() for c in getattr(self, key)]
        return d


@dataclass
class CertificateInfo:
    """Signing information for the APK."""

    v1_signed: bool = False           # JAR signature (META-INF/*.RSA|DSA|EC)
    v2_signed: bool = False           # APK Signature Scheme v2/v3 block present
    v3_signed: bool = False
    signers: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class FileEntry:
    name: str
    size: int
    compressed_size: int

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class SecretMatch:
    """A potential hard-coded secret / sensitive string found in the DEX/resources."""

    kind: str
    value_preview: str
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class AnalysisResult:
    """The complete output of analysing one APK."""

    file_name: str
    file_size: int
    sha256: str
    md5: str

    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    findings: List[Finding] = field(default_factory=list)
    files: List[FileEntry] = field(default_factory=list)
    secrets: List[SecretMatch] = field(default_factory=list)
    dex_count: int = 0
    native_libs: List[str] = field(default_factory=list)
    total_uncompressed: int = 0
    engine_version: str = ""
    analyzed_at: str = ""

    # -- derived metrics -------------------------------------------------
    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def risk_score(self) -> int:
        """0-100 risk score derived from weighted finding counts (higher = worse).

        Linear-with-cap: interpretable and monotonic. A single critical lands at
        45, a single high at 22, so the numeric score and the letter grade tell a
        consistent story.
        """
        counts = self.severity_counts
        raw = (
            45 * counts["critical"]
            + 22 * counts["high"]
            + 9 * counts["medium"]
            + 3 * counts["low"]
        )
        return int(min(100, raw))

    @property
    def grade(self) -> str:
        counts = self.severity_counts
        if counts["critical"] > 0:
            return "F"
        if counts["high"] > 0:
            return "D"
        score = self.risk_score
        if score >= 40:
            return "C"
        if score >= 15:
            return "B"
        if score > 0:
            return "A"
        return "A+"

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.id))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "md5": self.md5,
            "engine_version": self.engine_version,
            "analyzed_at": self.analyzed_at,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "severity_counts": self.severity_counts,
            "manifest": self.manifest.to_dict(),
            "certificate": self.certificate.to_dict(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "secrets": [s.to_dict() for s in self.secrets],
            "dex_count": self.dex_count,
            "native_libs": self.native_libs,
            "total_uncompressed": self.total_uncompressed,
            "files": [f.to_dict() for f in self.files],
        }
