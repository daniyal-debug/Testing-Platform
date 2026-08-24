"""APK Sentinel — a static analysis & security testing platform for Android APKs.

The engine is dependency-free (pure Python standard library). It treats an APK
as a ZIP archive, decodes Android's binary ``AndroidManifest.xml`` format,
scans DEX bytecode string pools, inspects signing certificates and runs a
catalog of security / quality rules. Findings are rendered into an actionable
remediation guide (HTML, Markdown and JSON).
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
