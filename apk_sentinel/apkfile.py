"""Thin wrapper around an APK (which is just a ZIP archive).

Provides hashing, a file inventory and convenient access to the entries the
rest of the engine cares about (manifest, DEX files, native libraries).
"""
from __future__ import annotations

import hashlib
import zipfile
from typing import Dict, List, Optional

from .models import FileEntry


class APKError(Exception):
    pass


class APKFile:
    def __init__(self, path: str):
        self.path = path
        try:
            self._zip = zipfile.ZipFile(path, "r")
        except zipfile.BadZipFile as exc:
            raise APKError(f"not a valid ZIP/APK archive: {exc}") from exc
        except FileNotFoundError as exc:
            raise APKError(f"file not found: {path}") from exc

        self._names = set(self._zip.namelist())
        if "AndroidManifest.xml" not in self._names:
            raise APKError(
                "archive has no AndroidManifest.xml — this does not look like an APK"
            )

    # -- lifecycle -------------------------------------------------------
    def close(self) -> None:
        try:
            self._zip.close()
        except Exception:
            pass

    def __enter__(self) -> "APKFile":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- hashing / size --------------------------------------------------
    def hashes(self) -> Dict[str, str]:
        sha = hashlib.sha256()
        md5 = hashlib.md5()
        size = 0
        with open(self.path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
                md5.update(chunk)
                size += len(chunk)
        return {"sha256": sha.hexdigest(), "md5": md5.hexdigest(), "size": str(size)}

    # -- entries ---------------------------------------------------------
    def read(self, name: str) -> bytes:
        return self._zip.read(name)

    def has(self, name: str) -> bool:
        return name in self._names

    def names(self) -> List[str]:
        return sorted(self._names)

    def manifest_bytes(self) -> bytes:
        return self._zip.read("AndroidManifest.xml")

    def dex_names(self) -> List[str]:
        return sorted(
            n for n in self._names
            if n.endswith(".dex") and "/" not in n
        )

    def native_libs(self) -> List[str]:
        return sorted(n for n in self._names if n.startswith("lib/") and n.endswith(".so"))

    def native_abis(self) -> List[str]:
        abis = set()
        for n in self.native_libs():
            parts = n.split("/")
            if len(parts) >= 2:
                abis.add(parts[1])
        return sorted(abis)

    def inventory(self) -> List[FileEntry]:
        out: List[FileEntry] = []
        for info in self._zip.infolist():
            if info.is_dir():
                continue
            out.append(FileEntry(info.filename, info.file_size, info.compress_size))
        return out

    def total_uncompressed(self) -> int:
        return sum(i.file_size for i in self._zip.infolist() if not i.is_dir())

    def signature_files(self) -> List[str]:
        return sorted(
            n for n in self._names
            if n.upper().startswith("META-INF/")
            and n.upper().rsplit(".", 1)[-1] in {"RSA", "DSA", "EC"}
        )

    def raw_bytes(self) -> bytes:
        with open(self.path, "rb") as fh:
            return fh.read()
