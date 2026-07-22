from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import md5, sha256
from math import log2
from pathlib import Path
from typing import Iterable
import json
import mimetypes
import zlib


MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
    (b"Rar!\x1a\x07\x00", "rar4"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"SQLite format 3\x00", "sqlite3"),
    (b"GVAS", "unreal-savegame"),
    (b"{", "json-object"),
    (b"[", "json-array"),
)

TEXT_EXTENSIONS = {
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".ini",
    ".cfg",
    ".txt",
    ".csv",
}


@dataclass(frozen=True)
class FileFingerprint:
    path: str
    name: str
    extension: str
    size: int
    sha256: str
    md5: str
    crc32: str
    entropy: float
    null_ratio: float
    printable_ratio: float
    detected_format: str
    mime_type: str | None
    likely_text: bool
    likely_compressed_or_encrypted: bool


@dataclass(frozen=True)
class AnalysisReport:
    schema_version: int
    files: tuple[FileFingerprint, ...]
    total_size: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "total_size": self.total_size,
            "files": [asdict(item) for item in self.files],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


class FileAnalyzer:
    """Generate reproducible, metadata-only fingerprints for save research."""

    def __init__(self, *, sample_limit: int = 1024 * 1024) -> None:
        if sample_limit <= 0:
            raise ValueError("sample_limit must be positive")
        self.sample_limit = sample_limit

    def analyze_path(self, path: str | Path) -> AnalysisReport:
        root = Path(path)
        if not root.exists():
            raise FileNotFoundError(root)

        paths = self._collect_files(root)
        fingerprints = tuple(self.analyze_file(item) for item in paths)
        return AnalysisReport(
            schema_version=1,
            files=fingerprints,
            total_size=sum(item.size for item in fingerprints),
        )

    def analyze_file(self, path: str | Path) -> FileFingerprint:
        file_path = Path(path)
        if not file_path.is_file():
            raise ValueError(f"Not a file: {file_path}")

        sha = sha256()
        legacy_md5 = md5(usedforsecurity=False)
        crc = 0
        size = 0
        sample = bytearray()

        with file_path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                sha.update(chunk)
                legacy_md5.update(chunk)
                crc = zlib.crc32(chunk, crc)
                if len(sample) < self.sample_limit:
                    remaining = self.sample_limit - len(sample)
                    sample.extend(chunk[:remaining])

        sample_bytes = bytes(sample)
        entropy = shannon_entropy(sample_bytes)
        printable_ratio = ratio_printable(sample_bytes)
        null_ratio = sample_bytes.count(0) / len(sample_bytes) if sample_bytes else 0.0
        detected_format = detect_format(sample_bytes, file_path.suffix)
        likely_text = is_likely_text(
            sample_bytes,
            extension=file_path.suffix,
            printable_ratio=printable_ratio,
            null_ratio=null_ratio,
        )

        return FileFingerprint(
            path=str(file_path),
            name=file_path.name,
            extension=file_path.suffix.lower(),
            size=size,
            sha256=sha.hexdigest(),
            md5=legacy_md5.hexdigest(),
            crc32=f"{crc & 0xFFFFFFFF:08x}",
            entropy=round(entropy, 6),
            null_ratio=round(null_ratio, 6),
            printable_ratio=round(printable_ratio, 6),
            detected_format=detected_format,
            mime_type=mimetypes.guess_type(file_path.name)[0],
            likely_text=likely_text,
            likely_compressed_or_encrypted=(entropy >= 7.6 and not likely_text),
        )

    @staticmethod
    def _collect_files(path: Path) -> list[Path]:
        if path.is_file():
            return [path]
        return sorted(item for item in path.rglob("*") if item.is_file())


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * log2(count / length) for count in counts if count)


def ratio_printable(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(
        1 for value in data if value in (9, 10, 13) or 32 <= value <= 126
    )
    return printable / len(data)


def detect_format(data: bytes, extension: str = "") -> str:
    stripped = data.lstrip()
    for signature, name in MAGIC_SIGNATURES:
        candidate = stripped if signature in (b"{", b"[") else data
        if candidate.startswith(signature):
            return name

    extension = extension.lower()
    if extension in {".yaml", ".yml"}:
        return "yaml"
    if extension == ".xml":
        return "xml"
    if extension in {".ini", ".cfg"}:
        return "configuration-text"
    return "unknown"


def is_likely_text(
    data: bytes,
    *,
    extension: str = "",
    printable_ratio: float | None = None,
    null_ratio: float | None = None,
) -> bool:
    if not data:
        return extension.lower() in TEXT_EXTENSIONS
    printable_ratio = ratio_printable(data) if printable_ratio is None else printable_ratio
    null_ratio = data.count(0) / len(data) if null_ratio is None else null_ratio
    if null_ratio > 0.01:
        return False
    return extension.lower() in TEXT_EXTENSIONS or printable_ratio >= 0.92


def analyze_many(paths: Iterable[str | Path]) -> AnalysisReport:
    analyzer = FileAnalyzer()
    files: list[FileFingerprint] = []
    for path in paths:
        files.extend(analyzer.analyze_path(path).files)
    files.sort(key=lambda item: item.path)
    return AnalysisReport(
        schema_version=1,
        files=tuple(files),
        total_size=sum(item.size for item in files),
    )
