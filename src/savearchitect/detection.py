from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass(frozen=True)
class Evidence:
    kind: str
    description: str
    weight: float
    offset: int | None = None


@dataclass(frozen=True)
class DetectionFinding:
    technology: str
    category: str
    confidence: float
    evidence: tuple[Evidence, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "technology": self.technology,
            "category": self.category,
            "confidence": round(self.confidence, 4),
            "evidence": [asdict(item) for item in self.evidence],
        }


Detector = Callable[[bytes, Path], DetectionFinding | None]


class DetectorRegistry:
    def __init__(self, detectors: Iterable[Detector] | None = None) -> None:
        self._detectors: list[Detector] = list(detectors or default_detectors())

    def register(self, detector: Detector) -> None:
        self._detectors.append(detector)

    def detect(self, data: bytes, path: str | Path) -> tuple[DetectionFinding, ...]:
        file_path = Path(path)
        findings = [
            finding
            for detector in self._detectors
            if (finding := detector(data, file_path)) is not None
        ]
        findings.sort(key=lambda item: item.confidence, reverse=True)
        return tuple(findings)


def default_detectors() -> tuple[Detector, ...]:
    return (
        detect_unreal_savegame,
        detect_sqlite,
        detect_json,
        detect_xml,
        detect_yaml,
        detect_zip,
        detect_rar,
        detect_gzip,
    )


def detect_unreal_savegame(data: bytes, path: Path) -> DetectionFinding | None:
    evidence: list[Evidence] = []
    if data.startswith(b"GVAS"):
        evidence.append(Evidence("magic", "File begins with Unreal SaveGame GVAS signature.", 0.92, 0))
    if b"StrProperty" in data or b"IntProperty" in data or b"ArrayProperty" in data:
        evidence.append(Evidence("serialization", "Unreal property type names are present.", 0.06))
    if not evidence:
        return None
    return _finding("Unreal Engine SaveGame", "game-save-format", evidence)


def detect_sqlite(data: bytes, path: Path) -> DetectionFinding | None:
    if not data.startswith(b"SQLite format 3\x00"):
        return None
    return _finding(
        "SQLite 3",
        "database",
        [Evidence("magic", "SQLite 3 database header is present.", 0.99, 0)],
    )


def detect_json(data: bytes, path: Path) -> DetectionFinding | None:
    stripped = data.lstrip()
    if not stripped.startswith((b"{", b"[")):
        return None
    evidence = [Evidence("syntax", "First non-whitespace byte is a JSON container token.", 0.7)]
    if path.suffix.lower() == ".json":
        evidence.append(Evidence("extension", "File extension is .json.", 0.2))
    try:
        import json

        json.loads(data.decode("utf-8"))
        evidence.append(Evidence("parse", "Content parses successfully as UTF-8 JSON.", 0.1))
    except (UnicodeDecodeError, ValueError):
        pass
    return _finding("JSON", "structured-text", evidence)


def detect_xml(data: bytes, path: Path) -> DetectionFinding | None:
    stripped = data.lstrip()
    if not (stripped.startswith(b"<?xml") or stripped.startswith(b"<")):
        return None
    evidence = [Evidence("syntax", "Content begins with an XML-style opening token.", 0.65)]
    if path.suffix.lower() == ".xml":
        evidence.append(Evidence("extension", "File extension is .xml.", 0.25))
    return _finding("XML", "structured-text", evidence)


def detect_yaml(data: bytes, path: Path) -> DetectionFinding | None:
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return None
    return _finding(
        "YAML",
        "structured-text",
        [Evidence("extension", "File extension indicates YAML.", 0.65)],
    )


def detect_zip(data: bytes, path: Path) -> DetectionFinding | None:
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return None
    return _finding("ZIP", "archive", [Evidence("magic", "ZIP signature is present.", 0.99, 0)])


def detect_rar(data: bytes, path: Path) -> DetectionFinding | None:
    if not data.startswith(b"Rar!\x1a\x07"):
        return None
    version = "RAR 5" if data.startswith(b"Rar!\x1a\x07\x01\x00") else "RAR 4"
    return _finding(version, "archive", [Evidence("magic", f"{version} signature is present.", 0.99, 0)])


def detect_gzip(data: bytes, path: Path) -> DetectionFinding | None:
    if not data.startswith(b"\x1f\x8b"):
        return None
    return _finding("GZip", "compression", [Evidence("magic", "GZip signature is present.", 0.99, 0)])


def _finding(technology: str, category: str, evidence: list[Evidence]) -> DetectionFinding:
    confidence = min(1.0, sum(max(0.0, item.weight) for item in evidence))
    return DetectionFinding(
        technology=technology,
        category=category,
        confidence=confidence,
        evidence=tuple(evidence),
    )
