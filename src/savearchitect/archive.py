from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
import json
import zipfile


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    size: int
    compressed_size: int | None
    crc32: str | None
    is_directory: bool


@dataclass(frozen=True)
class ArchiveInventory:
    archive_path: str
    archive_type: str
    members: tuple[ArchiveMember, ...]

    @property
    def total_uncompressed_size(self) -> int:
        return sum(member.size for member in self.members if not member.is_directory)

    def to_dict(self) -> dict[str, Any]:
        return {
            "archive_path": self.archive_path,
            "archive_type": self.archive_type,
            "total_uncompressed_size": self.total_uncompressed_size,
            "members": [asdict(member) for member in self.members],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)


def inventory_archive(path: str | Path) -> ArchiveInventory:
    archive_path = Path(path)
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)

    if zipfile.is_zipfile(archive_path):
        return _inventory_zip(archive_path)

    if _looks_like_rar(archive_path):
        return _inventory_rar(archive_path)

    raise ValueError(f"Unsupported or unrecognized archive: {archive_path}")


def _inventory_zip(path: Path) -> ArchiveInventory:
    members: list[ArchiveMember] = []
    with zipfile.ZipFile(path, "r") as archive:
        for info in archive.infolist():
            members.append(
                ArchiveMember(
                    name=info.filename,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                    crc32=f"{info.CRC:08x}" if not info.is_dir() else None,
                    is_directory=info.is_dir(),
                )
            )
    return ArchiveInventory(str(path), "zip", tuple(members))


def _inventory_rar(path: Path) -> ArchiveInventory:
    try:
        import rarfile  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError(
            "RAR inventory requires the optional 'rar' dependency: "
            "pip install 'savearchitect[rar]'"
        ) from exc

    members: list[ArchiveMember] = []
    with rarfile.RarFile(path) as archive:
        for info in archive.infolist():
            is_directory = info.isdir()
            members.append(
                ArchiveMember(
                    name=info.filename,
                    size=info.file_size,
                    compressed_size=getattr(info, "compress_size", None),
                    crc32=(
                        f"{info.CRC & 0xFFFFFFFF:08x}"
                        if not is_directory and getattr(info, "CRC", None) is not None
                        else None
                    ),
                    is_directory=is_directory,
                )
            )
    return ArchiveInventory(str(path), "rar", tuple(members))


def _looks_like_rar(path: Path) -> bool:
    with path.open("rb") as handle:
        header = handle.read(8)
    return header.startswith(b"Rar!\x1a\x07")
