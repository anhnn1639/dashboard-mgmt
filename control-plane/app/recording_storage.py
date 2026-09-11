"""Strict enumeration for removal; playback's missing-file fallback is unsuitable."""
import stat
import uuid
from pathlib import Path


def deletion_files(recording_root: str, session_id: str) -> list[Path]:
    try:
        if str(uuid.UUID(session_id)) != session_id.lower():
            raise ValueError
        root = Path(recording_root).resolve(strict=True)
        if not root.is_dir():
            raise OSError("Recording storage is not a directory")
        candidates = list(root.iterdir())
    except (ValueError, RuntimeError) as error:
        raise OSError("Invalid recording storage or session") from error
    result = []
    for candidate in candidates:
        name = candidate.name
        if not (name == session_id or (name.startswith(session_id) and
                len(name) > len(session_id) and name[len(session_id)] in "-._")):
            continue
        if not stat.S_ISREG(candidate.lstat().st_mode):
            raise OSError("Recording contains a link or unsupported file")
        result.append(candidate)
    return sorted(result)


def delete_recording(recording_root: str, session_id: str, deleted: list[str] | None = None) -> list[str]:
    files = deletion_files(recording_root, session_id)
    removed = deleted if deleted is not None else []
    for path in files:
        # Unlink the original child, never a symlink's resolved target.
        path.unlink()
        removed.append(path.name)
    if deletion_files(recording_root, session_id):
        raise OSError("Recording files changed during deletion")
    return [path.name for path in files]
