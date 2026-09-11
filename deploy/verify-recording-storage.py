"""Read a disposable guacd marker using the API process identity and mount."""
import os
import re
import sys
from pathlib import Path


MARKER = b"operation-portal-recording-readiness\n"


def verify_recording_storage(name: str, root: Path) -> None:
    if not re.fullmatch(r"\.operation-portal-storage\.[A-Za-z0-9]{12}", name):
        raise ValueError("Invalid recording readiness marker name")
    # The real watcher enumerates the mount, so opening one known filename alone
    # is insufficient to prove its directory permission is usable.
    with os.scandir(root) as entries:
        next(entries, None)
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("Recording readiness marker is missing or invalid")
    with path.open("rb") as source:
        if source.read(len(MARKER) + 1) != MARKER:
            raise ValueError("Recording readiness marker does not match")


def main() -> int:
    try:
        if os.geteuid() == 0 or len(sys.argv) != 2:
            raise ValueError("Recording readiness must run as the API service user")
        verify_recording_storage(sys.argv[1], Path(os.environ.get("RECORDING_ROOT", "/recordings")))
    except (OSError, ValueError):
        print("Recording storage check failed: the API service user cannot read the marker written by guacd. Check RECORDING_DIR, RECORDING_GID and the mounts of both services.", file=sys.stderr)
        return 1
    print("Recording storage verified: guacd can write and the API service user can read the same mount.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
