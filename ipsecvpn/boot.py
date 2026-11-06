"""Entry point for the project-owned early guard and post-network service."""

import sys

from .secureio import Stop
from .transaction import boot

if __name__ == "__main__":
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {"guard", "restore"}:
            raise Stop("Invalid boot phase.")
        boot(sys.argv[1])
    except Stop as exc:
        sys.exit(f"STOP: {exc}")
    except (OSError, ValueError, KeyError):
        sys.exit("STOP: project boot state could not be verified.")
