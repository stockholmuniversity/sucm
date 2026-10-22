"""Human-readable build/version info, computed once at startup."""

import re
import subprocess
from importlib import metadata
from pathlib import Path

_DESCRIBE_RE = re.compile(
    r"^(?P<tag>.+?)(?:-(?P<ahead>\d+)-g(?P<commit>[0-9a-f]+))?(?P<dirty>-dirty)?$"
)


def _git_describe():
    try:
        out = subprocess.run(
            ["git", "describe", "--tags", "--long", "--always", "--dirty"],
            cwd=Path(__file__).resolve().parent,
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _package_version():
    try:
        return metadata.version("sucm")
    except metadata.PackageNotFoundError:
        return "unknown"


def get_version_info():
    """Return a dict with an explicit, display-ready description of the version."""
    # --long always yields <tag>-<n>-g<hash>; a bare hash means no tag exists.
    describe = _git_describe()
    match = _DESCRIBE_RE.match(describe) if describe else None
    if not match or not match.group("commit"):
        return {"label": f"v{_package_version()}", "detail": ""}

    tag, ahead, commit = match["tag"], int(match["ahead"]), match["commit"]
    if ahead == 0:
        detail = f"release tag {tag}, commit {commit}"
    else:
        plural = "commit" if ahead == 1 else "commits"
        detail = f"{ahead} {plural} after tag {tag}, commit {commit}"
    if match.group("dirty"):
        detail += ", uncommitted changes"
    return {"label": f"v{tag}" + ("" if ahead == 0 else "+"), "detail": detail}
