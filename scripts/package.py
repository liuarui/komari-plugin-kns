#!/usr/bin/env python3
"""Build and verify the Komari KNS plugin ZIP and release checksums."""

import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "onebox-bridge.zip"
RUNTIME_FILES = [
    "LICENSE",
    "komari-plugin.json",
    "script.js",
    "pages/admin.html",
]
MODULE_DIR = ROOT / "kns"
DEPENDENCY_LOCK = ROOT / "requirements.lock"


def runtime_files() -> list[str]:
    files = list(RUNTIME_FILES)
    files.extend(path.relative_to(ROOT).as_posix() for path in sorted(MODULE_DIR.rglob("*.js")))
    return files


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_dependency_lock() -> dict:
    try:
        lock = json.loads(DEPENDENCY_LOCK.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Dependency lock is missing or invalid: {error}") from error
    if lock.get("lockVersion") != 1:
        raise SystemExit("Unsupported dependency lock version.")
    for group in ("runtime", "packaging", "tests"):
        section = lock.get(group)
        if not isinstance(section, dict) or not isinstance(section.get("dependencies"), list):
            raise SystemExit(f"Dependency lock section is invalid: {group}")
    return lock


def main() -> None:
    dependency_lock = load_dependency_lock()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    files = runtime_files()
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED) as archive:
        for relative in files:
            path = ROOT / relative
            if not path.is_file():
                raise SystemExit(f"Missing required plugin file: {relative}")
            archive.write(path, relative)
    with ZipFile(OUTPUT) as archive:
        names = set(archive.namelist())
        if "komari-plugin.json" not in names or "script.js" not in names or "LICENSE" not in names:
            raise SystemExit("Plugin ZIP is missing its manifest, entry script, or license.")
        if archive.testzip() is not None:
            raise SystemExit("Plugin ZIP failed its CRC check.")
    package_hash = sha256_file(OUTPUT)
    (OUTPUT.with_suffix(OUTPUT.suffix + ".sha256")).write_text(f"{package_hash}  {OUTPUT.name}\n", encoding="utf-8")
    (ROOT / "docs").mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / "komari-plugin.json").read_text(encoding="utf-8"))
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "Komari KNS", "version": manifest["version"], "licenses": [{"expression": "AGPL-3.0-only"}]}},
        "components": [],
        "dependencies": [],
        "properties": [
            {"name": "runtime.dependencies", "value": json.dumps(dependency_lock["runtime"]["dependencies"])},
            {"name": "dependency-lock.sha256", "value": sha256_file(DEPENDENCY_LOCK)},
            {"name": "packaging.dependencies", "value": json.dumps(dependency_lock["packaging"]["dependencies"])},
        ],
    }
    (ROOT / "docs" / "sbom.cdx.json").write_text(json.dumps(sbom, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT)
    print(f"SHA256 {package_hash}")


if __name__ == "__main__":
    main()
