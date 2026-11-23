#!/usr/bin/env python3
"""Build PEP 427 binary wheels wrapping pre-compiled sixi-scanner Go binaries.

Zero third-party Python build dependencies: uses only Python's standard library
to produce reproducible platform-tagged wheels ready for `pip install sixi-scanner`
and `uvx sixi-scanner` across Linux (x86_64/arm64), macOS (x86_64/arm64), and
Windows (x86_64).

Usage:
    python3 packaging/pypi/build_wheels.py \
        --version 1.1.0 \
        --dist-dir dist \
        --out-dir dist/wheels
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import stat
import sys
import zipfile
from pathlib import Path

PLATFORMS: list[tuple[str, str, str, str]] = [
    # (goos, goarch, binary_ext, wheel_platform_tag)
    ("linux", "amd64", "", "manylinux_2_17_x86_64.manylinux2014_x86_64"),
    ("linux", "arm64", "", "manylinux_2_17_aarch64.manylinux2014_aarch64"),
    ("darwin", "amd64", "", "macosx_11_0_x86_64"),
    ("darwin", "arm64", "", "macosx_11_0_arm64"),
    ("windows", "amd64", ".exe", "win_amd64"),
]

INIT_PY = '''"""Python distribution wrapper for the zero-dependency sixi-scanner Go CLI."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

__version__ = "{version}"


def binary_path() -> Path:
    name = "sixi-scanner.exe" if os.name == "nt" else "sixi-scanner"
    path = Path(__file__).resolve().parent / "bin" / name
    if not path.is_file():
        raise FileNotFoundError(f"Bundled sixi-scanner binary not found at {{path}}")
    return path


def main() -> int:
    exe = binary_path()
    argv = [str(exe), *sys.argv[1:]]
    if os.name != "nt":
        os.execv(str(exe), argv)
    return subprocess.call(argv)
'''

MAIN_PY = '''"""Allow `python -m sixi_scanner` invocation."""

import sys
from sixi_scanner import main

if __name__ == "__main__":
    raise SystemExit(main())
'''


def _record_hash(data: bytes) -> tuple[str, int]:
    digest = hashlib.sha256(data).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={b64}", len(data)


def _write_zip_entry(
    zf: zipfile.ZipFile,
    arcname: str,
    data: bytes,
    executable: bool = False,
) -> tuple[str, str, int]:
    info = zipfile.ZipInfo(arcname, date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if executable else 0o644
    info.external_attr = ((stat.S_IFREG | mode) & 0xFFFF) << 16
    zf.writestr(info, data)
    h, size = _record_hash(data)
    return arcname, h, size


def build_wheel(
    version: str,
    bin_path: Path,
    bin_ext: str,
    platform_tag: str,
    readme_text: str,
    license_text: str,
    out_dir: Path,
) -> Path:
    clean_ver = version.lstrip("v")
    dist_info = f"sixi_scanner-{clean_ver}.dist-info"
    wheel_name = f"sixi_scanner-{clean_ver}-py3-none-{platform_tag}.whl"
    wheel_path = out_dir / wheel_name

    metadata = "\n".join([
        "Metadata-Version: 2.1",
        "Name: sixi-scanner",
        f"Version: {clean_ver}",
        "Summary: Zero-dependency red-team scanner and MCP/A2A surface inspector for LLM agents",
        "Home-page: https://github.com/radeksixi/sixi-scanner",
        "Author: Radek (Sixi)",
        "License: Apache-2.0",
        "Project-URL: Homepage, https://github.com/radeksixi/sixi-scanner",
        "Project-URL: Repository, https://github.com/radeksixi/sixi-scanner",
        "Project-URL: Issues, https://github.com/radeksixi/sixi-scanner/issues",
        "Keywords: llm,ai-security,red-teaming,mcp,a2a,agent-security,owasp,prompt-injection",
        "Classifier: Development Status :: 5 - Production/Stable",
        "Classifier: Environment :: Console",
        "Classifier: Intended Audience :: Developers",
        "Classifier: Intended Audience :: Information Technology",
        "Classifier: License :: OSI Approved :: Apache Software License",
        "Classifier: Programming Language :: Go",
        "Classifier: Programming Language :: Python :: 3",
        "Classifier: Topic :: Security",
        "Requires-Python: >=3.9",
        "Description-Content-Type: text/markdown",
        "",
        readme_text,
    ]).encode("utf-8")

    wheel_meta = "\n".join([
        "Wheel-Version: 1.0",
        "Generator: sixi-scanner-build-wheels",
        "Root-Is-Purelib: false",
        f"Tag: py3-none-{platform_tag}",
        "",
    ]).encode("utf-8")

    entry_points = "[console_scripts]\nsixi-scanner = sixi_scanner:main\n".encode("utf-8")

    records: list[tuple[str, str, int]] = []
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        records.append(_write_zip_entry(
            zf, "sixi_scanner/__init__.py",
            INIT_PY.format(version=clean_ver).encode("utf-8"),
        ))
        records.append(_write_zip_entry(
            zf, "sixi_scanner/__main__.py",
            MAIN_PY.encode("utf-8"),
        ))
        records.append(_write_zip_entry(
            zf,
            f"sixi_scanner/bin/sixi-scanner{bin_ext}",
            bin_path.read_bytes(),
            executable=True,
        ))
        records.append(_write_zip_entry(zf, f"{dist_info}/METADATA", metadata))
        records.append(_write_zip_entry(zf, f"{dist_info}/WHEEL", wheel_meta))
        records.append(_write_zip_entry(zf, f"{dist_info}/entry_points.txt", entry_points))
        if license_text:
            records.append(_write_zip_entry(
                zf, f"{dist_info}/LICENSE", license_text.encode("utf-8"),
            ))

        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        for name, h, size in records:
            writer.writerow([name, h, size])
        record_name = f"{dist_info}/RECORD"
        writer.writerow([record_name, "", ""])
        _write_zip_entry(zf, record_name, buf.getvalue().encode("utf-8"))

    return wheel_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Build PEP 427 wheels wrapping sixi-scanner binaries.")
    ap.add_argument("--version", required=True, help="Release version, e.g. 1.1.0 or v1.1.0")
    ap.add_argument("--dist-dir", type=Path, default=Path("dist"), help="Directory containing cross-compiled binaries")
    ap.add_argument("--out-dir", type=Path, default=Path("dist/wheels"), help="Output directory for .whl files")
    ap.add_argument("--readme", type=Path, default=Path("packaging/pypi/README.md"))
    ap.add_argument("--license", type=Path, default=Path("LICENSE"))
    ap.add_argument("--single-binary", type=Path, default=None, help="Optional single binary path (requires --single-platform)")
    ap.add_argument("--single-platform", default="", help="Single GOOS/GOARCH pair, e.g. linux/arm64")
    args = ap.parse_args()

    tag = args.version if args.version.startswith("v") else f"v{args.version}"
    readme_text = args.readme.read_text(encoding="utf-8") if args.readme.is_file() else ""
    license_text = args.license.read_text(encoding="utf-8") if args.license.is_file() else ""
    args.out_dir.mkdir(parents=True, exist_ok=True)

    built: list[Path] = []
    if args.single_binary:
        if "/" not in args.single_platform:
            print("ERROR: --single-platform must be GOOS/GOARCH", file=sys.stderr)
            return 2
        goos, goarch = args.single_platform.split("/", 1)
        match = [p for p in PLATFORMS if p[0] == goos and p[1] == goarch]
        if not match:
            print(f"ERROR: unsupported platform {args.single_platform}", file=sys.stderr)
            return 2
        _, _, ext, plat_tag = match[0]
        built.append(build_wheel(args.version, args.single_binary, ext, plat_tag, readme_text, license_text, args.out_dir))
    else:
        for goos, goarch, ext, plat_tag in PLATFORMS:
            candidate = args.dist_dir / f"sixi-scanner-{tag}-{goos}-{goarch}{ext}"
            if not candidate.is_file():
                print(f"WARNING: missing binary {candidate}, skipping {goos}/{goarch}", file=sys.stderr)
                continue
            built.append(build_wheel(args.version, candidate, ext, plat_tag, readme_text, license_text, args.out_dir))

    if not built:
        print("ERROR: no wheels built", file=sys.stderr)
        return 1

    for whl in built:
        print(whl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
