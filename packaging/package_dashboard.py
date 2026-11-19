"""Archive a native Rust dashboard binary with its installation guide."""

import argparse
from pathlib import Path
import plistlib
import shutil
import tarfile
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile


SUPPORTED = (
    "windows-x64", "windows-arm64",
    "macos-x64", "macos-arm64",
    "linux-x64", "linux-arm64",
)


def portable_mode(member):
    is_executable = member.isfile() and Path(member.name).name == "security-dashboard"
    member.mode = 0o755 if member.isdir() or is_executable else 0o644
    return member


def make_archive(platform, binary, output):
    archive_name = f"security-dashboard-{platform}"
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="security-dashboard-package-") as temp:
        stage = Path(temp) / archive_name
        stage.mkdir()
        shutil.copyfile(Path(__file__).with_name("DOWNLOADS.md"), stage / "DOWNLOADS.md")
        if platform.startswith("macos-"):
            contents = stage / "Security Dashboard.app" / "Contents"
            executable = contents / "MacOS" / "security-dashboard"
            executable.parent.mkdir(parents=True)
            plist = {
                "CFBundleDisplayName": "Security Dashboard",
                "CFBundleName": "Security Dashboard",
                "CFBundleIdentifier": "org.ai-security-middleware.dashboard",
                "CFBundleExecutable": executable.name,
                "CFBundlePackageType": "APPL",
                "CFBundleInfoDictionaryVersion": "6.0",
                "LSMinimumSystemVersion": "12.0",
                "NSHighResolutionCapable": True,
            }
            with (contents / "Info.plist").open("wb") as file:
                plistlib.dump(plist, file)
        else:
            name = "security-dashboard.exe" if platform.startswith("windows-") else "security-dashboard"
            executable = stage / name
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)

        if platform.startswith("windows-"):
            archive = output / f"{archive_name}.zip"
            with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
                for file in stage.iterdir():
                    bundle.write(file, f"{archive_name}/{file.name}")
        else:
            archive = output / f"{archive_name}.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(stage, arcname=archive_name, filter=portable_mode)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("platform", choices=SUPPORTED)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not args.binary.is_file() or not args.binary.stat().st_size:
        parser.error("the binary must be a non-empty file")
    print(make_archive(args.platform, args.binary, args.output))


if __name__ == "__main__":
    main()
