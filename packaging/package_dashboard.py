"""Archive a native Rust dashboard binary with its installation guide."""

import argparse
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from zipfile import ZIP_DEFLATED, ZipFile


SUPPORTED = (
    "windows-x64", "windows-arm64",
)


def make_archive(platform, binary, output):
    archive_name = f"security-dashboard-{platform}"
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="security-dashboard-package-") as temp:
        stage = Path(temp) / archive_name
        stage.mkdir()
        shutil.copyfile(Path(__file__).with_name("DOWNLOADS.md"), stage / "DOWNLOADS.md")
        executable = stage / "security-dashboard.exe"
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)

        archive = output / f"{archive_name}.zip"
        with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
            for file in stage.iterdir():
                bundle.write(file, f"{archive_name}/{file.name}")
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
