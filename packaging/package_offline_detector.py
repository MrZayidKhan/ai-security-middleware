"""Package local, reviewed detector files and a Windows wheelhouse for offline installation."""

import argparse
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_HASHES = {
    'model_quantized.onnx': '61cd0741cdbfcc229e32e1de1392f352736d87d1e8b3c2b67ad9836bb7910d5d',
    'tokenizer.json': '47834a7dbbb0c4324fe9569fe47955241594a9ee539c9e478755d6fbc51e5f46',
    'NOTICE': '5ffe2383027c7510933df2e7055440edde8c96b67b7a58fb477f9632c72b9c14',
}
REQUIRED_FILES = (*MODEL_HASHES, 'config.json', 'advisory_profile.json', 'LICENSE', 'README.md')


def package(model_dir: Path, wheelhouse: Path, output: Path, python_version: str = '3.13',
            *, dashboard: Path) -> None:
    if not dashboard.is_file() or dashboard.stat().st_size == 0:
        raise ValueError('Supply a built Windows dashboard executable')
    model_files = [model_dir / name for name in REQUIRED_FILES]
    for file in model_files:
        if not file.is_file():
            raise ValueError(f'Missing required model file: {file.name}')
        expected = MODEL_HASHES.get(file.name)
        if expected:
            with file.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            if actual != expected:
                raise ValueError(f'Model checksum mismatch: {file.name}')
    wheels = sorted(wheelhouse.glob('*.whl'))
    for distribution in ('ai_security_middleware', 'onnxruntime', 'tokenizers', 'numpy',
                         'fastapi', 'uvicorn'):
        if not any(file.name.lower().startswith(distribution + '-') for file in wheels):
            raise ValueError(f'Wheelhouse is missing a {distribution} wheel')
    if output.suffix.lower() != '.zip' or output.exists():
        raise ValueError('Output must be a new .zip file')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('python-version.txt', python_version)
        bundle.write(ROOT / 'packaging' / 'OFFLINE_DETECTOR.md', 'OFFLINE_DETECTOR.md')
        for name in ('Setup.cmd', 'setup_detector.ps1', 'Open Dashboard.cmd',
                     'Open Sanitizer.cmd', 'Uninstall.cmd', 'uninstall_detector.py'):
            bundle.write(ROOT / 'packaging' / name, name)
        bundle.write(dashboard, 'security-dashboard.exe')
        for file in model_files:
            bundle.write(file, f'model/{file.name}')
        for file in wheels:
            bundle.write(file, f'wheels/{file.name}', compress_type=zipfile.ZIP_STORED)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-dir', required=True, type=Path)
    parser.add_argument('--wheelhouse', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--dashboard', required=True, type=Path)
    parser.add_argument('--python-version', choices=('3.13', '3.14'), default='3.13')
    args = parser.parse_args()
    try:
        package(args.model_dir, args.wheelhouse, args.output, args.python_version, dashboard=args.dashboard)
    except ValueError as error:
        parser.error(str(error))
    print(args.output)


if __name__ == '__main__':
    main()
