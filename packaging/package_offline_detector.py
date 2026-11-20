"""Package local, reviewed detector files and a Windows wheelhouse for offline installation."""

import argparse
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_HASHES = {
    'model_quantized.onnx': '61cd0741cdbfcc229e32e1de1392f352736d87d1e8b3c2b67ad9836bb7910d5d',
    'tokenizer.json': '47834a7dbbb0c4324fe9569fe47955241594a9ee539c9e478755d6fbc51e5f46',
}
REQUIRED_FILES = (*MODEL_HASHES, 'config.json', 'LICENSE', 'NOTICE', 'README.md')


def package(model_dir: Path, wheelhouse: Path, output: Path) -> None:
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
    for distribution in ('ai_security_middleware', 'onnxruntime', 'tokenizers', 'numpy'):
        if not any(file.name.lower().startswith(distribution + '-') for file in wheels):
            raise ValueError(f'Wheelhouse is missing a {distribution} wheel')
    if output.suffix.lower() != '.zip' or output.exists():
        raise ValueError('Output must be a new .zip file')
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(ROOT / 'packaging' / 'OFFLINE_DETECTOR.md', 'OFFLINE_DETECTOR.md')
        for file in model_files:
            bundle.write(file, f'model/{file.name}')
        for file in wheels:
            bundle.write(file, f'wheels/{file.name}', compress_type=zipfile.ZIP_STORED)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-dir', required=True, type=Path)
    parser.add_argument('--wheelhouse', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        package(args.model_dir, args.wheelhouse, args.output)
    except ValueError as error:
        parser.error(str(error))
    print(args.output)


if __name__ == '__main__':
    main()
