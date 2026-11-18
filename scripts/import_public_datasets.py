"""Download pinned public dataset snapshots without executing repository code.

Run with the project's Python environment. Re-running reuses existing files.
Raw releases retain their original splits; no training artifacts are changed.
"""
import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'datasets' / 'public_raw'
HF = ['hendzh/PromptShield', 'leolee99/NotInject',
      'deepset/prompt-injections', 'reshabhs/SPML_Chatbot_Prompt_Injection']


def fetch(url):
    with urlopen(Request(url, headers={'User-Agent': 'dataset-integrity-importer'}), timeout=90) as response:
        return response.read()


def save(source, revision, name, url):
    path = DEST / source.replace('/', '__') / name
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = path.read_bytes() if path.exists() else fetch(url)
    if not path.exists():
        path.write_bytes(payload)
    return {'source': source, 'revision': revision, 'file': name, 'url': url,
            'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    records, errors = [], []
    for source in HF:
        try:
            meta = json.loads(fetch('https://huggingface.co/api/datasets/' + source))
            revision = meta['sha']
            for item in meta['siblings']:
                name = item['rfilename']
                if name.endswith(('.parquet', '.json', '.jsonl', '.csv')) or name.lower().startswith(('readme', 'license')):
                    records.append(save(source, revision, name,
                                        f'https://huggingface.co/datasets/{source}/resolve/{revision}/{name}'))
            print(source, revision, 'downloaded', flush=True)
        except Exception as exc:
            errors.append({'source': source, 'error': str(exc)})
            print(source, str(exc), flush=True)
    for source, prefix in [('microsoft/BIPIA', ('benchmark/', 'bipia/data/')),
                           ('uiuc-kang-lab/InjecAgent', ('data/',))]:
        try:
            tree = json.loads(fetch(f'https://api.github.com/repos/{source}/git/trees/main?recursive=1'))
            revision = tree['sha']
            for item in tree['tree']:
                name = item['path']
                if item['type'] == 'blob' and (name.startswith(prefix) or name.lower().startswith(('readme', 'license'))):
                    records.append(save(source, revision, name,
                                        f'https://raw.githubusercontent.com/{source}/{revision}/{name}'))
            print(source, revision, 'downloaded', flush=True)
        except Exception as exc:
            errors.append({'source': source, 'error': str(exc)})
            print(source, str(exc), flush=True)
    (DEST / 'manifest.json').write_text(json.dumps({'files': records, 'errors': errors}, indent=2), encoding='utf-8')
    print(f'{len(records)} files; {len(errors)} source errors', flush=True)
    if errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
