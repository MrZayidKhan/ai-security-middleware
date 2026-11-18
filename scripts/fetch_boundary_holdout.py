"""Fetch a pinned, separately sourced boundary-pair regression holdout."""
import hashlib
import json
from urllib.request import urlopen
from train_candidates import ROOT

SOURCE='Horizon-Labs/prompt-injection-eval-suite'
REVISION='d6dd8d499d0087661afd6cd7ecdfcf94a5af1c05'
DEST=ROOT/'datasets/public_raw/horizon_eval'


def main():
    DEST.mkdir(parents=True,exist_ok=True)
    records=[]
    for name in ('README.md','data/boundary_pairs_test.parquet'):
        url=f'https://huggingface.co/datasets/{SOURCE}/resolve/{REVISION}/{name}?download=true'
        path=DEST/name.split('/')[-1]
        if not path.exists():
            with urlopen(url,timeout=90) as response:
                path.write_bytes(response.read())
        records.append(dict(file=path.name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),url=url))
    (DEST/'manifest.json').write_text(json.dumps(dict(source=SOURCE,revision=REVISION,files=records),indent=2),encoding='utf-8')
    import pyarrow.parquet as pq
    table=pq.read_table(DEST/'boundary_pairs_test.parquet')
    print('Rows:',table.num_rows,'Columns:',table.column_names)
    print((DEST/'README.md').read_text(encoding='utf-8')[:1500])


if __name__=='__main__':main()
