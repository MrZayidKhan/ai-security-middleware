# Public dataset import

Snapshots are in `datasets/public_raw/`. `manifest.json` records the upstream
revision, download URL, size and SHA-256 for all 53 downloaded files. Import with
`.venv/Scripts/python.exe scripts/import_public_datasets.py`; audit with
`.venv/Scripts/python.exe scripts/audit_public_datasets.py`.

Downloaded sources: hendzh/PromptShield (43,425 rows), NotInject (339 prompts
published in two equivalent layouts), deepset (662 rows), SPML (16,012 rows),
official Microsoft BIPIA benchmark data/loaders, and official InjecAgent data
(1,054 base cases and corresponding enhanced variants).

The local 3,000-row Mendeley PromptShield CSV is a different dataset from
hendzh/PromptShield. Their labels and provenance must remain separate.
TADBench is a pipeline over existing sources; its copies are not additional
independent training data. Its generated adversarial suites have not been imported.

Initial audit: 14 normalized prompt identities overlap PromptShield train and
validation; one deepset training prompt occurs in PromptShield test. Within-file
duplicate rows: PromptShield train 123, validation 2, test 171; SPML 98.
SPML contains one empty user prompt. See public_dataset_audit.json for counts.

Before training, exclude training/validation examples that overlap reserved
external tests, group related templates, and handle conflicting labels explicitly.
SPML's user prompt must be interpreted with its system prompt. NotInject stays
an external benign evaluation set regardless of upstream train/validation names.
InjecAgent base/enhanced cases are related variants, not independent observations.

BIPIA includes ready-made email/code/table contexts (1,200 context rows total),
attack definitions, and loaders. Web QA (`qa`) and summarization (`abstract`)
contain indexes/preparation scripts; original context datasets still need
reconstruction per upstream instructions. Earlier chat folder names such as
`email_qa` were inaccurate; actual folders are `email`, `code`, `table`, `qa`,
and `abstract`.

This import and exact-text audit do not train or replace the deployed classifier.
Near-duplicate analysis, context reconstruction, label review, and an isolated
candidate training run remain to be completed before promotion.
