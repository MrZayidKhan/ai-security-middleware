# Training source decisions

- **hendzh/PromptShield:** retain original training and validation partitions;
  original test remains evaluation data. Its validation results did not predict
  external behavior in the first experiment. Do not report validation as overall
  model quality.
- **deepset:** retain as a small direct-attack supplement, with its test excluded.
- **BIPIA:** retain for indirect-content training experiments. Remove clean-context
  overlap before constructing variants; hold out development attack families and
  contexts separately. The current reconstruction uses start/end/character-middle
  placement and is not the complete official BIPIA benchmark.
- **SPML:** exclude from generic text-classifier training. The upstream README
  explicitly advises against that use because violations depend on specific
  system prompts. Retain as a possible future context-aware diagnostic.
- **NotInject:** retain as benign regression data, excluded from training. Its
  upstream split names are alternate layouts of the same small benign suite.
- **InjecAgent:** retain as indirect-attack regression data, excluded from training.
  Base and enhanced variants must not be counted as independent cases.
- **Local Mendeley PromptShield:** exclude pending label-policy review. Its
  three-class uncertainty labels cannot be mapped to binary attacks without
  adjudication. It is separate from hendzh/PromptShield.
- **TADBench copies:** exclude as independent sources; they duplicate original
  releases. Generated adversarial suites have not been imported.

The first word and word/character candidate artifacts are rejected for deployment.
Keep their reports/artifacts for reproducibility; raw sources are not deleted.
Previously inspected external tests now provide regression evidence. Future model
selection must use development data and a new untouched final holdout is needed
before making a deployment-quality claim.
