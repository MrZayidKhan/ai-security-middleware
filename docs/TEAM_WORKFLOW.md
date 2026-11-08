# Team Workflow

## Repository and task selection

The Git repository is `ai-security-middleware` on branch `main`. Tasks are unassigned until a contributor registers work in the project tracker. Do not assign work to a person in public documentation.

## Getting started

Clone the GitHub repository and work from `D:\Mini_project\ai-security-middleware` (or an equivalent path). The repository currently has no executable setup; follow [DEVELOPMENT.md](DEVELOPMENT.md) once milestone 1 setup is approved. Do not add model binaries, private local data, credentials, or generated databases to Git.

## Branches and commits

Use one branch per focused task:

- `feature/<feature-name>`
- `fix/<bug-name>`
- `docs/<documentation-name>`
- `test/<test-name>`

Use clear commits such as `feat: add document search tool`, `fix: prevent path traversal`, `test: add unauthorized access cases`, or `docs: explain policy engine`.

## Independent work and ownership

Documentation tasks can be separated by file. Once stable interfaces are written and approved, tool implementations, policy tests, and dashboard presentation can be divided. Until then, avoid parallel edits to shared interfaces, the gateway/dispatcher, dependency manifests, shared schemas, and tracker.

## Integration order

Agree on schema and tool contracts first; land the narrow tool functions and tests; integrate through the gateway; then add content inspection/review; integrate API and dashboard; finally run the evaluation corpus and update docs. Each task's dependencies and acceptance criteria are in the tracker.

## Pull request expectations

Each PR should link a tracker task, explain the change and security implications, include tests for significant behavior, update relevant documentation, identify limitations, and avoid unrelated edits. A task is complete only when its definition of done in the tracker is met and the changes are ready for review/committed. Resolve conflicts with the owning contributors before changing shared interfaces.
