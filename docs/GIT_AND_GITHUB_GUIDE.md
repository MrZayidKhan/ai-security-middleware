# Git and GitHub Guide

## Purpose

Git keeps a local history of changes. GitHub hosts a shared copy so contributors can review and combine work. The project currently uses the `main` branch as the shared baseline.

## Planned task workflow

1. Check the tracker and choose an unassigned task.
2. Update the local `main` branch before starting.
3. Create one branch for the task: `feature/<name>`, `fix/<name>`, `test/<name>`, or `docs/<name>`.
4. Make the focused change and run its relevant checks.
5. Review the changed files before committing.
6. Create a clear commit, such as `feat: add document search tool`.
7. Push the branch and open a pull request.
8. Review the pull request, merge after approval and passing checks, then update local `main`.

Each Git command will be introduced during the related task with its purpose, effect, verification step, and recovery guidance. This avoids asking contributors to run commands before there is actual work to commit.

## Shared-file coordination

Before modifying shared schemas, policy definitions, the gateway dispatcher, dependency manifest, or tracker, check the active work recorded in the tracker. Agree on interfaces before parallel implementation. Keep commits narrow so a reviewer can understand and safely merge them.
