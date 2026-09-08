# Contributing to SOC Investigation Lab

## Development Principles

- Meaningful work starts from a GitHub Issue with a defined goal, requirements, and acceptance criteria.
- Changes are made on short-lived branches created from the current `main` branch.
- `main` is protected, and changes reach it through Pull Requests.
- Required local validation and the `Backend quality` status check must pass before merge.
- Each Pull Request should stay narrowly scoped to its linked Issue; do not bundle unrelated refactoring into the same task.
- Documentation must reflect the repository's actual implementation state. Planned functionality must not be presented as implemented.
- Implementation, tests, and documentation should evolve together when the change makes each relevant.

The repository does not use a `develop` branch.

## Issue Workflow

Implementation and documentation work normally begins from an existing GitHub Issue. The Issue should provide enough context to understand its goal, requirements, and acceptance criteria. Where appropriate, it may also carry labels, a milestone, and an assignee.

The normal lifecycle is:

Issue
→ Branch
→ Implementation or Documentation
→ Local Validation
→ Pull Request
→ Review
→ Testing
→ Squash Merge
→ Issue Closure

A Pull Request intended to complete an Issue should normally include `Closes #<issue-number>`. GitHub then closes the linked Issue when the PR is merged into the default branch. The repository does not currently require a particular Issue template.

## GitHub Project Workflow

The GitHub Project uses this exact Status sequence:

Backlog → Ready → In Progress → Review → Testing → Done

### Backlog

Work exists but has not yet been prepared for execution.

### Ready

Prerequisites have been checked and the task is ready to start.

### In Progress

Active implementation or documentation work is taking place.

### Review

A Pull Request is open and the change is being reviewed.

### Testing

Review has passed and final validation is being performed.

### Done

The Issue has been successfully completed and merged.

`blocked` is a repository label, not a Project Status. Apply it when work cannot proceed because of an external dependency or unresolved decision; do not introduce a separate workflow state for that condition.

The configured Project workflow may automatically move an item to Done when its linked Issue closes. Avoid a redundant manual Project update when automation has already completed the transition.

## Branch Naming

Use this format:

```text
<type>/<issue-number>-<short-description>
```

Common branch types are `feat`, `fix`, `detection`, `case`, `docs`, `test`, `refactor`, and `chore`. Use `feat/`, not `feature/`, as the canonical feature prefix.

Examples:

```text
docs/8-contribution-workflow
feat/23-alert-model
detection/31-suspicious-powershell
fix/42-normalization-timestamp
```

Branch names must be lowercase, include the GitHub Issue number, and use a concise hyphen-separated description. Create the branch from the current `main`. One Issue should normally correspond to one working branch.

## Commit Convention

Use Conventional Commit style:

```text
type(scope): description
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, and `chore`. Project-specific types such as `detection` and `case` may also be used when they make the change clearer.

Examples:

```text
docs(workflow): document contribution process
test(backend): add parser regression test
feat(alerts): add alert domain model
detection(windows): add suspicious execution rule
fix(parser): preserve event timestamp
```

Use a lowercase type, a meaningful scope when useful, and a concise imperative description. Avoid vague messages such as `update files`, `fix stuff`, or `changes`. Commits should remain logically related to the Issue. A single focused commit is acceptable and is common; multiple commits are not required.

## Development and Validation

The current development baseline is Python 3.12 with uv for dependency and environment management.

Install the development and test dependencies:

```console
uv sync --group dev --group test
```

Run the current local validation sequence:

```console
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run mypy backend/tests
uv run --group test pytest
```

The dependency lock must remain consistent, and linting, formatting validation, type checking, and tests must pass. The repository does not currently define a coverage threshold.

### Pre-commit

The current pre-commit configuration runs Ruff lint, Ruff formatting checks, and mypy. Run all configured hooks when appropriate with:

```console
uv run pre-commit run --all-files
```

Pre-commit does not replace the complete validation sequence. Pytest and dependency-lock validation remain separate checks.

## Pull Request Workflow

1. Start from a GitHub Issue.
2. Confirm the Issue prerequisites and the current `main` state.
3. Move the Project item from Backlog to Ready and then In Progress.
4. Create a working branch from the current `main`.
5. Make only the narrowly scoped changes required by the Issue.
6. Run local validation.
7. Commit using the repository commit convention.
8. Push the branch.
9. Open a Pull Request targeting `main`.
10. Include `Closes #<issue-number>` when the PR completes the Issue.
11. Move the Project item from In Progress to Review.
12. Wait for CI to complete.
13. Address review feedback without expanding the Issue scope.
14. After review passes, move the Project item from Review to Testing.
15. Perform final validation.
16. Squash merge only after every gate passes.
17. Verify Issue closure, branch deletion, the resulting `main` state, and final Project status.

A PR should normally include a clear Summary, Changes, Validation, Related issue, and a checklist when useful. No exact universal PR template is currently mandatory.

### Review expectations

Review should verify that:

- the change matches the linked Issue and its acceptance criteria;
- no unrelated files changed;
- documentation matches the actual implementation state;
- tests are appropriate when application logic changes;
- CI is green; and
- no review conversation remains unresolved.

The active protection rules require review conversations to be resolved. Formal review remains part of the project workflow, but GitHub currently requires zero approving reviews; do not treat an approval count as a merge gate.

### Protected main

The active `main-protection` ruleset targets the default branch. Changes targeting `main` require a Pull Request and linear history. Review conversations must be resolved, and the required `Backend quality` status check must succeed. Deleting the protected branch is blocked, as are force pushes and other non-fast-forward updates. No bypass actor is configured.

The required-status-check strict or up-to-date policy is disabled, so a branch is not required to be brought up to date with `main` solely by this setting before merge. The required approving-review count is zero.

## Continuous Integration

The `Backend CI` GitHub Actions workflow runs for Pull Requests targeting `main`. It exposes the required `Backend quality` job and status check, which validates:

- dependency-lock consistency;
- locked installation of development and test dependencies;
- Ruff linting;
- Ruff formatting;
- mypy type checking; and
- pytest.

`Backend quality` must succeed before merge. The current workflow is PR-triggered, has no push trigger, and does not require repository secrets.

## Merge Policy

The effective repository merge configuration enables squash merge and disables both merge commits and rebase merge. Project convention therefore requires squash merge for all PRs.

Use a final squash commit title consistent with Conventional Commit style and normally include the PR number, for example:

```text
docs(workflow): document contribution process (#20)
```

## After Merge

Verify that:

- the PR is merged and closed;
- the linked Issue is closed when `Closes #N` was used;
- the expected change exists on `main`;
- exactly the intended squash commit advanced `main`;
- the source branch is deleted; and
- the Project item reaches Done.

The repository automatically deletes head branches after merge. The GitHub Project workflow may also move a closed linked Issue to Done automatically. Do not duplicate an automated transition with an unnecessary manual update.

## Scope Discipline

Do not introduce unrelated architecture, dependencies, infrastructure, or product capabilities without an appropriate Issue. In particular, do not evolve SOC Investigation Lab into a full SIEM, EDR, or SOAR platform, and do not introduce speculative distributed architecture.

The authoritative product boundaries are maintained in [Project Scope](docs/project-scope.md). High-level technical boundaries are maintained in [System Architecture](docs/architecture/overview.md).

