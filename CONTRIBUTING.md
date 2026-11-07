# Contributing to TirBase

Thank you for your interest in contributing to TirBase. This document describes the
contribution workflow, the Developer Certificate of Origin (DCO) sign-off requirement,
and the project's code-review process.

---

## Table of Contents

1. [Developer Certificate of Origin (DCO)](#developer-certificate-of-origin-dco)
2. [Contribution Workflow](#contribution-workflow)
3. [Issue Templates](#issue-templates)
4. [Coding Guidelines](#coding-guidelines)
5. [Security Policy](#security-policy)

---

## Developer Certificate of Origin (DCO)

Every commit to TirBase **must** carry a `Signed-off-by` trailer certifying that you
agree to the Developer Certificate of Origin 1.1 printed below. This is a lightweight
attestation that you have the right to contribute the code and that you agree to the
project's open-source licence terms.

### DCO 1.1 Full Text

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to Sign Off

Add the following trailer to every commit message, using your real name and the
e-mail address associated with your identity:

```
Signed-off-by: Jane Doe <jane.doe@example.com>
```

The easiest way is to pass `-s` (or `--signoff`) to `git commit`:

```bash
git commit -s -m "feat(guard): add rate-of-change check"
```

If you forget to sign off on a commit that has not yet been pushed, you can amend it:

```bash
git commit --amend -s
```

For a series of commits that have not yet been pushed you can rebase:

```bash
git rebase --signoff HEAD~<N>
```

> **Note:** Commits that arrive in a pull request without a `Signed-off-by` trailer will
> be asked to add one before the PR can be merged.

---

## Contribution Workflow

1. **Open or find an issue.** Before starting work, check the issue tracker.
   If no issue exists for the change you want to make, open one describing the problem
   or feature so maintainers can give early feedback.

2. **Fork the repository.** Create a personal fork on GitHub and clone it locally:

   ```bash
   git clone https://github.com/<your-username>/TriBase.git
   cd TriBase
   ```

3. **Create a feature branch.** Branch off `main` with a short descriptive name:

   ```bash
   git switch -c feat/my-change
   ```

4. **Make your changes.** Follow the [Coding Guidelines](#coding-guidelines) below.

5. **Write tests.** New behaviour must be covered by at least one integration test
   (two real `CoreHandle` instances, the gateway binary, or the SDK). See
   `docs/RFC-workspace.md` for the crate responsibilities and test-level guidance.

6. **Sign off all commits.** Use `git commit -s` (see the DCO section above).

7. **Open a pull request** against the `main` branch. Fill in the PR description:
   - *What* changed and *why*.
   - Which `PV-X.Y` requirement(s) the change addresses.
   - Which integration test validates the change (test identifier).

8. **Respond to review feedback.** At least one maintainer approval is required before
   merge. Address every comment thread before requesting a re-review.

9. **Merge.** Maintainers will squash-merge when all CI checks are green and the PR
   is approved.

---

## Issue Templates

When reporting a bug please use the
[Bug Report template](.github/ISSUE_TEMPLATE/bug_report.md).

GitHub will present this template automatically when you open a new issue and select
"Bug report" from the issue-type menu.

---

## Coding Guidelines

- **Rust edition 2021** across the workspace.
- **`pub(crate)` by default.** Only items that are part of the declared public API
  surface (listed in each crate's `public-api.txt`) should be `pub`.
- **No direct clock calls.** All time access must go through the `TimeSource` trait.
  The `clippy::disallowed_methods` configuration at the workspace root enforces this.
- **`#![warn(dead_code)]`** is active; CI promotes it to an error. Remove unused code
  rather than suppressing the lint.
- **Unsafe code** must be justified with a `// SAFETY:` comment and will be tracked by
  `cargo geiger`. The geiger baseline must not increase.
- **Every new security or behaviour claim** must be added to `CLAIMS.md` with a
  `Planned` status *before* writing production code, then moved to `Proven` once a
  passing integration test backs it.
- **EARS-format requirements** must be added to `requirements.md` and design notes to
  `design.md` before any production code for that behaviour is written.

---

## Security Policy

Please do not file public issues for security vulnerabilities. Instead, follow the
responsible-disclosure process described in [SECURITY.md](SECURITY.md).
