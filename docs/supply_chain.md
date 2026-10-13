# Supply-chain and reproducible dependency controls

The project keeps direct dependency declarations in `requirements.txt` and
`requirements-postgres.txt`. The generated `requirements.lock` and
`requirements-postgres.lock` files pin the resolved direct and transitive
versions used by CI. They are generated with `pip-tools` on Python 3.12:

```powershell
python -m pip install pip-tools==7.6.2
pip-compile --output-file=requirements.lock requirements.txt
pip-compile --constraint=requirements.lock --output-file=requirements-postgres.lock requirements-postgres.txt
```

Review the resolver output and run the full test matrix before committing a
lock refresh. A lock file makes dependency versions reproducible; it does not
make downloaded artifacts or the resulting application image bit-for-bit
reproducible. The lock files currently pin versions but do not claim artifact
hash verification.

## CI evidence

The `supply-chain` job installs the locked runtime and PostgreSQL environments,
runs pinned `pip-audit==2.10.1`, and fails on any unresolved audit finding (no
severity is silently excluded). Its JSON reports and a CycloneDX JSON SBOM
generated from the lock inputs are uploaded as artifacts tied to the workflow
revision. The SBOM is an inventory, not a signature or independent attestation.

The `secret-scan` job runs Gitleaks against the repository without production
credentials. A finding must be investigated and, when real secret material was
exposed, the affected credential must be revoked or rotated. Do not suppress a
finding merely to make CI green; document any reviewed false positive with its
file, rule, rationale, owner, and reassessment condition.

## Scope and limitations

- The dependency scan covers the resolved packages installed by CI, not
  operating-system packages or production-managed services.
- Secret scanning covers the checked-out repository. It does not prove that a
  secret was never present in earlier history unless history scanning is
  explicitly enabled and reviewed.
- The repository does not claim that a clean scan proves the absence of all
  vulnerabilities or secrets.
- Ruff/mypy-style lint and type enforcement are not yet part of the required
  CI gate; introducing them requires a separate debt assessment rather than
  silently weakening security checks.
