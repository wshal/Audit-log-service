# Tamper-Evident Audit Log Service

A high-integrity, append-only Audit Log Service engineered with cryptographic hash chaining, selective field-level redaction, configurable retention policies, and regulatory compliance reporting.

Built for the **Charles Schwab & Co., Inc.** Engineering Assessment.

---

## 1. System Overview

This service guarantees an append-only, tamper-evident audit ledger:
- **Scenario A (Core Service)**: Append-only event ingestion, multi-attribute querying, cryptographic SHA-256 hash chaining, and full-chain verification reporting.
- **Scenario B (Lifecycle & Privacy)**: Configurable retention policy (soft-delete/archival without chain breakage), structured cryptographic field-level redaction, and self-contained verifiable export bundles.
- **Scenario C (Compliance Reporting)**: Requirement normalization and implementation of an audited client data access trail with regulatory export and anomaly detection.

---

## 2. Architecture & Design Principles

1. **Append-Only Ingestion**: The API exposes no `UPDATE` or `DELETE` endpoints for audit records.
2. **Deterministic Cryptographic Chaining**:
   - Each record stores `record_hash` and `prev_hash`.
   - The hash is computed using SHA-256 over deterministic JSON (sorted keys, compact separators). This is a Python-specific canonical encoding, not a full RFC 8785 implementation.
   - The first record in the chain binds to a defined genesis value (`"0" * 64`).
3. **Tamper Detection**:
   - `GET /audit/verify` traverses the ledger sequentially.
   - Detects content mutation, record deletion, reordering, and chain truncation.
   - Identifies the exact sequence number and failure category.
4. **Structured Redaction**:
   - Sensitive fields within `payload` (e.g., SSN, account numbers) can be masked without invalidating the parent block's cryptographic hash.
   - Designed using per-field cryptographic commitments (salted field hashing).

---

## 3. Tech Stack

- **Runtime**: Python 3.12+
- **API Framework**: FastAPI (Asynchronous, OpenAPI 3.1 self-documenting)
- **Validation**: Pydantic v2
- **Persistence**: SQLite (Local embedded relational ledger with strict concurrency controls)
- **Testing**: Pytest, HTTPX

---

## 4. Repository Structure

```text
├── ATTESTATION.md                    # Section 0.4 Candidate declaration
├── AI_LOG.md                         # Section 4.3 AI traceability log
├── README.md                         # Architecture, design decisions, run instructions
├── pytest.ini                        # Pytest configuration
├── requirements.txt                  # Python dependencies
├── docs/
│   ├── architecture.md               # Deep-dive architecture and design trade-offs
│   ├── audit_review.md               # Implementation audit and improvement record
│   ├── final_engineering_summary.md  # Final engineering summary and risk analysis
│   └── scenario_c_normalization.md   # Requirement normalization and scope boundary
├── app/
│   ├── __init__.py
│   ├── main.py                       # FastAPI application entrypoint
│   ├── config.py                     # Configuration settings
│   ├── security.py                   # API-key authentication & RBAC roles
│   ├── models/
│   │   ├── schemas.py                # Core Audit Record schemas (Scenario A)
│   │   ├── retention_redaction.py    # Retention, Redaction, Export schemas (Scenario B)
│   │   └── compliance.py             # Regulatory Compliance schemas (Scenario C)
│   ├── crypto/
│   │   ├── hasher.py                 # Deterministic JSON & SHA-256 hash chaining
│   │   ├── redaction.py              # Salted field commitments for structured redaction
│   │   └── signer.py                 # Ed25519 asymmetric record signatures & key ring
│   ├── storage/
│   │   ├── database.py               # Database entities, indexes, and session factory
│   │   └── repository.py             # Append-only audit ledger repository
│   ├── services/
│   │   ├── verifier.py               # Ledger chain verification & tamper detector
│   │   ├── lifecycle.py              # Retention archival, redaction, verifiable export
│   │   └── compliance.py             # Compliance report & anomaly detection engine
│   └── routers/
│       ├── audit.py                  # Core endpoints (Write, Query, Verify)
│       ├── lifecycle.py              # Lifecycle endpoints (Retention, Redact, Export)
│       └── compliance.py             # Compliance endpoints (Client access report)
└── tests/
    ├── conftest.py                   # Test fixtures and database isolation
    ├── test_scenario_a.py            # Scenario A tests (Write, Query, Verify, Tamper Detection)
    ├── test_scenario_b.py            # Scenario B tests (Retention, Redaction, Export)
    ├── test_scenario_c.py            # Scenario C tests (Compliance reports & Anomaly detection)
    ├── test_integrity_regressions.py # Concurrency, timestamp, and redaction regression tests
    └── test_security_controls.py     # Auth, RBAC, Ed25519 signatures & witness tests
```

---

## 5. Local Setup & Execution Instructions

### 1. Activate Environment & Install Dependencies
```bash
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install requirements:
pip install -r requirements.txt
```

### Security Configuration

Every API route requires an `X-API-Key` header. For local development and assessment review, the service includes a built-in development key with `admin` privileges:
```text
X-API-Key: development-only-audit-key
```

In a production environment, provide keys and asymmetric signing materials via environment variables:
```powershell
$env:AUDIT_ENV = "production"
$env:AUDIT_API_KEYS = '{"<secret-api-key>":{"subject":"audit-writer","roles":["writer"]}}'
$env:AUDIT_SIGNING_PRIVATE_KEY = "<base64 Ed25519 private key, 32 raw bytes>"
$env:AUDIT_SIGNING_KEY_ID = "ed25519-2026-10"
$env:AUDIT_SIGNING_PUBLIC_KEYS = '{"ed25519-2026-10":"<base64 Ed25519 public key>"}'
$env:AUDIT_CORS_ORIGINS = "https://audit.example.com"
```

Supported RBAC roles: `reader`, `writer`, `retention_admin`, `privacy_officer`, `exporter`, `compliance_reviewer`; `admin` grants full access.

### 2. Run Test Suite
```bash
pytest -v
```
All **22 automated tests** validate:
- Append-only write & hash chain linking
- Multi-parameter indexed querying
- Tamper detection upon direct database payload modification
- Tamper detection upon record deletion
- Retention policy soft-archival without false positives
- Field-level redaction preserving historical chain validity
- Mutation detection after redaction through an immutable redaction manifest
- Competing SQLite writes serialized under `BEGIN IMMEDIATE`, timestamp normalization, and invalid lifecycle input
- Independent verifiable bulk export bundle integrity with Ed25519 key ring
- Regulatory compliance reporting and anomaly detection
- API authentication/role enforcement, Ed25519 record signatures, offline signature verification, lifecycle-manifest witnesses, and archival-state tamper detection

See [docs/audit_review.md](docs/audit_review.md) for the implementation audit and hardening record.
For a copy/paste clean-database walkthrough of every scenario with expected outputs, see [docs/manual_validation.md](docs/manual_validation.md).

### 3. Start Local Microservice
```bash
uvicorn app.main:app --reload --port 8000
```
Interactive API documentation and live playground will be accessible at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

> **Note for Swagger UI**: Click the green **Authorize** button at the top right of the Swagger UI and enter `development-only-audit-key` to authorize all requests.

---

## 6. Live Defense Walkthrough (Quick Reference)

1. **Authorize in Swagger UI**:
   - Open `http://localhost:8000/docs`, click **Authorize**, enter `development-only-audit-key`.
2. **Verify Ledger Authenticity**:
   - Call `GET /audit/verify` -> returns `{"intact": true, "violationType": "NONE"}`.
3. **Demonstrate Tampering Detection**:
   - Write events using `POST /audit/events`.
   - Directly modify SQLite payload or delete a record in `audit_records`.
   - Call `GET /audit/verify` -> returns `{"intact": false, "violationType": "CONTENT_HASH_MISMATCH"}` (or `SEQUENCE_DISCONTINUITY`) along with the exact broken record sequence number.
4. **Demonstrate Privacy Redaction**:
   - Call `POST /audit/redact` with field names `["ssn", "bankAccount"]`.
   - Verify values are masked to `[REDACTED:COMMITMENT:...]` while `GET /audit/verify` confirms the hash chain remains intact.
5. **Demonstrate Regulatory Compliance Report**:
   - Call `GET /audit/compliance/client-access?clientId=client-act-001`.
   - Observe actor breakdown, access justifications, anomaly flagging, and chain verification.
