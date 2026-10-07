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
   - The hash is computed using SHA-256 over canonicalized JSON representation (RFC 8785: sorted keys, compact separators).
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
├── ATTESTATION.md              # Section 0.4 Candidate declaration
├── AI_LOG.md                   # Section 4.3 AI traceability log
├── README.md                   # Architecture, design decisions, run instructions
├── requirements.txt            # Python dependencies
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entrypoint
│   ├── config.py               # Application configuration
│   ├── models/                 # Domain & API schemas
│   ├── crypto/                 # SHA-256 hashing, canonical serialization, redaction
│   ├── storage/                # Database layer, append-only repository
│   ├── services/               # Chain verification, retention, compliance engine
│   └── routers/                # API route definitions
└── tests/
    ├── __init__.py
    ├── test_scenario_a.py      # Core ingestion, query, chain verify, tamper detection
    ├── test_scenario_b.py      # Retention, structured redaction, verifiable export
    └── test_scenario_c.py      # Regulatory compliance audit queries & reports
```

---

## 5. Local Setup & Execution Instructions

### Prerequisites
- Python 3.12+ installed

### Setup Environment
```bash
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

### Run the Service
```bash
uvicorn app.main:app --reload --port 8000
```
Interactive API documentation will be available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Run Test Suite
```bash
pytest -v
```
