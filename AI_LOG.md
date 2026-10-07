# AI Usage and Decision Log

This document records the traceability of AI assistance throughout the development of the **Tamper-Evident Audit Log Service** in accordance with Schwab requirements (Section 0.3, 4.3, and 7).

## Principles & Quality Gates
- **Human-in-the-Loop**: All architectural boundaries, cryptographic choices, redaction designs, and test suites are directed, reviewed, and signed off by the engineer.
- **Traceability**: Decisions to accept, modify, or reject AI proposals are documented here.
- **Verification**: All code passes automated unit and integration tests, static typing checks, and manual tamper-detection validation.

---

## Log Entries

### Entry 1: Project Scaffolding & Architecture Formulation
- **Date**: 2026-10-07
- **Intent**: Define technical stack, system architecture, data model, and decomposition plan.
- **Prompt Summary**: "Analyze the Charles Schwab Audit Log Service requirements across Scenarios A, B, and C. Propose architecture, directory structure, and technical stack."
- **AI Proposal**: Recommended Python with FastAPI, Pydantic v2, SQLite/SQLAlchemy with strict deterministic canonical JSON serialization (RFC 8785) for cryptographic hashing.
- **Engineer Decision**: **Accepted with Refinements**.
  - Refined cryptographic approach: SHA-256 with explicit canonical sorting (keys sorted, no unescaped whitespaces) to eliminate serialization non-determinism across platforms.
  - Required explicit genesis block hash specification (`GENESIS_BLOCK_PREV_HASH = "0" * 64`).
  - Added dedicated redaction mechanism using HMAC / Merkle-leaf or salted field hashes so redacting a sensitive value retains mathematical proof of original integrity.
