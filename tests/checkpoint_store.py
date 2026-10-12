"""Test-only local checkpoint store.

This intentionally models neither external durability nor a production
checkpoint authority.  It exists solely to exercise the Phase B contract
without introducing a provider, KMS, or application persistence path.
"""

from app.checkpoint import Checkpoint


class InMemoryCheckpointStore:
    def __init__(self) -> None:
        self._checkpoint: Checkpoint | None = None

    def put(self, checkpoint: Checkpoint) -> None:
        if self._checkpoint is not None and checkpoint.sequenceNum < self._checkpoint.sequenceNum:
            raise ValueError("checkpoint sequence cannot move backwards")
        self._checkpoint = checkpoint

    def get(self) -> Checkpoint | None:
        return self._checkpoint
