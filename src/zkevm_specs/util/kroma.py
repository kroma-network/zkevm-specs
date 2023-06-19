from .hash import keccak256
from .typing import U64, U256

class SourceHashAux:
    l1_block_hash: U256
    """
    For system deposit tx(l1 info deposit tx), this refers to sequence number.
    For user deposit tx, this refers to l1 log index.
    """
    index: U64

    def __init__(
        self,
        l1_block_hash: U256 = U256(0),
        index: U64 = U64(0),
    ) -> None:
        self.l1_block_hash = l1_block_hash
        self.index = index

    @staticmethod
    def domain(id: int) -> int:
        # See https://github.com/kroma-network/kroma/blob/dev/specs/deposits.md#source-hash-computation
        return 1 if id == 1 else 0

    @classmethod
    def domain_bytes(obj, id: int) -> bytes:
        return obj.domain(id).to_bytes(32, "big")

    def value_bytes(self) -> bytes:
        return self.l1_block_hash.to_bytes(32, "big") + self.index.to_bytes(32, "big")

    def value_hash(self) -> bytes:
        return keccak256(self.value_bytes())

    def source_hash(self, id: int, is_deposit_tx: bool) -> bytes:
        if not is_deposit_tx:
            return bytes(0)

        return keccak256(SourceHashAux.domain_bytes(id) + self.value_hash())
