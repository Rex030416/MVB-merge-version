import hashlib
from typing import List, Tuple, Optional

"""
Merkle Tree implementation for transaction aggregation.

=== WHY MERKLE TREES? ===

Merkle trees solve a key problem: How can a light client verify that a
transaction is included in a block without downloading all transactions?

Without Merkle trees:
- Must download ALL transactions in a block to verify one
- Full nodes must send entire blocks to light clients

With Merkle trees:
- Only need O(log n) hashes to prove inclusion
- Light clients can verify transactions with minimal data
- This enables SPV (Simplified Payment Verification)

=== STRUCTURE ===

For transactions [A, B, C, D]:

                 Root
                /    \
            H(AB)    H(CD)
            /  \      /  \
          H(A) H(B) H(C) H(D)
           |    |    |    |
           A    B    C    D

The root is stored in the block header. To prove C is in the block,
you only need: [H(D), H(AB)] - just 2 hashes instead of 4 transactions!

=== OUR APPROACH ===

We use double-SHA256 for Merkle hashing. If there's an odd number of
elements at any level, the missing right sibling is filled with zeros
(a 32-byte zero hash represented as 64 hex characters).
"""

# Zero hash used for padding when tree is unbalanced (32 bytes of zeros as hex)
ZERO_HASH = '0' * 64


def double_sha256(data: bytes) -> bytes:
    firstHash=hashlib.sha256(data).digest()
    secondHash=hashlib.sha256(firstHash).digest()
    return secondHash


def merkleParent(left: str, right: str) -> str:
    leftBytes=bytes.fromhex(left)
    rightBytes=bytes.fromhex(right)
    combineBytes=leftBytes+rightBytes
    parentBytes=double_sha256(combineBytes)
    return parentBytes.hex()


def build_merkle_tree(tx_hashes: List[str]) -> str:
    if tx_hashes == []:
        return double_sha256(b"").hex()

    curLevel = tx_hashes

    while len(curLevel) > 1:
        #odd node
        if len(curLevel) % 2 != 0:
            curLevel.append(ZERO_HASH)

        nextLevel = []
        for i in range(0, len(curLevel), 2):
            parent = merkleParent(curLevel[i], curLevel[i + 1])
            nextLevel.append(parent)
        curLevel = nextLevel

    return curLevel[0]


def merkle_proof(tx_hashes: List[str], index: int) -> List[Tuple[str, str]]:
    proof = []
    curLevel = tx_hashes
    curIndex = index

    while len(curLevel) > 1:
        if len(curLevel) % 2 != 0:
            curLevel.append(ZERO_HASH)

        if curIndex % 2 == 0:
            siblingIndex = curIndex + 1
            proof.append((curLevel[siblingIndex], 'right'))
        else:
            siblingIndex = curIndex - 1
            proof.append((curLevel[siblingIndex], 'left'))

        # 向上移动到父节点层
        nxtLevel = []
        for i in range(0, len(curLevel), 2):
            nxtLevel.append(merkleParent(curLevel[i], curLevel[i + 1]))

        curLevel = nxtLevel
        curIndex //= 2

    return proof


def verify_merkle_proof(tx_hash: str, proof: List[Tuple[str, str]], root: str) -> bool:
    """
    Verify a Merkle proof for a transaction.

    Starting from the transaction hash, combine with each sibling in the
    proof (respecting left/right position) until reaching the root.

    Args:
        tx_hash: The transaction hash to verify
        proof: The Merkle proof (list of (sibling_hash, position) tuples)
        root: The expected Merkle root

    Returns:
        True if the proof is valid, False otherwise
    """
    current = tx_hash
    for sibling, position in proof:
        if position == 'right':
            current = merkleParent(current, sibling)
        else:
            current = merkleParent(sibling, current)
    return current == root
