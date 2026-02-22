from typing import Optional, List, Union

from script import Script, verify_p2pkh
from transaction import Transaction, Output, Input, DIFFICULTY, BLOCK_REWARD
from block import Block
from blockchain import Blockchain

"""
Network node that manages multiple blockchain forks.

=== NAKAMOTO CONSENSUS ===

This implementation follows Nakamoto Consensus, the breakthrough innovation
that allows a decentralized network to agree on a single transaction history
without a central authority.

Key principles:

1. LONGEST CHAIN RULE
   - Always consider the longest valid chain as the "true" chain
   - When you receive a new block, add it to whatever chain it extends
   - When building a new block, always build on the longest chain
   - This ensures all honest nodes eventually converge on the same chain

2. TIE-BREAKING
   - When two chains have equal length, stick with the one you saw first
   - Only switch to a different chain if it becomes longer
   - This prevents unnecessary chain reorganizations

3. PROOF OF WORK
   - Miners must find a nonce that makes the block hash below DIFFICULTY
   - This makes it computationally expensive to create blocks
   - An attacker would need >50% of network hashpower to rewrite history

4. BLOCK REWARDS (Coinbase)
   - Miners receive newly created coins for finding valid blocks
   - This incentivizes honest mining behavior
   - Coinbase transactions have no inputs - they create new money

5. FORK HANDLING
   - Temporary forks are normal when two miners find blocks simultaneously
   - The network naturally resolves forks as one chain becomes longer
   - Transactions in orphaned blocks return to the mempool
"""


class Node:
    """
    All chains that the node is currently aware of.
    """

    def __init__(self):
        # We will not access this field, you are free change it if needed.
        self.chains = []

    def new_chain(self, genesis: Block):
        """
        Create a new chain with the given genesis block.
        The autograder will give you the genesis block.

        The genesis block is special:
        - It's the first block in the chain (no previous block)
        - Its coinbase transaction creates the initial coins
        - All nodes must agree on the same genesis block

        Note: Genesis block has block.txs (a list of transactions)
        """
        utxos = []
        for tx in genesis.txs:
            for idx, output in enumerate(tx.outputs):
                utxos.append({"tx_hash": tx.tx_hash, "output_index": idx, "output": output})
        self.chains.append(Blockchain(chain=[genesis], utxos=utxos))

    def append(self, block: Block) -> bool:
        """
        Attempt to append a block broadcast on the network.
        Returns True if it is possible to add (e.g. could be a fork), False otherwise.

        === NAKAMOTO CONSENSUS: FORK HANDLING ===

        When a new block arrives, we don't immediately know if it will be
        part of the longest chain. Two miners might find valid blocks at
        nearly the same time, creating a temporary fork.

        Our strategy:
        1. Accept ALL valid blocks that extend ANY known chain tip
        2. Each valid block creates a new "fork" in our view
        3. When building blocks, we always choose the longest fork
        4. Eventually, one fork will become longer and "win"
        """
        for chain in self.chains:
            last_block = chain.chain[-1]
            if block.prev == last_block.hash():
                # Validate the block against this chain
                if not self.is_valid_block(block, chain):
                    return False
                # Create a new fork with copied UTXOs
                new_utxos = [utxo.copy() for utxo in chain.utxos]
                new_chain = Blockchain(chain=chain.chain.copy() + [block], utxos=new_utxos)
                # Update UTXOs for all transactions in the block
                for tx in block.txs:
                    self.update_utxos(new_chain, tx)
                self.chains.append(new_chain)
                return True
        return False

    def build_block(self, txs: List[Transaction]) -> Optional[Block]:
        """
        Build a block on the longest chain you are currently tracking.
        Returns None if any transaction is invalid (e.g. double spend).

        Accepts a list of transactions to include in the block.
        For convenience, also accepts a single Transaction (auto-wrapped in list).

        === NAKAMOTO CONSENSUS: LONGEST CHAIN RULE ===

        This method implements a core principle of Nakamoto Consensus:
        always build on the longest valid chain.

        Why? Because the longest chain represents the most cumulative
        proof-of-work, meaning the most computational effort was spent
        on it. An attacker trying to rewrite history would need to
        outpace the entire honest network.
        """
        if isinstance(txs, Transaction):
            txs = [txs]

        if not self.chains:
            return None

        # Find the longest chain (ties broken by first-seen, per Nakamoto Consensus)
        longest = max(self.chains, key=lambda c: len(c.chain))

        # Validate all transactions against a temporary UTXO set so that
        # transactions within the same block can spend each other's outputs.
        temp_utxos = [utxo.copy() for utxo in longest.utxos]
        temp_chain = Blockchain(chain=longest.chain.copy(), utxos=temp_utxos)

        for i, tx in enumerate(txs):
            is_coinbase_allowed = (i == 0)
            if not self.is_transaction_valid(tx, temp_chain, is_coinbase_allowed):
                return None
            self.update_utxos(temp_chain, tx)

        # Mine the block
        prev = longest.chain[-1].hash()
        block = Block(prev, txs, '00')
        block.mine()

        # Register the new chain (with the mined block) so subsequent calls
        # to build_block() and the longest-chain rule see it immediately.
        temp_chain.chain.append(block)
        self.chains.append(temp_chain)

        return block

    def is_valid_block(self, block: Block, chain: Blockchain) -> bool:
        """Validate a block's proof of work and all transactions."""
        if not self.verify_pow(block):
            return False

        if not block.txs:
            return False

        # Validate all transactions with a temporary UTXO set.
        # This allows transactions in the same block to spend outputs
        # created by earlier transactions in the same block.
        temp_utxos = [utxo.copy() for utxo in chain.utxos]
        temp_chain = Blockchain(chain=chain.chain.copy(), utxos=temp_utxos)

        for i, tx in enumerate(block.txs):
            is_coinbase_allowed = (i == 0)
            if not self.is_transaction_valid(tx, temp_chain, is_coinbase_allowed):
                return False
            self.update_utxos(temp_chain, tx)

        return True

    def is_transaction_valid(self, tx: Transaction, blockchain: Blockchain, is_coinbase_allowed: bool = False) -> bool:
        """
        Validate a transaction.

        For coinbase transactions:
        - Must have no inputs (check tx.is_coinbase())
        - Output value must not exceed BLOCK_REWARD
        - Only allowed as the first transaction in a block

        For regular transactions:
        1. Find the UTXO being spent for each input
        2. Extract signature and pubkey from scriptSig (input.script_sig.elements)
        3. Extract expected pubkey hash from scriptPubKey (input.output.script_pubkey.elements[2])
        4. Use verify_p2pkh() to validate the signature
        5. Input total must equal output total (no inflation)

        Also check:
        - No double-spending within the transaction
        """
        # Coinbase transaction
        if tx.is_coinbase():
            if not is_coinbase_allowed:
                return False
            total_output = sum(o.value for o in tx.outputs)
            return total_output <= BLOCK_REWARD

        # Regular transaction
        tx_data = bytes.fromhex(tx.bytes_to_sign())
        input_total = 0
        seen = set()

        for inp in tx.inputs:
            # Find the matching UTXO. We match by (tx_hash, output bytes) so that
            # two different outputs of the same transaction are distinguished.
            utxo_found = False
            for utxo in blockchain.utxos:
                if utxo["tx_hash"] == inp.tx_hash and utxo["output"].to_bytes() == inp.output.to_bytes():
                    # Detect double-spending within this transaction using the
                    # UTXO's canonical (tx_hash, output_index) identity.
                    utxo_key = (utxo["tx_hash"], utxo["output_index"])
                    if utxo_key in seen:
                        return False
                    seen.add(utxo_key)
                    utxo_found = True
                    break
            if not utxo_found:
                return False

            # Verify P2PKH signature
            signature = bytes.fromhex(inp.script_sig.elements[0])
            pubkey = bytes.fromhex(inp.script_sig.elements[1])
            expected_hash = bytes.fromhex(inp.output.script_pubkey.elements[2])
            if not verify_p2pkh(signature, pubkey, expected_hash, tx_data):
                return False

            input_total += inp.output.value

        # Input total must equal output total (no coin creation in regular txs)
        output_total = sum(o.value for o in tx.outputs)
        return input_total == output_total

    def update_utxos(self, blockchain: Blockchain, tx: Transaction):
        """
        Update UTXO set after a transaction is confirmed.

        1. Remove UTXOs that were spent by the transaction's inputs
        2. Add new UTXOs from the transaction's outputs
        """
        # Remove UTXOs spent by inputs
        for inp in tx.inputs:
            for i, utxo in enumerate(blockchain.utxos):
                if utxo["tx_hash"] == inp.tx_hash and utxo["output"].to_bytes() == inp.output.to_bytes():
                    blockchain.utxos.pop(i)
                    break
        # Add new UTXOs from outputs
        for idx, output in enumerate(tx.outputs):
            blockchain.utxos.append({"tx_hash": tx.tx_hash, "output_index": idx, "output": output})

    def verify_pow(self, block: Block) -> bool:
        """Verify proof of work meets difficulty requirement."""
        block_hash = int(block.hash(), 16)
        return block_hash <= DIFFICULTY

    def find_transaction(self, blockchain: Blockchain, tx_hash: str) -> Optional[Transaction]:
        """Find a transaction by its hash in the blockchain."""
        for block in blockchain.chain:
            for tx in block.txs:
                if tx.tx_hash == tx_hash:
                    return tx
        return None
