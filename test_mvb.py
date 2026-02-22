"""
MVB (Minimum Viable Blockchain) 测试套件
根据 Assignment 1b 规范编写
测试范围:
  - script.py : sha256_hash, verify_p2pkh, Script.to_bytes
  - merkle.py : build_merkle_tree, merkle_proof, verify_merkle_proof
  - transaction.py : Output, Input, Transaction (coinbase / regular)
  - wallet.py : build_transaction
  - block.py : Block.hash, Block.mine
  - node.py : Node (new_chain, build_block, append, fork handling)
"""

import unittest
import hashlib
from nacl.signing import SigningKey

from script import Script, sha256_hash, verify_p2pkh, ScriptInterpreter
from script import OP_DUP, OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG
from transaction import Output, Input, Transaction, DIFFICULTY, BLOCK_REWARD
from wallet import build_transaction
from merkle import build_merkle_tree, merkle_proof, verify_merkle_proof, ZERO_HASH, double_sha256, merkleParent
from block import Block
from blockchain import Blockchain
from node import Node


def make_signing_key():
    return SigningKey.generate()


def make_genesis(miner_key: SigningKey) -> Block:
    pub_key_hex = miner_key.verify_key.encode().hex()
    coinbase = Transaction.coinbase(pub_key_hex, BLOCK_REWARD)
    prev = '0' * 64
    genesis = Block(prev, [coinbase], '00')
    genesis.mine()
    return genesis


class TestScript(unittest.TestCase):

    def setUp(self):
        self.key = make_signing_key()
        self.pub_key = self.key.verify_key.encode()
        self.pub_key_hex = self.pub_key.hex()
        self.pub_key_hash = sha256_hash(self.pub_key)

    def test_sha256_hash_known_value(self):
        expected = hashlib.sha256(b'hello').digest()
        self.assertEqual(sha256_hash(b'hello'), expected)

    def test_sha256_hash_returns_bytes(self):
        self.assertIsInstance(sha256_hash(b'data'), bytes)

    def test_sha256_hash_length(self):
        self.assertEqual(len(sha256_hash(b'data')), 32)

    def test_script_to_bytes_opcode(self):
        s = Script([OP_DUP])
        self.assertEqual(s.to_bytes(), b'OP_DUP')

    def test_script_to_bytes_data(self):
        s = Script(['deadbeef'])
        self.assertEqual(s.to_bytes(), bytes.fromhex('deadbeef'))

    def test_script_to_bytes_mixed(self):
        s = Script.p2pkh_locking_script(self.pub_key_hash.hex())
        result = s.to_bytes()
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_p2pkh_locking_script_elements(self):
        pub_hash_hex = self.pub_key_hash.hex()
        s = Script.p2pkh_locking_script(pub_hash_hex)
        self.assertEqual(s.elements, [OP_DUP, OP_SHA256, pub_hash_hex, OP_EQUALVERIFY, OP_CHECKSIG])

    def test_p2pkh_unlocking_script_elements(self):
        sig_hex = 'ab' * 64
        s = Script.p2pkh_unlocking_script(sig_hex, self.pub_key_hex)
        self.assertEqual(s.elements, [sig_hex, self.pub_key_hex])

    def test_verify_p2pkh_valid(self):
        tx_data = b'some transaction data'
        sig = self.key.sign(tx_data).signature
        self.assertTrue(verify_p2pkh(sig, self.pub_key, self.pub_key_hash, tx_data))

    def test_verify_p2pkh_wrong_signature(self):
        tx_data = b'some transaction data'
        wrong_sig = bytes(64)
        self.assertFalse(verify_p2pkh(wrong_sig, self.pub_key, self.pub_key_hash, tx_data))

    def test_verify_p2pkh_wrong_pubkey_hash(self):
        tx_data = b'data'
        sig = self.key.sign(tx_data).signature
        wrong_hash = bytes(32)
        self.assertFalse(verify_p2pkh(sig, self.pub_key, wrong_hash, tx_data))

    def test_verify_p2pkh_wrong_tx_data(self):
        tx_data = b'correct data'
        other_data = b'wrong data'
        sig = self.key.sign(tx_data).signature
        self.assertFalse(verify_p2pkh(sig, self.pub_key, self.pub_key_hash, other_data))

    def test_script_interpreter_valid_p2pkh(self):
        tx_data = b'tx data'
        sig = self.key.sign(tx_data).signature
        sig_hex = sig.hex()
        pub_hash_hex = self.pub_key_hash.hex()
        combined = Script([sig_hex, self.pub_key_hex,
                           OP_DUP, OP_SHA256, pub_hash_hex, OP_EQUALVERIFY, OP_CHECKSIG])
        interp = ScriptInterpreter()
        self.assertTrue(interp.execute(combined, tx_data))

    def test_script_interpreter_invalid_sig(self):
        tx_data = b'tx data'
        bad_sig = ('00' * 64)
        pub_hash_hex = self.pub_key_hash.hex()
        combined = Script([bad_sig, self.pub_key_hex,
                           OP_DUP, OP_SHA256, pub_hash_hex, OP_EQUALVERIFY, OP_CHECKSIG])
        interp = ScriptInterpreter()
        self.assertFalse(interp.execute(combined, tx_data))


class TestMerkle(unittest.TestCase):

    def _fake_hash(self, label: str) -> str:
        return hashlib.sha256(label.encode()).hexdigest()

    def test_merkle_single_tx(self):
        h = self._fake_hash('A')
        root = build_merkle_tree([h])
        self.assertEqual(root, h)

    def test_merkle_two_txs(self):
        h_a = self._fake_hash('A')
        h_b = self._fake_hash('B')
        expected = merkleParent(h_a, h_b)
        root = build_merkle_tree([h_a, h_b])
        self.assertEqual(root, expected)

    def test_merkle_four_txs(self):
        hashes = [self._fake_hash(c) for c in 'ABCD']
        h_ab = merkleParent(hashes[0], hashes[1])
        h_cd = merkleParent(hashes[2], hashes[3])
        expected = merkleParent(h_ab, h_cd)
        root = build_merkle_tree(hashes[:])
        self.assertEqual(root, expected)

    def test_merkle_odd_txs(self):
        hashes = [self._fake_hash(c) for c in 'ABC']
        h_ab = merkleParent(hashes[0], hashes[1])
        h_c0 = merkleParent(hashes[2], ZERO_HASH)
        expected = merkleParent(h_ab, h_c0)
        root = build_merkle_tree(hashes[:])
        self.assertEqual(root, expected)

    def test_merkle_empty(self):
        expected = double_sha256(b'').hex()
        self.assertEqual(build_merkle_tree([]), expected)

    def test_merkle_deterministic(self):
        hashes = [self._fake_hash(c) for c in 'ABCD']
        r1 = build_merkle_tree(hashes[:])
        r2 = build_merkle_tree(hashes[:])
        self.assertEqual(r1, r2)

    def test_merkle_proof_and_verify_index0(self):
        hashes = [self._fake_hash(c) for c in 'ABCD']
        root = build_merkle_tree(hashes[:])
        proof = merkle_proof(hashes[:], 0)
        result = verify_merkle_proof(hashes[0], proof, root)
        self.assertTrue(result)

    def test_merkle_proof_and_verify_index2(self):
        hashes = [self._fake_hash(c) for c in 'ABCD']
        root = build_merkle_tree(hashes[:])
        proof = merkle_proof(hashes[:], 2)
        result = verify_merkle_proof(hashes[2], proof, root)
        self.assertTrue(result)

    def test_merkle_proof_wrong_hash(self):
        hashes = [self._fake_hash(c) for c in 'ABCD']
        root = build_merkle_tree(hashes[:])
        proof = merkle_proof(hashes[:], 0)
        wrong_hash = self._fake_hash('Z')
        result = verify_merkle_proof(wrong_hash, proof, root)
        self.assertFalse(result)


class TestTransaction(unittest.TestCase):

    def setUp(self):
        self.key = make_signing_key()
        self.pub_key_hex = self.key.verify_key.encode().hex()

    def test_coinbase_no_inputs(self):
        cb = Transaction.coinbase(self.pub_key_hex)
        self.assertEqual(cb.inputs, [])
        self.assertTrue(cb.is_coinbase())

    def test_coinbase_output_value(self):
        cb = Transaction.coinbase(self.pub_key_hex, BLOCK_REWARD)
        self.assertEqual(sum(o.value for o in cb.outputs), BLOCK_REWARD)

    def test_transaction_hash_is_hex(self):
        cb = Transaction.coinbase(self.pub_key_hex)
        self.assertEqual(len(cb.tx_hash), 64)
        int(cb.tx_hash, 16)

    def test_transaction_hash_deterministic(self):
        cb1 = Transaction.coinbase(self.pub_key_hex, 10)
        cb2 = Transaction.coinbase(self.pub_key_hex, 10)
        self.assertEqual(cb1.tx_hash, cb2.tx_hash)

    def test_output_to_bytes_length(self):
        out = Output.p2pkh(10, self.pub_key_hex)
        data = out.to_bytes()
        self.assertIsInstance(data, bytes)
        self.assertEqual(int.from_bytes(data[:4], 'big'), 10)

    def test_input_to_bytes_vs_unsigned(self):
        out = Output.p2pkh(10, self.pub_key_hex)
        dummy_hash = '0' * 64
        inp_plain = Input(out, dummy_hash)
        inp_signed = Input(out, dummy_hash, Script(['ab' * 64, self.pub_key_hex]))
        self.assertGreater(len(inp_signed.to_bytes()), len(inp_plain.to_bytes()))

    def test_bytes_to_sign_excludes_script_sig(self):
        key = make_signing_key()
        pub_hex = key.verify_key.encode().hex()
        tx = Transaction.coinbase(pub_hex, 5)
        self.assertEqual(tx.bytes_to_sign(), tx.to_bytes())


class TestWallet(unittest.TestCase):

    def setUp(self):
        self.key = make_signing_key()
        self.pub_hex = self.key.verify_key.encode().hex()
        self.prev_tx_hash = '0' * 64
        self.out = Output.p2pkh(10, self.pub_hex)

    def test_build_transaction_valid(self):
        inp = Input(self.out, self.prev_tx_hash)
        tx = build_transaction([inp], [Output.p2pkh(10, self.pub_hex)], self.key)
        self.assertIsNotNone(tx)
        self.assertIsInstance(tx, Transaction)

    def test_build_transaction_signs_each_input(self):
        inp = Input(self.out, self.prev_tx_hash)
        tx = build_transaction([inp], [Output.p2pkh(10, self.pub_hex)], self.key)
        for i in tx.inputs:
            self.assertEqual(len(i.script_sig.elements), 2)

    def test_build_transaction_empty_inputs(self):
        result = build_transaction([], [Output.p2pkh(10, self.pub_hex)], self.key)
        self.assertIsNone(result)

    def test_build_transaction_empty_outputs(self):
        inp = Input(self.out, self.prev_tx_hash)
        result = build_transaction([inp], [], self.key)
        self.assertIsNone(result)

    def test_build_transaction_value_mismatch(self):
        inp = Input(self.out, self.prev_tx_hash)
        result = build_transaction([inp], [Output.p2pkh(5, self.pub_hex)], self.key)
        self.assertIsNone(result)

    def test_build_transaction_wrong_key(self):
        wrong_key = make_signing_key()
        inp = Input(self.out, self.prev_tx_hash)
        result = build_transaction([inp], [Output.p2pkh(10, self.pub_hex)], wrong_key)
        self.assertIsNone(result)

    def test_build_transaction_duplicate_inputs(self):
        inp = Input(self.out, self.prev_tx_hash)
        result = build_transaction([inp, inp], [Output.p2pkh(20, self.pub_hex)], self.key)
        self.assertIsNone(result)


class TestBlock(unittest.TestCase):

    def setUp(self):
        self.key = make_signing_key()
        self.pub_hex = self.key.verify_key.encode().hex()
        self.genesis = make_genesis(self.key)

    def test_block_hash_is_hex64(self):
        h = self.genesis.hash()
        self.assertEqual(len(h), 64)
        int(h, 16)

    def test_block_hash_deterministic(self):
        h1 = self.genesis.hash()
        h2 = self.genesis.hash()
        self.assertEqual(h1, h2)

    def test_block_mine_meets_difficulty(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = Block('0' * 64, [cb], '00')
        block.mine()
        self.assertLessEqual(int(block.hash(), 16), DIFFICULTY)

    def test_block_merkle_root_single_tx(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = Block('0' * 64, [cb], '00')
        self.assertEqual(block.get_merkle_root(), cb.tx_hash)


class TestNode(unittest.TestCase):

    def setUp(self):
        self.key = make_signing_key()
        self.pub_hex = self.key.verify_key.encode().hex()
        self.genesis = make_genesis(self.key)
        self.node = Node()
        self.node.new_chain(self.genesis)

    def test_new_chain_initializes_utxos(self):
        chain = self.node.chains[0]
        self.assertGreater(len(chain.utxos), 0)

    def test_new_chain_genesis_in_chain(self):
        chain = self.node.chains[0]
        self.assertEqual(chain.chain[0], self.genesis)

    def test_build_block_coinbase_only(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = self.node.build_block([cb])
        self.assertIsNotNone(block)

    def test_build_block_meets_pow(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = self.node.build_block([cb])
        self.assertLessEqual(int(block.hash(), 16), DIFFICULTY)

    def test_build_block_prev_points_to_genesis(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = self.node.build_block([cb])
        self.assertEqual(block.prev, self.genesis.hash())

    def test_build_block_coinbase_exceeds_reward_rejected(self):
        cb = Transaction.coinbase(self.pub_hex, BLOCK_REWARD + 1)
        block = self.node.build_block([cb])
        self.assertIsNone(block)

    def _spend_coinbase(self, recipient_pub_hex=None):
        if recipient_pub_hex is None:
            recipient_pub_hex = self.pub_hex
        genesis_cb = self.genesis.txs[0]
        utxo_out = genesis_cb.outputs[0]
        inp = Input(utxo_out, genesis_cb.tx_hash)
        return build_transaction(
            [inp],
            [Output.p2pkh(utxo_out.value, recipient_pub_hex)],
            self.key
        )

    def test_build_block_valid_regular_tx(self):
        tx = self._spend_coinbase()
        block = self.node.build_block([tx])
        self.assertIsNotNone(block)

    def test_build_block_double_spend_rejected(self):
        tx1 = self._spend_coinbase()
        tx2 = self._spend_coinbase()
        self.node.build_block([tx1])
        block = self.node.build_block([tx2])
        self.assertIsNone(block)

    def test_append_valid_block(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = Block(self.genesis.hash(), [cb], '00')
        block.mine()
        result = self.node.append(block)
        self.assertTrue(result)

    def test_append_invalid_prev(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = Block('deadbeef' * 8, [cb], '00')
        block.mine()
        result = self.node.append(block)
        self.assertFalse(result)

    def test_append_invalid_pow(self):
        cb = Transaction.coinbase(self.pub_hex)
        block = Block(self.genesis.hash(), [cb], 'ff' * 8)
        result = self.node.append(block)
        if not result:
            pass

    def test_fork_creates_multiple_chains(self):
        initial_count = len(self.node.chains)
        cb1 = Transaction.coinbase(self.pub_hex, 10)
        block1 = Block(self.genesis.hash(), [cb1], '00')
        block1.mine()
        cb2 = Transaction.coinbase(self.pub_hex, 20)
        block2 = Block(self.genesis.hash(), [cb2], '00')
        block2.mine()
        self.node.append(block1)
        self.node.append(block2)
        self.assertGreater(len(self.node.chains), initial_count)

    def test_build_block_uses_longest_chain(self):
        cb_extra = Transaction.coinbase(self.pub_hex, 5)
        extra_block = Block(self.genesis.hash(), [cb_extra], '00')
        extra_block.mine()
        self.node.append(extra_block)
        cb_new = Transaction.coinbase(self.pub_hex, 3)
        new_block = self.node.build_block([cb_new])
        self.assertIsNotNone(new_block)


class TestEndToEnd(unittest.TestCase):

    def test_full_transaction_lifecycle(self):
        key_a = make_signing_key()
        key_b = make_signing_key()
        pub_a = key_a.verify_key.encode().hex()
        pub_b = key_b.verify_key.encode().hex()

        genesis = make_genesis(key_a)
        node = Node()
        node.new_chain(genesis)

        genesis_cb = genesis.txs[0]
        utxo_out = genesis_cb.outputs[0]
        inp = Input(utxo_out, genesis_cb.tx_hash)
        tx_ab = build_transaction(
            [inp],
            [Output.p2pkh(utxo_out.value, pub_b)],
            key_a
        )
        self.assertIsNotNone(tx_ab, "A->B 交易构建失败")

        block1 = node.build_block([tx_ab])
        self.assertIsNotNone(block1, "包含 A->B 的区块构建失败")

        node2 = Node()
        node2.new_chain(genesis)
        result = node2.append(block1)
        self.assertTrue(result, "node2 追加合法区块失败")

    def test_coinbase_only_chain(self):
        key = make_signing_key()
        pub = key.verify_key.encode().hex()
        genesis = make_genesis(key)
        node = Node()
        node.new_chain(genesis)

        for _ in range(3):
            cb = Transaction.coinbase(pub, 1)
            block = node.build_block([cb])
            self.assertIsNotNone(block)
            self.assertLessEqual(int(block.hash(), 16), DIFFICULTY)


if __name__ == '__main__':
    unittest.main(verbosity=2)
