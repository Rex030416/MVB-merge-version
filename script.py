import hashlib
from typing import List
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

"""
Bitcoin Script implementation for P2PKH (Pay to Public Key Hash).

This is a simplified, educational version using human-readable opcodes.

=== ASSIGNMENT STRUCTURE ===

REQUIRED: Implement verify_p2pkh() - a simple, direct validation function
          that checks P2PKH transactions without stack manipulation.

EXTRA CREDIT: Implement ScriptInterpreter - a full stack-based script
              interpreter that can execute Bitcoin-like scripts.
"""

# Opcodes (simplified, human-readable)
OP_DUP = 'OP_DUP'
OP_SHA256 = 'OP_SHA256'
OP_EQUALVERIFY = 'OP_EQUALVERIFY'
OP_CHECKSIG = 'OP_CHECKSIG'

# Set of all opcodes for easy checking
OPCODES = {OP_DUP, OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG}


def sha256_hash(data: bytes) -> bytes:
    """
    SHA256 hash for public keys.

    This is used to create the public key hash in P2PKH transactions.
    (Bitcoin uses RIPEMD160(SHA256), but we use plain SHA256 for simplicity.)
    """
    return hashlib.sha256(data).digest()


def verify_p2pkh(signature: bytes, pubkey: bytes, expected_pubkey_hash: bytes, tx_data: bytes) -> bool:
    """
    [REQUIRED] Verify a P2PKH transaction directly without stack manipulation.

    This is a simplified validation that checks:
    1. The public key hashes to the expected hash (SHA256(pubkey) == expected_pubkey_hash)
    2. The signature is valid for the given transaction data

    Args:
        signature: The signature bytes from scriptSig
        pubkey: The public key bytes from scriptSig
        expected_pubkey_hash: The pubkey hash from scriptPubKey (what the funds are locked to)
        tx_data: The transaction data that was signed

    Returns:
        True if validation passes, False otherwise
    """
    # Step 1: Check that sha256_hash(pubkey) == expected_pubkey_hash
    if sha256_hash(pubkey) != expected_pubkey_hash:
        return False
    # Step 2: Verify the signature using VerifyKey
    try:
        VerifyKey(pubkey).verify(tx_data, signature)
        return True
    except BadSignatureError:
        return False


class Script:
    """
    A Bitcoin script - a list of opcodes and data pushes.

    Data elements are hex strings, opcodes are string constants (OP_*).
    Elements that are not opcodes are treated as data to push onto the stack.
    """

    def __init__(self, elements: List[str]):
        self.elements = elements

    def to_bytes(self) -> bytes:
        """
        Serialize the script to bytes for hashing.

        Each element is converted to bytes and concatenated:
        - Opcodes are encoded as their string representation (UTF-8)
        - Data elements (hex strings) are converted to bytes
        """
        result = b''
        for element in self.elements:
            if element in OPCODES:
                result += element.encode('utf-8')
            else:
                result += bytes.fromhex(element)
        return result

    @staticmethod
    def p2pkh_locking_script(pub_key_hash: str) -> 'Script':
        """
        Create a P2PKH locking script (scriptPubKey).

        Format: OP_DUP OP_SHA256 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG

        This script locks funds to a public key hash. To spend, the spender
        must provide a signature and public key that hashes to this value.
        """
        return Script([OP_DUP, OP_SHA256, pub_key_hash, OP_EQUALVERIFY, OP_CHECKSIG])

    @staticmethod
    def p2pkh_unlocking_script(signature: str, pub_key: str) -> 'Script':
        """
        Create a P2PKH unlocking script (scriptSig).

        Format: <signature> <pubKey>

        This script provides the signature and public key needed to unlock
        a P2PKH output.
        """
        return Script([signature, pub_key])

    def __repr__(self):
        return f"Script({self.elements})"


class ScriptInterpreter:
    """
    [EXTRA CREDIT] Full stack-based Bitcoin script interpreter.

    Executes Bitcoin scripts on a stack. The interpreter processes each element:
    - Opcodes trigger operations on the stack
    - Data elements are pushed onto the stack

    For P2PKH, the combined script (scriptSig + scriptPubKey) executes as:
    1. Push signature (from scriptSig)
    2. Push pubKey (from scriptSig)
    3. OP_DUP: Duplicate pubKey -> stack: [sig, pubKey, pubKey]
    4. OP_SHA256: Hash top element -> stack: [sig, pubKey, pubKeyHash]
    5. Push expected pubKeyHash (from scriptPubKey) -> stack: [sig, pubKey, pubKeyHash, expectedHash]
    6. OP_EQUALVERIFY: Pop two, verify equal -> stack: [sig, pubKey]
    7. OP_CHECKSIG: Verify signature -> stack: [true/false]

    The script succeeds if the stack is non-empty and the top value is truthy.
    """

    def __init__(self):
        self.stack: List[bytes] = []

    def execute(self, script: Script, tx_data: bytes) -> bool:
        """
        Execute a script. tx_data is used for OP_CHECKSIG.

        Returns True if script succeeds (stack top is truthy), False otherwise.

        Process each element in the script:
        - If it's an opcode, execute the corresponding operation
        - If it's data (hex string), push it onto the stack

        The script succeeds if:
        - No errors occurred during execution
        - The stack is non-empty
        - The top of the stack is truthy (not empty or zero)
        """
        # Reset stack so that this interpreter instance can be safely reused
        # across multiple execute() calls without leaking state.
        self.stack = []
        try:
            for element in script.elements:
                if element == OP_DUP:
                    self._op_dup()
                elif element == OP_SHA256:
                    self._op_sha256()
                elif element == OP_EQUALVERIFY:
                    if not self._op_equalverify():
                        return False
                elif element == OP_CHECKSIG:
                    self._op_checksig(tx_data)
                else:
                    # Data element (hex string) — push as bytes
                    self.stack.append(bytes.fromhex(element))
            # Script succeeds if stack is non-empty and top is truthy
            return len(self.stack) > 0 and self.stack[-1] != b'\x00' and self.stack[-1] != b''
        except Exception:
            return False

    def _op_dup(self):
        """
        OP_DUP: Duplicate the top stack element.

        Stack: [..., a] -> [..., a, a]
        Raises IndexError (caught by execute) if stack is empty.
        """
        self.stack.append(self.stack[-1])

    def _op_sha256(self):
        """
        OP_SHA256: Replace top element with SHA256(element).

        Stack: [..., data] -> [..., sha256(data)]
        """
        data = self.stack.pop()
        self.stack.append(sha256_hash(data))

    def _op_equalverify(self) -> bool:
        """
        OP_EQUALVERIFY: Check top two elements are equal.

        Stack: [..., a, b] -> [...]
        Returns False if a != b, True if a == b.

        Note: This operation removes both elements from the stack.
        """
        b = self.stack.pop()
        a = self.stack.pop()
        return a == b

    def _op_checksig(self, tx_data: bytes):
        """
        OP_CHECKSIG: Verify signature against public key and tx_data.

        Stack: [..., signature, pubKey] -> [..., result]

        Pops pubKey first (top of stack), then signature.
        Pushes b'\\x01' (true) if valid, b'\\x00' (false) if invalid.
        Any exception during verification (bad key format, bad signature, etc.)
        is treated as a failed verification rather than a fatal error, so the
        script can continue executing and the final truthy check will fail.
        """
        pubkey = self.stack.pop()
        signature = self.stack.pop()
        try:
            VerifyKey(pubkey).verify(tx_data, signature)
            self.stack.append(b'\x01')
        except Exception:
            # Catches BadSignatureError AND ValueError (malformed pubkey length)
            self.stack.append(b'\x00')
