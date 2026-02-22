from typing import List, Optional
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

from script import Script, sha256_hash
from transaction import Input, Output, Transaction

"""
Wallet functionality for building and signing transactions.
"""


def build_transaction(inputs: List[Input], outputs: List[Output], signing_key: SigningKey) -> Optional[Transaction]:
    """
    Build and sign a transaction with the given inputs and outputs.

    This creates P2PKH unlocking scripts (scriptSig) for each input.
    Returns None if impossible to build a valid transaction.
    Does not verify that inputs are unspent.

    Validation checks:
    - Inputs and outputs must not be empty
    - All inputs must be spendable by the signing key (pub_key_hash matches)
    - Input values must equal output values
    - No duplicate inputs (same txid + same output)

    Steps:
    1. Validate inputs and outputs
    2. Check that the signing key can spend all inputs
    3. Create an unsigned transaction (empty scriptSigs)
    4. Sign the transaction data
    5. Create scriptSig for each input with signature and public key
    6. Return the signed transaction
    """
    # Validate inputs and outputs not empty
    if not inputs or not outputs:
        return None

    # No duplicate inputs: identify each input by (tx_hash, output_bytes).
    # Two inputs with the same tx_hash but different outputs are VALID (spending
    # two outputs from the same transaction), so we must include the output
    # content in the identity check rather than comparing tx_hash alone.
    input_ids = [(inp.tx_hash, inp.output.to_bytes()) for inp in inputs]
    if len(input_ids) != len(set(input_ids)):
        return None

    # Get public key and its hash
    pub_key = signing_key.verify_key.encode()
    pub_key_hash = sha256_hash(pub_key)

    # All inputs must be spendable by the signing key
    for inp in inputs:
        expected_hash = bytes.fromhex(inp.output.script_pubkey.elements[2])
        if pub_key_hash != expected_hash:
            return None

    # Input values must equal output values
    input_total = sum(inp.output.value for inp in inputs)
    output_total = sum(out.value for out in outputs)
    if input_total != output_total:
        return None

    # Create unsigned transaction to get bytes to sign
    unsigned_tx = Transaction(inputs, outputs)
    tx_data = bytes.fromhex(unsigned_tx.bytes_to_sign())

    # Sign the transaction data
    sig = signing_key.sign(tx_data).signature
    sig_hex = sig.hex()
    pub_key_hex = pub_key.hex()

    # Create signed inputs with scriptSig
    signed_inputs = []
    for inp in inputs:
        script_sig = Script.p2pkh_unlocking_script(sig_hex, pub_key_hex)
        signed_inputs.append(Input(inp.output, inp.tx_hash, script_sig))

    return Transaction(signed_inputs, outputs)
