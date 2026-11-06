"""Dummy application code: the Q-Shield code scanner should flag this file."""
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def make_keys():
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    exchange_key = ec.generate_private_key(ec.SECP256R1())
    return signing_key, exchange_key
