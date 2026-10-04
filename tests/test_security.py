import os
import hashlib
import pytest

from cryptography.exceptions import InvalidSignature

from handshake import (
    make_rsa_key,
    handshake,
    sign,
    verify,
    build_transcript,
    decode_transcript,
    GATEWAY_ROLE,
    NODE_ROLE
)

from secure_record import (
    make_sender,
    make_receiver,
    seal,
    open_record,
    GATEWAY_TO_NODE,
    NODE_TO_GATEWAY
)


def setup_session():
    gateway_rsa = make_rsa_key()
    node_rsa = make_rsa_key()

    result = handshake(
        gateway_rsa,
        node_rsa
    )

    keys = result["keys"]
    session_id = keys["session_id"]

    gateway_sender = make_sender(
        keys["K_g2n_enc"],
        keys["K_g2n_mac"],
        session_id,
        GATEWAY_TO_NODE
    )

    node_receiver = make_receiver(
        keys["K_g2n_enc"],
        keys["K_g2n_mac"],
        session_id,
        GATEWAY_TO_NODE
    )

    node_sender = make_sender(
        keys["K_n2g_enc"],
        keys["K_n2g_mac"],
        session_id,
        NODE_TO_GATEWAY
    )

    gateway_receiver = make_receiver(
        keys["K_n2g_enc"],
        keys["K_n2g_mac"],
        session_id,
        NODE_TO_GATEWAY
    )

    return (
        gateway_sender,
        node_receiver,
        node_sender,
        gateway_receiver
    )


def test_valid_handshake_and_messages():
    gateway_sender, node_receiver, node_sender, gateway_receiver = setup_session()

    record1 = seal(
        gateway_sender,
        b"hello node"
    )

    plaintext1, message_type1 = open_record(
        node_receiver,
        record1
    )

    assert plaintext1 == b"hello node"
    assert message_type1 == 1

    record2 = seal(
        node_sender,
        b"hello gateway"
    )

    plaintext2, message_type2 = open_record(
        gateway_receiver,
        record2
    )

    assert plaintext2 == b"hello gateway"
    assert message_type2 == 1


def test_modified_ciphertext_rejected():
    gateway_sender, node_receiver, _, _ = setup_session()

    record = seal(
        gateway_sender,
        b"hello node"
    )

    modified = bytearray(record)

    modified[31] ^= 1

    with pytest.raises(ValueError, match="Invalid MAC"):
        open_record(
            node_receiver,
            bytes(modified)
        )


def test_modified_header_rejected():
    gateway_sender, node_receiver, _, _ = setup_session()

    record = seal(
        gateway_sender,
        b"hello node"
    )

    modified = bytearray(record)

    modified[0] ^= 1

    with pytest.raises(ValueError, match="Invalid MAC"):
        open_record(
            node_receiver,
            bytes(modified)
        )


def test_replay_rejected():
    gateway_sender, node_receiver, _, _ = setup_session()

    record = seal(
        gateway_sender,
        b"hello node"
    )

    plaintext, message_type = open_record(
        node_receiver,
        record
    )

    assert plaintext == b"hello node"

    with pytest.raises(ValueError, match="Invalid sequence number"):
        open_record(
            node_receiver,
            record
        )


def test_reflected_record_rejected():
    gateway_sender, _, _, gateway_receiver = setup_session()

    record = seal(
        gateway_sender,
        b"hello node"
    )

    with pytest.raises(ValueError, match="Invalid MAC"):
        open_record(
            gateway_receiver,
            record
        )


def test_wrong_rsa_key_rejected():
    gateway_rsa = make_rsa_key()
    wrong_rsa = make_rsa_key()

    transcript_hash = hashlib.sha256(
        b"test transcript"
    ).digest()

    signature = sign(
        gateway_rsa,
        GATEWAY_ROLE,
        transcript_hash
    )

    with pytest.raises(InvalidSignature):
        verify(
            wrong_rsa.public_key(),
            GATEWAY_ROLE,
            transcript_hash,
            signature
        )


def test_changed_nonce_rejected():
    gateway_rsa = make_rsa_key()

    gateway_public = os.urandom(384)
    node_public = os.urandom(384)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    )

    transcript_hash = hashlib.sha256(
        transcript
    ).digest()

    signature = sign(
        gateway_rsa,
        GATEWAY_ROLE,
        transcript_hash
    )

    changed_nonce = bytearray(node_nonce)
    changed_nonce[0] ^= 1

    changed_transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        bytes(changed_nonce)
    )

    changed_hash = hashlib.sha256(
        changed_transcript
    ).digest()

    with pytest.raises(InvalidSignature):
        verify(
            gateway_rsa.public_key(),
            GATEWAY_ROLE,
            changed_hash,
            signature
        )


def test_changed_public_value_rejected():
    gateway_rsa = make_rsa_key()

    gateway_public = os.urandom(384)
    node_public = os.urandom(384)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    )

    transcript_hash = hashlib.sha256(
        transcript
    ).digest()

    signature = sign(
        gateway_rsa,
        GATEWAY_ROLE,
        transcript_hash
    )

    changed_public = bytearray(node_public)
    changed_public[0] ^= 1

    changed_transcript = build_transcript(
        gateway_public,
        bytes(changed_public),
        gateway_nonce,
        node_nonce
    )

    changed_hash = hashlib.sha256(
        changed_transcript
    ).digest()

    with pytest.raises(InvalidSignature):
        verify(
            gateway_rsa.public_key(),
            GATEWAY_ROLE,
            changed_hash,
            signature
        )


def test_reflected_handshake_rejected():
    gateway_rsa = make_rsa_key()

    transcript_hash = hashlib.sha256(
        b"test transcript"
    ).digest()

    signature = sign(
        gateway_rsa,
        GATEWAY_ROLE,
        transcript_hash
    )

    with pytest.raises(InvalidSignature):
        verify(
            gateway_rsa.public_key(),
            NODE_ROLE,
            transcript_hash,
            signature
        )


def test_malformed_transcript_rejected():
    gateway_public = os.urandom(384)
    node_public = os.urandom(384)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    )

    malformed = bytearray(transcript)

    malformed[0:4] = (999999).to_bytes(
        4,
        "big"
    )

    with pytest.raises(ValueError, match="Malformed transcript"):
        decode_transcript(
            bytes(malformed)
        )


def test_unexpected_identity_rejected():
    gateway_rsa = make_rsa_key()
    node_rsa = make_rsa_key()

    with pytest.raises(ValueError, match="Unexpected node identity"):
        handshake(
            gateway_rsa,
            node_rsa,
            expected_node_id=b"attacker"
        )
