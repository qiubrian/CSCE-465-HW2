import os
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh


PROTOCOL = b"CSCE465-HS-v2"
GROUP = b"ffdhe3072"

GATEWAY_ID = b"gateway"
NODE_ID = b"node"

GATEWAY_ROLE = b"gateway"
NODE_ROLE = b"node"


def encode_field(data):
    return len(data).to_bytes(4, "big") + data


def decode_transcript(transcript):
    fields = []
    index = 0

    for i in range(8):
        if index + 4 > len(transcript):
            raise ValueError("Malformed transcript")

        length = int.from_bytes(transcript[index:index + 4], "big")
        index += 4

        if index + length > len(transcript):
            raise ValueError("Malformed transcript")

        field = transcript[index:index + length]
        fields.append(field)

        index += length

    if index != len(transcript):
        raise ValueError("Malformed transcript")

    return fields


def public_to_bytes(public_key):
    y = public_key.public_numbers().y
    return y.to_bytes(384, "big")


def build_transcript(
    gateway_public,
    node_public,
    gateway_nonce,
    node_nonce
):
    fields = [
        PROTOCOL,
        GROUP,
        GATEWAY_ID,
        NODE_ID,
        gateway_public,
        node_public,
        gateway_nonce,
        node_nonce
    ]

    transcript = b""

    for field in fields:
        transcript += encode_field(field)

    decode_transcript(transcript)

    return transcript


def make_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )


def sign(private_key, role, transcript_hash):
    return private_key.sign(
        role + transcript_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(public_key, role, transcript_hash, signature):
    public_key.verify(
        signature,
        role + transcript_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def hmac_sha256(key, data):
    return hmac.new(
        key,
        data,
        hashlib.sha256
    ).digest()


def derive_keys(shared_secret, transcript_hash):
    master = hashlib.sha256(
        b"CSCE465-KDF-v1"
        + shared_secret
        + transcript_hash
    ).digest()

    g2n_enc = hmac_sha256(
        master,
        b"gateway-to-node encryption" + transcript_hash
    )

    g2n_mac = hmac_sha256(
        master,
        b"gateway-to-node MAC" + transcript_hash
    )

    n2g_enc = hmac_sha256(
        master,
        b"node-to-gateway encryption" + transcript_hash
    )

    n2g_mac = hmac_sha256(
        master,
        b"node-to-gateway MAC" + transcript_hash
    )

    session_id = hmac_sha256(
        master,
        b"session identifier" + transcript_hash
    )[:8]

    return {
        "K_master": master,
        "K_g2n_enc": g2n_enc,
        "K_g2n_mac": g2n_mac,
        "K_n2g_enc": n2g_enc,
        "K_n2g_mac": n2g_mac,
        "session_id": session_id
    }


def load_parameters():
    with open("ffdhe3072.pem", "rb") as file:
        data = file.read()

    return serialization.load_pem_parameters(data)


def handshake(
    gateway_rsa,
    node_rsa,
    expected_gateway_id=b"gateway",
    expected_node_id=b"node"
):
    if expected_gateway_id != GATEWAY_ID:
        raise ValueError("Unexpected gateway identity")

    if expected_node_id != NODE_ID:
        raise ValueError("Unexpected node identity")

    parameters = load_parameters()

    gateway_dh_private = parameters.generate_private_key()
    node_dh_private = parameters.generate_private_key()

    gateway_dh_public = gateway_dh_private.public_key()
    node_dh_public = node_dh_private.public_key()

    gateway_public_bytes = public_to_bytes(gateway_dh_public)
    node_public_bytes = public_to_bytes(node_dh_public)

    gateway_nonce = os.urandom(16)
    node_nonce = os.urandom(16)

    transcript = build_transcript(
        gateway_public_bytes,
        node_public_bytes,
        gateway_nonce,
        node_nonce
    )

    fields = decode_transcript(transcript)

    if fields[0] != PROTOCOL:
        raise ValueError("Invalid protocol")

    if fields[1] != GROUP:
        raise ValueError("Invalid group")

    if fields[2] != expected_gateway_id:
        raise ValueError("Unexpected gateway identity")

    if fields[3] != expected_node_id:
        raise ValueError("Unexpected node identity")

    transcript_hash = hashlib.sha256(transcript).digest()

    gateway_signature = sign(
        gateway_rsa,
        GATEWAY_ROLE,
        transcript_hash
    )

    node_signature = sign(
        node_rsa,
        NODE_ROLE,
        transcript_hash
    )

    verify(
        gateway_rsa.public_key(),
        GATEWAY_ROLE,
        transcript_hash,
        gateway_signature
    )

    verify(
        node_rsa.public_key(),
        NODE_ROLE,
        transcript_hash,
        node_signature
    )

    gateway_shared = gateway_dh_private.exchange(
        node_dh_public
    )

    node_shared = node_dh_private.exchange(
        gateway_dh_public
    )

    gateway_shared = int.from_bytes(
        gateway_shared,
        "big"
    ).to_bytes(384, "big")

    node_shared = int.from_bytes(
        node_shared,
        "big"
    ).to_bytes(384, "big")

    if gateway_shared != node_shared:
        raise ValueError("Shared secrets do not match")

    gateway_keys = derive_keys(
        gateway_shared,
        transcript_hash
    )

    node_keys = derive_keys(
        node_shared,
        transcript_hash
    )

    if gateway_keys != node_keys:
        raise ValueError("Derived keys do not match")

    return {
        "transcript": transcript,
        "transcript_hash": transcript_hash,
        "gateway_signature": gateway_signature,
        "node_signature": node_signature,
        "gateway_nonce": gateway_nonce,
        "node_nonce": node_nonce,
        "keys": gateway_keys
    }


def main():
    gateway_rsa = make_rsa_key()
    node_rsa = make_rsa_key()

    result = handshake(
        gateway_rsa,
        node_rsa
    )

    print("Handshake successful")

    print("\nTranscript hash:")
    print(result["transcript_hash"].hex())

    print("\nGateway nonce:")
    print(result["gateway_nonce"].hex())

    print("\nNode nonce:")
    print(result["node_nonce"].hex())

    print("\nK_g2n_enc:")
    print(result["keys"]["K_g2n_enc"].hex())

    print("\nK_g2n_mac:")
    print(result["keys"]["K_g2n_mac"].hex())

    print("\nK_n2g_enc:")
    print(result["keys"]["K_n2g_enc"].hex())

    print("\nK_n2g_mac:")
    print(result["keys"]["K_n2g_mac"].hex())

    print("\nSession ID:")
    print(result["keys"]["session_id"].hex())


if __name__ == "__main__":
    main()
