from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature

from handshake import make_rsa_key, handshake


VERSION = 1

GATEWAY_TO_NODE = 0
NODE_TO_GATEWAY = 1


def make_sender(enc_key, mac_key, session_id, direction):
    if len(session_id) != 8:
        raise ValueError("Invalid session ID")

    return {
        "enc_key": enc_key,
        "mac_key": mac_key,
        "session_id": session_id,
        "direction": direction,
        "sequence": 0
    }


def make_receiver(enc_key, mac_key, session_id, direction):
    if len(session_id) != 8:
        raise ValueError("Invalid session ID")

    return {
        "enc_key": enc_key,
        "mac_key": mac_key,
        "session_id": session_id,
        "direction": direction,
        "sequence": 0
    }


def encrypt(key, iv, plaintext):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv)
    )

    encryptor = cipher.encryptor()

    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt(key, iv, ciphertext):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv)
    )

    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def make_tag(key, data):
    mac = hmac.HMAC(
        key,
        hashes.SHA256()
    )

    mac.update(data)

    return mac.finalize()


def verify_tag(key, data, tag):
    mac = hmac.HMAC(
        key,
        hashes.SHA256()
    )

    mac.update(data)

    try:
        mac.verify(tag)

    except InvalidSignature:
        raise ValueError("Invalid MAC")


def seal(sender, plaintext, message_type=1):
    sequence = sender["sequence"]

    if sequence >= 2 ** 64:
        raise ValueError("Sequence number too large")

    if message_type < 0 or message_type > 255:
        raise ValueError("Invalid message type")

    sequence_bytes = sequence.to_bytes(8, "big")

    iv = sender["session_id"] + sequence_bytes

    ciphertext = encrypt(
        sender["enc_key"],
        iv,
        plaintext
    )

    header = (
        VERSION.to_bytes(1, "big")
        + sender["direction"].to_bytes(1, "big")
        + sequence_bytes
        + message_type.to_bytes(1, "big")
        + len(ciphertext).to_bytes(4, "big")
    )

    tag = make_tag(
        sender["mac_key"],
        header + iv + ciphertext
    )

    sender["sequence"] += 1

    return header + iv + ciphertext + tag


def open_record(receiver, record):
    header_length = 15
    iv_length = 16
    tag_length = 32

    minimum_length = (
        header_length
        + iv_length
        + tag_length
    )

    if len(record) < minimum_length:
        raise ValueError("Malformed record")

    header = record[:header_length]

    iv = record[
        header_length:
        header_length + iv_length
    ]

    ciphertext = record[
        header_length + iv_length:
        -tag_length
    ]

    tag = record[-tag_length:]

    verify_tag(
        receiver["mac_key"],
        header + iv + ciphertext,
        tag
    )

    version = header[0]
    direction = header[1]

    sequence = int.from_bytes(
        header[2:10],
        "big"
    )

    message_type = header[10]

    ciphertext_length = int.from_bytes(
        header[11:15],
        "big"
    )

    if version != VERSION:
        raise ValueError("Invalid version")

    if direction != receiver["direction"]:
        raise ValueError("Invalid direction")

    if sequence != receiver["sequence"]:
        raise ValueError("Invalid sequence number")

    if ciphertext_length != len(ciphertext):
        raise ValueError("Invalid ciphertext length")

    expected_iv = (
        receiver["session_id"]
        + sequence.to_bytes(8, "big")
    )

    if iv != expected_iv:
        raise ValueError("Invalid IV")

    plaintext = decrypt(
        receiver["enc_key"],
        iv,
        ciphertext
    )

    receiver["sequence"] += 1

    return plaintext, message_type


def main():
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

    message1 = b"hello node"

    record1 = seal(
        gateway_sender,
        message1
    )

    plaintext1, type1 = open_record(
        node_receiver,
        record1
    )

    print("Gateway to node:")
    print(plaintext1)

    print("\nMessage type:")
    print(type1)

    print("\nGateway sequence:")
    print(gateway_sender["sequence"])

    print("\nNode expected sequence:")
    print(node_receiver["sequence"])

    message2 = b"hello gateway"

    record2 = seal(
        node_sender,
        message2
    )

    plaintext2, type2 = open_record(
        gateway_receiver,
        record2
    )

    print("\nNode to gateway:")
    print(plaintext2)

    print("\nMessage type:")
    print(type2)

    print("\nNode sequence:")
    print(node_sender["sequence"])

    print("\nGateway expected sequence:")
    print(gateway_receiver["sequence"])


if __name__ == "__main__":
    main()
