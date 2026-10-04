import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def relay(ciphertext):
    original = b"READ"
    replacement = b"ECHO"

    index = len(b'{"action":"')
    modified = bytearray(ciphertext)

    print("\nXOR:")

    for i in range(len(original)):
        difference = original[i] ^ replacement[i]

        print(
            chr(original[i]),
            "XOR",
            chr(replacement[i]),
            "=",
            hex(difference)
        )

        modified[index + i] ^= difference

    return bytes(modified)


def receiver(key, iv, ciphertext):
    plaintext = decrypt(key, iv, ciphertext)

    print("Receiver processed:")
    print(plaintext)


def main():
    plaintext = b'{"action":"READ","path":"notes.txt"}'

    key = os.urandom(32)
    iv = os.urandom(16)

    ciphertext = encrypt(key, iv, plaintext)
    decrypted = decrypt(key, iv, ciphertext)

    print("Original plaintext:")
    print(plaintext)

    print("\nOriginal ciphertext:")
    print(ciphertext.hex())

    print("\nOriginal decrypted ciphertext:")
    print(decrypted)

    modifiedCiphertext = relay(ciphertext)

    print("\nTampered ciphertext:")
    print(modifiedCiphertext.hex())

    print("\nTampered ciphertext decrypted:")
    print(decrypt(key, iv, modifiedCiphertext))

    print("\nReplay:")

    receiver(key, iv, ciphertext)
    receiver(key, iv, ciphertext)
    print("No replay protection as the same ciphertext is accepted and decrypted twice")

if __name__ == "__main__":
    main()
