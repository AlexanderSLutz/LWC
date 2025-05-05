import struct, os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from lutz_functions import *
from ascon import *




# === AES CBC ===
def encrypt_AES_CBC(can_message: bytes, key: bytes, iv_length = 16) -> bytes:
    """
    Encrypts a CAN message using AES encryption in CBC mode.
    
    The longer the IV length, the more secure, but less actual data able to be sent through
    IV length should be either 0, 8, or 16 bytes
    """
    
    iv = os.urandom(iv_length)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) 
    encryptor = cipher.encryptor()
    # Ensure the CAN message is padded to 16-byte alignment
    # If CAN message is a clean multiple of 16 bytes, the message will still be padded with an additional 16 bytes due to PKCS7
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(can_message) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    
    # Return the IV + encrypted message as a hex string
    return iv + encrypted_message

def decrypt_AES_CBC(encrypted_message: str, key: bytes, iv_length = 16) -> bytes:
    """
    Decrypts an AES-encrypted CAN message.
    """
    
    iv = encrypted_message[:iv_length]  # Extract IV
    encrypted_data = encrypted_message[iv_length:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_data) + decryptor.finalize()
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    
    return decrypted_message

# === AES GCM ===
def encrypt_AES_GCM(plaintext: bytes, key: bytes, associated_data: bytes = b'') -> bytes:
    """
    Encrypts a message using AES-GCM and packs it for a CAN-FD frame.
    Output: nonce (12) + ciphertext + tag (16) <= 64 bytes
    """
    nonce_len = 12
    tag_len = 16
    
    assert len(key) in [16, 24, 32], "Key must be 128, 192, or 256 bits"
    assert len(plaintext) <= 64 - nonce_len - tag_len, "Plaintext too long for one CAN-FD frame"


    nonce = os.urandom(nonce_len)
    aesgcm = AESGCM(key)
    full_ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return nonce + full_ciphertext


def decrypt_AES_GCM(payload: bytes, key: bytes, associated_data: bytes = b'') -> bytes:
    """
    Decrypts a CAN-FD frame encrypted with AES-GCM.
    Input: payload = nonce (12) + ciphertext + tag (16)
    Returns: plaintext (or raises if tag invalid)
    """
    nonce_len = 12
    tag_len = 16

    assert len(key) in [16, 24, 32], "Key must be 128, 192, or 256 bits"
    assert len(payload) <= 64, "Payload exceeds CAN-FD frame size"
    assert len(payload) >= nonce_len + tag_len, "Payload too short"
    
    if payload[-1] == b"\x00":
        payload = strip_nulls_if_two_or_more(payload)

    nonce = payload[:nonce_len]
    # print(f"nonce: {nonce}")
    ciphertext = payload[nonce_len:-tag_len]
    tag = payload[-tag_len:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)

# === Blowfish ===
def encrypt_blowfish(data: bytes, key: bytes, iv_length: int) -> bytes:
    iv = os.urandom(iv_length)
    algorithm = decrepit_algorithms.Blowfish(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext
    padder = padding.PKCS7(algorithm.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_blowfish(frame: bytes, key: bytes, iv_length: int) -> bytes:
    iv = frame[:iv_length]
    ciphertext = frame[iv_length:]
    algorithm = decrepit_algorithms.Blowfish(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# === TripleDES ===
def encrypt_3DES(data: bytes, key: bytes, iv_len: int):
    iv = os.urandom(iv_len)
    algorithm = decrepit_algorithms.TripleDES(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(64).padder()  # 64 bits = 8 bytes block size
    padded_data = padder.update(data) + padder.finalize()
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Prepend IV to the ciphertext

def decrypt_3DES(ct: bytes, key: bytes, iv_len: int):
    iv = ct[:iv_len]
    ciphertext = ct[iv_len:]
    algorithm = decrepit_algorithms.TripleDES(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


# === Camellia ===
def encrypt_camellia(data: bytes, key: bytes, iv_len: int):
    iv = os.urandom(iv_len)
    algorithm = algorithms.Camellia(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithm.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    ct = encryptor.update(padded) + encryptor.finalize()
    return iv + ct

def decrypt_camellia(ct: bytes, key: bytes, iv_len: int):
    iv = ct[:iv_len]              # First 16 bytes = IV
    ct = ct[iv_len:]              # The rest is the ciphertext
    algorithm = algorithms.Camellia(key)
    cipher = Cipher(algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    unpadded =  unpadder.update(padded) + unpadder.finalize()
    return unpadded


# === ChaCha20 ===
def encrypt_chacha20(data: bytes, key: bytes, full_nonce_len: int, counter: int):
    nonce = b'8\x93\xf9\xf5\x08v\xb1\xd4' # acutal generated nonce only accounts for 8 bytes, counter usees the first 8 bytes then append gen nonce
    full_nonce = struct.pack("<Q", counter) + nonce
    algorithm = algorithms.ChaCha20(key, full_nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(data)
    return full_nonce + ct, counter

def decrypt_chacha20(ct: bytes, key: bytes, full_nonce_len: int):
    nonce = ct[:full_nonce_len]     # First 16 bytes = nonce
    ct = ct[full_nonce_len:]        # The rest is the ciphertext
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ct)


# === Ascon ===
def encrypt_ascon128(plaintext: bytes, key: bytes, associated_data: bytes = b'') -> bytes:
    """
    Encrypts a plaintext message for a single CAN-FD frame (max 64 bytes total).
    Returns: payload = nonce (16) + ciphertext + tag (16)
    """

    nonce = os.urandom(16)
    ct_and_tag = ascon_encrypt(key, nonce, associated_data, plaintext)
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    return nonce + ciphertext + tag

def decrypt_ascon128(can_fd_payload: bytes, key: bytes, associated_data: bytes = b'') -> bytes:
    """
    Decrypts a 64-byte CAN-FD ASCON payload.
    Assumes: payload = nonce (16) + ciphertext (?) + tag (16)
    Returns: decrypted plaintext (no tag or nonce)
    """
    
    nonce_len = 16
    tag_len = 16

    nonce = can_fd_payload[:nonce_len]
    ciphertext_and_tag = can_fd_payload[nonce_len:]

    plaintext = ascon_decrypt(key, nonce, associated_data, ciphertext_and_tag)

    return plaintext


