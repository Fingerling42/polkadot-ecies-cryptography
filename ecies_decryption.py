from ecies_encryption import NONCE_SIZE, DERIVATION_KEY_SALT_SIZE, PUBLIC_KEY_SIZE, MAC_VALUE_SIZE
from ecies_encryption import derive_key, bytes_concat, get_sr25519_agreement, get_ed25519_agreement, generate_mac_data
from nacl.secret import SecretBox
import typing as tp


def ecies_decrypt(encrypted_message: bytes, receiver_private_key: bytes, receiver_keypair_type: str) -> tp.Tuple:

    # Split encrypted_message to parts
    message_public_key, salt, mac_value, nonce, sealed_message = decapsulate_encrypted_message(encrypted_message)

    # Repeat encryption_key and mac_key generation based on encrypted_message
    if receiver_keypair_type == 'SR25519':
        agreement_key = get_sr25519_agreement(private_key=receiver_private_key,
                                              public_key=message_public_key)
    elif receiver_keypair_type == 'ED25519':
        agreement_key = get_ed25519_agreement(private_key=receiver_private_key,
                                              public_key=message_public_key)
    else:
        raise TypeError('Keypair type of receiver is not supported')

    master_secret = bytes_concat(message_public_key, agreement_key)
    encryption_key, mac_key = derive_key(master_secret, salt)

    # Get decrypted MAC value
    decrypted_mac_value = generate_mac_data(
        nonce=nonce,
        encrypted_message=sealed_message,
        message_public_key=message_public_key,
        mac_key=mac_key
    )

    # Check if MAC values the same
    assert mac_value == decrypted_mac_value, "MAC values do not match"

    # Decrypt the message
    decrypted_message = nacl_decrypt(sealed_message, nonce, encryption_key)
    return decrypted_message, message_public_key


def decapsulate_encrypted_message(encrypted_message: bytes):
    assert len(encrypted_message) > NONCE_SIZE + DERIVATION_KEY_SALT_SIZE + PUBLIC_KEY_SIZE + MAC_VALUE_SIZE, \
        "Wrong encrypted message length"

    message_public_key = encrypted_message[
                         NONCE_SIZE + DERIVATION_KEY_SALT_SIZE: NONCE_SIZE + DERIVATION_KEY_SALT_SIZE + PUBLIC_KEY_SIZE]

    salt = encrypted_message[NONCE_SIZE: NONCE_SIZE + DERIVATION_KEY_SALT_SIZE]
    mac_value = encrypted_message[
                NONCE_SIZE + DERIVATION_KEY_SALT_SIZE + PUBLIC_KEY_SIZE: NONCE_SIZE + DERIVATION_KEY_SALT_SIZE
                                                                         + PUBLIC_KEY_SIZE + MAC_VALUE_SIZE]

    nonce = encrypted_message[:NONCE_SIZE]
    sealed_message = encrypted_message[NONCE_SIZE + DERIVATION_KEY_SALT_SIZE + PUBLIC_KEY_SIZE + MAC_VALUE_SIZE:]

    return message_public_key, salt, mac_value, nonce, sealed_message


def nacl_decrypt(sealed_message: bytes, nonce: bytes, encryption_key: bytes):
    # Create a nacl SecretBox using the encryption key
    box = SecretBox(encryption_key)
    try:
        # Decrypt the message
        decrypted_message = box.decrypt(sealed_message, nonce)
        return decrypted_message
    except Exception as e:
        raise ValueError("Invalid secret or pubkey provided") from e