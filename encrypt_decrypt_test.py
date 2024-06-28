from substrateinterface import Keypair, KeypairType
from ecies_encryption import ecies_encrypt
from ecies_decryption import ecies_decrypt

receiver_mnemonic = 'intact eight crunch slogan stairs coin odor pudding cushion waste electric raw'

receiver_keypair_sr: Keypair = Keypair.create_from_mnemonic(
    mnemonic=receiver_mnemonic,
    crypto_type=KeypairType.SR25519
)

receiver_keypair_ed: Keypair = Keypair.create_from_mnemonic(
    mnemonic=receiver_mnemonic,
    crypto_type=KeypairType.ED25519
)

test_message_string = 'This is the test message'

# Encrypt string message for Schnorrkel/Ristretto keypair
encrypted_string_sr = ecies_encrypt(test_message_string, receiver_keypair_sr.public_key, 'SR25519')
print('Encrypted string for Schnorrkel/Ristretto keypair:', encrypted_string_sr.hex())

# Encrypt string message for Edwards keypair
encrypted_string_ed = ecies_encrypt(test_message_string, receiver_keypair_ed.public_key, 'ED25519')
print('Encrypted string for Edwards keypair:', encrypted_string_ed.hex())

# Decrypt string for Schnorrkel/Ristretto keypair
decrypted_string_sr, message_public_key_sr = ecies_decrypt(encrypted_string_sr,
                                                           receiver_keypair_sr.private_key,
                                                           'SR25519')
print('Decrypted for Schnorrkel/Ristretto keypair:', decrypted_string_sr.decode())

# Decrypt string for Edwards keypair
decrypted_string_ed, message_public_key_ed = ecies_decrypt(encrypted_string_ed,
                                                           receiver_keypair_ed.private_key,
                                                           'ED25519')
print('Decrypted for Edwards keypair:', decrypted_string_ed.decode())
