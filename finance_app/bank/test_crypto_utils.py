import bank.crypto_utils as crypto_utils
from django.test import TestCase
from decimal import Decimal
class EncryptionTests(TestCase):
    def setUp(self):
        # Clear any cached server key so that get_server_keys reads fresh from the DB.
        crypto_utils._server_keys_cache = None
        # Create a new key in the database.
        self.server_key = crypto_utils.generate_new_key()
    
    # --- Balance Encryption Tests ---
    def test_encrypt_decrypt_balance(self):
        balance = Decimal('12345.67')
        encrypted_balance = crypto_utils.encrypt_balance(balance)
        decrypted_balance = crypto_utils.decrypt_balance(encrypted_balance)
        self.assertEqual(balance, decrypted_balance)

    def test_encrypt_balance_invalid(self):
        balance = Decimal('9999.99')
        encrypted_balance = crypto_utils.encrypt_balance(balance)
        # Tamper with encrypted data to force decryption failure.
        tampered = encrypted_balance[:-5] + "00000"
        with self.assertRaises(Exception):
            crypto_utils.decrypt_balance(tampered)

    # --- Field Encryption Tests ---
    def test_encrypt_decrypt_field(self):
        value = "Test Field Value"
        salt = b'field_salt'
        info = b'field info'
        encrypted = crypto_utils.encrypt_field(value, salt, info)
        decrypted = crypto_utils.decrypt_field(encrypted, salt, info)
        self.assertEqual(value, decrypted)

    def test_field_invalid_decryption(self):
        value = "Sensitive Data"
        salt = b'field_salt'
        info = b'field info'
        encrypted = crypto_utils.encrypt_field(value, salt, info)
        # Tamper with the encrypted data.
        tampered = encrypted[:-5] + "XXXXX"
        with self.assertRaises(Exception):
            crypto_utils.decrypt_field(tampered, salt, info)

    # --- Message Encryption Tests ---
    def test_encrypt_decrypt_message(self):
        message = "This is a secure message."
        encrypted_message = crypto_utils.encrypt_message(message)
        decrypted_message = crypto_utils.decrypt_message(encrypted_message)
        self.assertEqual(message, decrypted_message)

    def test_message_invalid(self):
        message = "Another secure message"
        encrypted_message = crypto_utils.encrypt_message(message)
        # Tamper with the encrypted message.
        tampered = encrypted_message[:-5] + "12345"
        with self.assertRaises(Exception):
            crypto_utils.decrypt_message(tampered)

    # --- Key Generation and Caching Tests ---
    def test_generate_new_key(self):
        key = crypto_utils.generate_new_key()
        self.assertTrue(key.is_active)
        self.assertEqual(key.algorithm, "MLKEM1024")

    def test_server_keys_existence(self):
        keys = crypto_utils.get_server_keys()
        self.assertIsNotNone(keys)

    def test_server_keys_caching(self):
        keys1 = crypto_utils.get_server_keys()
        keys2 = crypto_utils.get_server_keys()
        self.assertEqual(keys1, keys2)

     # Key Management
    def test_generate_key_creates_active_key(self):
        key = crypto_utils.generate_new_key()
        self.assertTrue(key.is_active)
        self.assertEqual(key.algorithm, "MLKEM1024")

    def test_get_server_keys_returns_same_key_if_cached(self):
        key1 = crypto_utils.get_server_keys()
        key2 = crypto_utils.get_server_keys()
        self.assertEqual(key1, key2)

    # Decryption with Missing Key
    def test_decrypt_balance_with_missing_key_raises_exception(self):
        from .models import PQServerKey
        balance = Decimal("100.00")
        encrypted = crypto_utils.encrypt_balance(balance)
        # Delete all keys so that the key used for encryption is missing.
        PQServerKey.objects.all().delete()
        with self.assertRaises(Exception):
            crypto_utils.decrypt_balance(encrypted)

    # Corrupt Encrypted Data
    def test_decrypt_message_with_corrupted_data_raises_exception(self):
        message = "Hello"
        encrypted = crypto_utils.encrypt_message(message)
        # Tamper with the encrypted message.
        tampered = encrypted[:-5] + "abcde"
        with self.assertRaises(Exception):
            crypto_utils.decrypt_message(tampered)

    # Field Encryption/Decryption with Unicode Data
    def test_encrypt_decrypt_field_unicode(self):
        value = "sëcrēt🚀data"
        salt = b'field_salt'
        info = b'unicode'
        encrypted = crypto_utils.encrypt_field(value, salt, info)
        decrypted = crypto_utils.decrypt_field(encrypted, salt, info)
        self.assertEqual(decrypted, value)

    # Balance Encryption/Decryption for Large Values
    def test_encrypt_decrypt_large_balance(self):
        balance = Decimal("9999999999.99")
        encrypted = crypto_utils.encrypt_balance(balance)
        decrypted = crypto_utils.decrypt_balance(encrypted)
        self.assertEqual(balance, decrypted)

    # Balance Encryption/Decryption for Zero Value
    def test_encrypt_balance_zero(self):
        balance = Decimal("0.00")
        encrypted = crypto_utils.encrypt_balance(balance)
        decrypted = crypto_utils.decrypt_balance(encrypted)
        self.assertEqual(balance, decrypted)

    # Nonce Randomness: Same input produces different encrypted outputs.
    def test_encryption_produces_different_outputs_for_same_input(self):
        message = "duplicate input"
        encrypted1 = crypto_utils.encrypt_message(message)
        encrypted2 = crypto_utils.encrypt_message(message)
        self.assertNotEqual(encrypted1, encrypted2)

    # Decrypt Field with Wrong Salt
    def test_decrypt_field_with_wrong_salt_fails(self):
        value = "sensitive field"
        salt = b'correct_salt'
        info = b'field'
        encrypted = crypto_utils.encrypt_field(value, salt, info)
        with self.assertRaises(Exception):
            crypto_utils.decrypt_field(encrypted, b'wrong_salt', info)

    # Decrypt Field with Wrong Info
    def test_decrypt_field_with_wrong_info_fails(self):
        value = "sensitive field"
        salt = b'salt'
        encrypted = crypto_utils.encrypt_field(value, salt, b'correct_info')
        with self.assertRaises(Exception):
            crypto_utils.decrypt_field(encrypted, salt, b'wrong_info')




class Argon2HasherTests(TestCase):
    def test_argon2_password_hashing(self):
        from django.contrib.auth.hashers import make_password, check_password
        password = "SuperSecurePassword123!"
        hashed_password = make_password(password)
        self.assertTrue(check_password(password, hashed_password))
        self.assertFalse(check_password("WrongPassword", hashed_password))
