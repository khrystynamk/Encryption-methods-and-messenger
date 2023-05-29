"""ECC in class"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hmac, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class ECC:
    """class that represents an Elliptic Curve Cryptography
    using Integrated Encryption Scheme"""

    def __init__(self, user1:'User', user2:'User', curve=ec.SECP256R1()) -> None:
        self.curve = curve
        self._iv = b"random_ivrandom_"  # generate a valid 16-byte IV
        self._kenc = None
        self.user1 = user1
        self.user2 = user2

    def generate_shared(self, user:'User') -> str:
        """creates shared key using Diffie-Hellman method"""
        private = self.user1._private if user == self.user1 else self.user2._private
        public = self.user1.public if user != self.user1 else self.user2.public
        return private.exchange(ec.ECDH(), public)

    def generate_enc_key(self, shared_key: str) -> str:
        """creates encryption key for AES symmetric algorythm"""
        kdf_enc = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the encryption key in bytes (adjust as needed)
            salt=None,  # Optional salt value (if not provided, set to None)
            info=b"encryption_key",  # Additional context or identifier for the encryption key
            backend=default_backend(),
        )
        self._kenc = kdf_enc.derive(shared_key)
        return self._kenc

    def generate_mac_key(self, shared_key:str) -> str:
        """creates key with mac function"""
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Specify the desired length of the MAC key (in bytes)
            salt=None,  # Optional salt value (can be set to None if not needed)
            info=b"MAC key derivation",  # Optional context/application-specific info
            backend=default_backend()
        )
        return kdf.derive(shared_key)

    def aes_enc(self, message: str, key:str) -> str:
        """encrypts given message"""
        # transform message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()

        # cipher text
        cipher = Cipher(
            algorithms.AES(key), modes.CBC(self._iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def aes_dec(self, c_message: str) -> str:
        """decrypts message"""
        cipher = Cipher(
            algorithms.AES(self._kenc), modes.CBC(self._iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(c_message) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()  # transform message
        return unpadder.update(decrypted_data) + unpadder.finalize()

    def generate_tag(self, c_message: str, k_mac:str) -> str:
        """generating tag using mac function"""
        hmac_alg = hmac.HMAC(k_mac, SHA256(), backend=default_backend())
        hmac_alg.update(c_message)
        return hmac_alg.finalize()

class User:
    """represents an user"""
    def __init__(self, name:str, curve=ec.SECP256R1()) -> None:
        self.name = name
        self.curve = curve
        self._private = self._generate_private()
        self.public = self.generate_public()

    def _generate_private(self) -> "ec._EllipticCurvePrivateKey":
        """creates private key using ECC method"""
        return ec.generate_private_key(self.curve, default_backend())

    def generate_public(self) -> "ec._EllipticCurvePublicKey":
        """creates public key according to private one"""
        return self._private.public_key()

# EXAMPLE
with open('file10.txt', 'rb') as data:
    data = data.read()

MESSAGE =  data #b""

# setting users
Alice = User("Alice")
Bob = User("Bob")

# an class instance
ecc_algo = ECC(Alice, Bob)

# PART 1

# shared secret for alice
secret_a = ecc_algo.generate_shared(Alice)

# creating k_enc1 and k_mac1
k_enc1 = ecc_algo.generate_enc_key(secret_a)
k_mac1 = ecc_algo.generate_mac_key(secret_a)

# encrypting message
a_encrypted = ecc_algo.aes_enc(MESSAGE, k_enc1)

# create a_tag
a_tag = ecc_algo.generate_tag(a_encrypted, k_mac1)

# PART 2

# shared secret for bob
secret_b = ecc_algo.generate_shared(Bob)

# creating k_enc2 and k_mac2
k_enc2 = ecc_algo.generate_enc_key(secret_b)
k_mac2 = ecc_algo.generate_mac_key(secret_b)

# encrypting message
b_encrypted = ecc_algo.aes_enc(MESSAGE, k_enc2)

# create b_tag
b_tag = ecc_algo.generate_tag(b_encrypted, k_mac2)

# vefiry tags
if a_tag == b_tag:
    decrypted = ecc_algo.aes_dec(b_encrypted)
else:
    print("MAC verification failed. Message declined.")

# RESULTS

# print("Message: ", MESSAGE)
# print("Encrypted: ", b_encrypted)
# print("Decrypted: ", decrypted)
# print(MESSAGE==decrypted)
