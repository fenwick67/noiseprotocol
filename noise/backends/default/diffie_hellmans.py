import abc

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from noise.backends.default.crypto import X448
from noise.backends.default.keypairs import KeyPair25519, KeyPair448
from noise.exceptions import NoiseValueError
from noise.functions.dh import DH

cryptography_backend = default_backend()


class CryptographyECDH(DH, metaclass=abc.ABCMeta):
    @property
    def dhlen(self):
        return self.klass.curve.key_size

    def generate_keypair(self) -> 'KeyPair':
        private_key = ec.generate_private_key(self.klass.curve, cryptography_backend)
        public_key = private_key.public_key()
        return self.klass(private_key, public_key)

    def dh(self, private_key, public_key) -> bytes:
        return private_key.exchange(ec.ECDH(), public_key)


class ED25519(DH):
    @property
    def klass(self):
        return KeyPair25519

    @property
    def dhlen(self):
        return 32

    def generate_keypair(self) -> 'KeyPair':
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair25519(private_key, public_key, public_key.public_bytes())

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x25519.X25519PrivateKey) or not isinstance(public_key, x25519.X25519PublicKey):
            raise NoiseValueError('Invalid keys! Must be x25519.X25519PrivateKey and x25519.X25519PublicKey instances')
        return private_key.exchange(public_key)


class ED448(DH):
    @property
    def klass(self):
        return KeyPair448

    @property
    def dhlen(self):
        return 56

    def generate_keypair(self) -> 'KeyPair':
        return KeyPair448.new()

    def dh(self, private_key, public_key) -> bytes:
        if len(private_key) != self.dhlen or len(public_key) != self.dhlen:
            raise NoiseValueError('Invalid length of keys! Should be {}'.format(self.dhlen))
        return X448.mul(private_key, public_key)
