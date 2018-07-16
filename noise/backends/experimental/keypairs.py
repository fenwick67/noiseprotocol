from cryptography.hazmat.primitives.asymmetric import ec

from noise.backends.default.keypairs import CryptographyKeyPair


class KeyPairSECP256K1(CryptographyKeyPair):
    @property
    def curve(self):
        return ec.SECP256K1
