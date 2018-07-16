from noise.backends.default.diffie_hellmans import CryptographyECDH
from noise.backends.experimental.keypairs import KeyPairSECP256K1


class ECDHSECP256K1(CryptographyECDH):
    @property
    def klass(self):
        return KeyPairSECP256K1
