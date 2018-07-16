from noise.backends.default import DefaultNoiseBackend
from noise.backends.experimental.diffie_hellmans import ECDHSECP256K1
from noise.backends.experimental.keypairs import KeyPairSECP256K1


class ExperimentalNoiseBackend(DefaultNoiseBackend):
    """
    Contains all the default crypto methods, but also methods not directly endorsed by Noise Protocol specification
    """
    def __init__(self):
        super(ExperimentalNoiseBackend, self).__init__()
        self.diffie_hellmans.update({
            'secp256k1': ECDHSECP256K1
        })
        self.ciphers.update({
            'secp256k1': KeyPairSECP256K1
        })
