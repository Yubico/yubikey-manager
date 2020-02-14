from __future__ import unicode_literals

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from ykman.driver_ccid import APDUError
from ykman.opgp import OpgpController, KEY_SLOT
from .framework import yubikey_conditions

E = 65537
DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_ADMIN_PIN = '12345678'
NON_DEFAULT_ADMIN_PIN = '87654321'


class TestKeyManagement(object):

    @pytest.fixture(autouse=True)
    def set_controller(self, open_device_ccid):
        self.dev = open_device_ccid()
        self.controller = OpgpController(self.dev.driver)
        self.controller.reset()
        yield None
        self.dev.driver.close()

    def test_generate_requires_admin(self):
        with pytest.raises(APDUError):
            self.controller.generate_rsa_key(KEY_SLOT.SIG, 2048)

    @yubikey_conditions.is_not_roca
    def test_generate_rsa2048(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_rsa_key(KEY_SLOT.SIG, 2048)
        assert pub.key_size == 2048
        self.controller.delete_key(KEY_SLOT.SIG)

    @yubikey_conditions.is_not_roca
    @yubikey_conditions.version_min((4, 0, 0))
    def test_generate_rsa4096(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_rsa_key(KEY_SLOT.SIG, 4096)
        assert pub.key_size == 4096

    @yubikey_conditions.version_min((5, 2, 0))
    def test_generate_secp256r1(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_ec_key(KEY_SLOT.SIG, 'secp256r1')
        assert pub.key_size == 256
        assert pub.curve.name == 'secp256r1'

    @yubikey_conditions.version_min((5, 2, 0))
    def test_generate_ed25519(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_ec_key(KEY_SLOT.SIG, 'ed25519')
        assert 32 == len(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))

    @yubikey_conditions.version_min((5, 2, 0))
    def test_generate_x25519(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_ec_key(KEY_SLOT.ENC, 'x25519')
        assert 32 == len(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))

    def test_import_rsa2048(self):
        priv = rsa.generate_private_key(E, 2048, default_backend())
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @yubikey_conditions.version_min((4, 0, 0))
    def test_import_rsa4096(self):
        priv = rsa.generate_private_key(E, 4096, default_backend())
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @yubikey_conditions.version_min((5, 2, 0))
    def test_import_secp256r1(self):
        priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @yubikey_conditions.version_min((5, 2, 0))
    def test_import_ed25519(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv = ed25519.Ed25519PrivateKey.generate()
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @yubikey_conditions.version_min((5, 2, 0))
    def test_import_x25519(self):
        from cryptography.hazmat.primitives.asymmetric import x25519
        priv = x25519.X25519PrivateKey.generate()
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.ENC, priv)
