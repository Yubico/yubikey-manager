from __future__ import unicode_literals

import unittest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from ykman.driver_ccid import APDUError
from ykman.opgp import OpgpController, KEY_SLOT
from ykman.util import TRANSPORT
from .framework import device_test_suite, yubikey_conditions

E = 65537
DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_ADMIN_PIN = '12345678'
NON_DEFAULT_ADMIN_PIN = '87654321'


@device_test_suite(TRANSPORT.CCID)
def additional_tests(open_device):

    class OpgpTestCase(unittest.TestCase):

        def setUp(self):
            self.dev = open_device()
            self.controller = OpgpController(self.dev.driver)

        def tearDown(self):
            self.dev.driver.close()

        def reconnect(self):
            self.dev.driver.close()
            self.dev = open_device()
            self.controller = OpgpController(self.dev.driver)

    class KeyManagement(OpgpTestCase):

        @classmethod
        def setUpClass(cls):
            with open_device() as dev:
                controller = OpgpController(dev.driver)
                controller.reset()

        def test_generate_requires_admin(self):
            with self.assertRaises(APDUError):
                self.controller.generate_rsa_key(KEY_SLOT.SIG, 2048)

        @yubikey_conditions.is_not_roca
        def test_generate_rsa2048(self):
            self.controller.verify_admin(DEFAULT_ADMIN_PIN)
            pub = self.controller.generate_rsa_key(KEY_SLOT.SIG, 2048)
            self.assertEqual(pub.key_size, 2048)
            self.controller.delete_key(KEY_SLOT.SIG)

        @yubikey_conditions.is_not_roca
        @yubikey_conditions.version_min((4, 0, 0))
        def test_generate_rsa4096(self):
            self.controller.verify_admin(DEFAULT_ADMIN_PIN)
            pub = self.controller.generate_rsa_key(KEY_SLOT.SIG, 4096)
            self.assertEqual(pub.key_size, 4096)

        @yubikey_conditions.version_min((5, 2, 0))
        def test_generate_secp256r1(self):
            self.controller.verify_admin(DEFAULT_ADMIN_PIN)
            pub = self.controller.generate_ec_key(KEY_SLOT.SIG, 'secp256r1')
            self.assertEqual(pub.key_size, 256)
            self.assertEqual(pub.curve.name, 'secp256r1')

        @yubikey_conditions.version_min((5, 2, 0))
        def test_generate_ed25519(self):
            self.controller.verify_admin(DEFAULT_ADMIN_PIN)
            pub = self.controller.generate_ec_key(KEY_SLOT.SIG, 'ed25519')
            self.assertEqual(
                len(pub.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )),
                32
            )

        @yubikey_conditions.version_min((5, 2, 0))
        def test_generate_x25519(self):
            self.controller.verify_admin(DEFAULT_ADMIN_PIN)
            pub = self.controller.generate_ec_key(KEY_SLOT.ENC, 'x25519')
            self.assertEqual(
                len(pub.public_bytes(
                    Encoding.Raw,
                    PublicFormat.Raw
                )),
                32
            )

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

    return [OpgpTestCase, KeyManagement]
