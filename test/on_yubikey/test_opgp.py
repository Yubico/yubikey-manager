from __future__ import unicode_literals

import unittest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, x25519
from ykman.driver_ccid import APDUError
from ykman.opgp import OpgpController, KEY_SLOT
from .util import (
    DestructiveYubikeyTestCase, missing_mode, open_device, get_version,
    skip_roca, TRANSPORT)


E = 65537
DEFAULT_PIN = '123456'
NON_DEFAULT_PIN = '654321'
DEFAULT_ADMIN_PIN = '12345678'
NON_DEFAULT_ADMIN_PIN = '87654321'


no_rsa4096 = (get_version() is not None and get_version() < (4, 0, 0),
              'RSA 4096 not supported.')

no_ec = (get_version() is not None and get_version() < (5, 2, 0),
         'EC not supported.')


@unittest.skipIf(*missing_mode(TRANSPORT.CCID))
class OpgpTestCase(DestructiveYubikeyTestCase):

    def setUp(self):
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.controller = OpgpController(self.dev.driver)

    def tearDown(self):
        self.dev.driver.close()

    def reconnect(self):
        self.dev.driver.close()
        self.dev = open_device(transports=TRANSPORT.CCID)
        self.controller = OpgpController(self.dev.driver)


class KeyManagement(OpgpTestCase):

    @classmethod
    def setUpClass(cls):
        with open_device(transports=TRANSPORT.CCID) as dev:
            controller = OpgpController(dev.driver)
            controller.reset()

    def test_generate_requires_admin(self):
        with self.assertRaises(APDUError):
            self.controller.generate_rsa_key(KEY_SLOT.SIG, 2048)

    @unittest.skipIf(*skip_roca)
    def test_generate_rsa2048(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_rsa_key(KEY_SLOT.SIG, 2048)
        self.assertEqual(pub.key_size, 2048)
        self.controller.delete_key(KEY_SLOT.SIG)

    @unittest.skipIf(*skip_roca)
    @unittest.skipIf(*no_rsa4096)
    def test_generate_rsa4096(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_rsa_key(KEY_SLOT.SIG, 4096)
        self.assertEqual(pub.key_size, 4096)

    @unittest.skipIf(*no_ec)
    def test_generate_secp256r1(self):
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        pub = self.controller.generate_ec_key(KEY_SLOT.SIG, 'secp256r1')
        self.assertEqual(pub.key_size, 256)
        self.assertEqual(pub.curve.name, 'secp256r1')

    @unittest.skipIf(*no_ec)
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

    @unittest.skipIf(*no_ec)
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

    @unittest.skipIf(*no_rsa4096)
    def test_import_rsa4096(self):
        priv = rsa.generate_private_key(E, 4096, default_backend())
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @unittest.skipIf(*no_ec)
    def test_import_secp256r1(self):
        priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @unittest.skipIf(*no_ec)
    def test_import_ed25519(self):
        priv = ed25519.Ed25519PrivateKey.generate()
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.SIG, priv)

    @unittest.skipIf(*no_ec)
    def test_import_x25519(self):
        priv = x25519.X25519PrivateKey.generate()
        self.controller.verify_admin(DEFAULT_ADMIN_PIN)
        self.controller.import_key(KEY_SLOT.ENC, priv)
