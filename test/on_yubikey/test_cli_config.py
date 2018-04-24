from .util import (DestructiveYubikeyTestCase, ykman_cli)


class TestConfigUSB(DestructiveYubikeyTestCase):

    def setUp(self):
        ykman_cli('config', 'usb', '--enable-all', '-f')

    def tearDown(self):
        ykman_cli('config', 'usb', '--enable-all', '-f')

    def test_disable_otp(self):
        ykman_cli('config', 'usb', '--disable', 'OTP', '-f')
        output = ykman_cli('config', 'usb', '--list')
        self.assertNotIn('OTP', output)

    def test_disable_u2f(self):
        ykman_cli('config', 'usb', '--disable', 'U2F', '-f')
        output = ykman_cli('config', 'usb', '--list')
        self.assertNotIn('FIDO U2F', output)

    def test_disable_openpgp(self):
        ykman_cli('config', 'usb', '--disable', 'OPGP', '-f')
        output = ykman_cli('config', 'usb', '--list')
        self.assertNotIn('OpenPGP', output)

    def test_disable_piv(self):
        ykman_cli('config', 'usb', '--disable', 'PIV', '-f')
        output = ykman_cli('config', 'usb', '--list')
        self.assertNotIn('PIV', output)

    def test_disable_oath(self):
        ykman_cli('config', 'usb', '--disable', 'OATH', '-f')
        output = ykman_cli('config', 'usb', '--list')
        self.assertNotIn('OATH', output)

    def test_disable_fido2(self):
        ykman_cli('config', 'usb', '--disable', 'FIDO2', '-f')
        output = ykman_cli('config', 'usb', '--list')
        self.assertNotIn('FIDO2', output)


class TestConfigNFC(DestructiveYubikeyTestCase):

    def setUp(self):
        ykman_cli('config', 'nfc', '--enable-all', '-f')

    def tearDown(self):
        ykman_cli('config', 'nfc', '--enable-all', '-f')

    def test_disable_otp(self):
        ykman_cli('config', 'nfc', '--disable', 'OTP', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        self.assertNotIn('OTP', output)

    def test_disable_u2f(self):
        ykman_cli('config', 'nfc', '--disable', 'U2F', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        self.assertNotIn('FIDO U2F', output)

    def test_disable_openpgp(self):
        ykman_cli('config', 'nfc', '--disable', 'OPGP', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        self.assertNotIn('OpenPGP', output)

    def test_disable_piv(self):
        ykman_cli('config', 'nfc', '--disable', 'PIV', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        self.assertNotIn('PIV', output)

    def test_disable_oath(self):
        ykman_cli('config', 'nfc', '--disable', 'OATH', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        self.assertNotIn('OATH', output)

    def test_disable_fido2(self):
        ykman_cli('config', 'nfc', '--disable', 'FIDO2', '-f')
        output = ykman_cli('config', 'nfc', '--list')
        self.assertNotIn('FIDO2', output)
