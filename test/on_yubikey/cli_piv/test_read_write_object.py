import os
import unittest

from cryptography.hazmat.primitives import serialization
from ..framework import cli_test_suite
from ykman.piv import OBJ, SLOT, TAG
from ykman.util import Tlv
from .util import DEFAULT_MANAGEMENT_KEY
from ...util import generate_self_signed_certificate


@cli_test_suite
def additional_tests(ykman_cli):
    class ReadWriteObject(unittest.TestCase):

        def setUp(cls):
            ykman_cli('piv', 'reset', '-f')
            pass

        @classmethod
        def tearDownClass(cls):
            ykman_cli('piv', 'reset', '-f')
            pass

        def test_write_read_preserves_ansi_escapes(self):
            red = b'\x00\x1b[31m'
            blue = b'\x00\x1b[34m'
            reset = b'\x00\x1b[0m'
            data = (b'Hello, ' + red + b'red' + reset + b' and ' + blue
                    + b'blue' + reset + b' world!')
            ykman_cli(
                'piv', 'write-object',
                '-m', DEFAULT_MANAGEMENT_KEY, '0x5f0001',
                '-', input=data)
            output_data = ykman_cli.with_bytes_output(
                'piv', 'read-object', '0x5f0001')
            self.assertEqual(data, output_data)

        def test_read_write_read_is_noop(self):
            data = os.urandom(32)

            ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      input=data)

            output1 = ykman_cli.with_bytes_output('piv', 'read-object',
                                                  hex(OBJ.AUTHENTICATION))
            self.assertEqual(output1, data)

            ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      input=output1)

            output2 = ykman_cli.with_bytes_output('piv', 'read-object',
                                                  hex(OBJ.AUTHENTICATION))
            self.assertEqual(output2, data)

        def test_read_write_certificate_as_object(self):
            with self.assertRaises(SystemExit):
                ykman_cli('piv', 'read-object', hex(OBJ.AUTHENTICATION))

            cert = generate_self_signed_certificate()
            cert_bytes_der = cert.public_bytes(
                encoding=serialization.Encoding.DER)

            input_tlv = (
                Tlv(TAG.CERTIFICATE, cert_bytes_der) +
                Tlv(TAG.CERT_INFO, b'\0') +
                Tlv(TAG.LRC, b'')
            )

            ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                      '-m', DEFAULT_MANAGEMENT_KEY,
                      input=input_tlv)

            output1 = ykman_cli.with_bytes_output('piv', 'read-object',
                                                  hex(OBJ.AUTHENTICATION))
            output_cert_bytes = Tlv.parse_dict(output1)[TAG.CERTIFICATE]
            self.assertEqual(output_cert_bytes, cert_bytes_der)

            output2 = ykman_cli.with_bytes_output('piv', 'export-certificate',
                                                  hex(SLOT.AUTHENTICATION), '-',
                                                  '--format', 'DER')
            self.assertEqual(output2, cert_bytes_der)

    return [ReadWriteObject]
