import os
import pytest

from cryptography.hazmat.primitives import serialization
from ykman.piv import OBJ, SLOT, TAG
from ykman.util import Tlv
from .util import DEFAULT_MANAGEMENT_KEY
from ...util import generate_self_signed_certificate


class ReadWriteObject(object):

    @pytest.fixture(autouse=True)
    def setUpTearDown(self, ykman_cli):
        ykman_cli('piv', 'reset', '-f')
        yield None
        ykman_cli('piv', 'reset', '-f')

    def test_write_read_preserves_ansi_escapes(self, ykman_cli):
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
        assert data == output_data

    def test_read_write_read_is_noop(self, ykman_cli):
        data = os.urandom(32)

        ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                  '-m', DEFAULT_MANAGEMENT_KEY,
                  input=data)

        output1 = ykman_cli.with_bytes_output('piv', 'read-object',
                                              hex(OBJ.AUTHENTICATION))
        assert output1 == data

        ykman_cli('piv', 'write-object', hex(OBJ.AUTHENTICATION), '-',
                  '-m', DEFAULT_MANAGEMENT_KEY,
                  input=output1)

        output2 = ykman_cli.with_bytes_output('piv', 'read-object',
                                              hex(OBJ.AUTHENTICATION))
        assert output2 == data

    def test_read_write_certificate_as_object(self, ykman_cli):
        with pytest.raises(SystemExit):
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
        assert output_cert_bytes == cert_bytes_der

        output2 = ykman_cli.with_bytes_output('piv', 'export-certificate',
                                              hex(SLOT.AUTHENTICATION), '-',
                                              '--format', 'DER')
        assert output2 == cert_bytes_der
