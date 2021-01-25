import os

from cryptography.hazmat.primitives import serialization
from ....util import generate_self_signed_certificate
from yubikit.core import Tlv
from yubikit.piv import OBJECT_ID, SLOT
import contextlib
import io
import pytest


DEFAULT_MANAGEMENT_KEY = "010203040506070801020304050607080102030405060708"


class TestReadWriteObject:
    def test_write_read_preserves_ansi_escapes(self, ykman_cli):
        red = b"\x00\x1b[31m"
        blue = b"\x00\x1b[34m"
        reset = b"\x00\x1b[0m"
        data = (
            b"Hello, "
            + red
            + b"red"
            + reset
            + b" and "
            + blue
            + b"blue"
            + reset
            + b" world!"
        )
        ykman_cli(
            "piv",
            "objects",
            "import",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            "0x5f0001",
            "-",
            input=data,
        )
        output_data = ykman_cli(
            "piv", "objects", "export", "0x5f0001", "-"
        ).stdout_bytes
        assert data == output_data

    def test_read_write_read_is_noop(self, ykman_cli):
        data = os.urandom(32)

        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input=data,
        )

        output1 = ykman_cli(
            "piv", "objects", "export", hex(OBJECT_ID.AUTHENTICATION), "-"
        ).stdout_bytes
        assert output1 == data

        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input=output1,
        )

        output2 = ykman_cli(
            "piv", "objects", "export", hex(OBJECT_ID.AUTHENTICATION), "-"
        ).stdout_bytes
        assert output2 == data

    def test_read_write_aliases(self, ykman_cli):
        data = os.urandom(32)

        with io.StringIO() as buf:
            with contextlib.redirect_stderr(buf):
                ykman_cli(
                    "piv",
                    "write-object",
                    hex(OBJECT_ID.AUTHENTICATION),
                    "-",
                    "-m",
                    DEFAULT_MANAGEMENT_KEY,
                    input=data,
                )

                output1 = ykman_cli(
                    "piv", "read-object", hex(OBJECT_ID.AUTHENTICATION), "-"
                ).stdout_bytes
            err = buf.getvalue()
        assert output1 == data
        assert "piv objects import" in err
        assert "piv objects export" in err

    def test_read_write_certificate_as_object(self, ykman_cli):
        with pytest.raises(SystemExit):
            ykman_cli("piv", "objects", "export", hex(OBJECT_ID.AUTHENTICATION), "-")

        cert = generate_self_signed_certificate()
        cert_bytes_der = cert.public_bytes(encoding=serialization.Encoding.DER)

        input_tlv = Tlv(0x70, cert_bytes_der) + Tlv(0x71, b"\0") + Tlv(0xFE, b"")

        ykman_cli(
            "piv",
            "objects",
            "import",
            hex(OBJECT_ID.AUTHENTICATION),
            "-",
            "-m",
            DEFAULT_MANAGEMENT_KEY,
            input=input_tlv,
        )

        output1 = ykman_cli(
            "piv", "objects", "export", hex(OBJECT_ID.AUTHENTICATION), "-"
        ).stdout_bytes
        output_cert_bytes = Tlv.parse_dict(output1)[0x70]
        assert output_cert_bytes == cert_bytes_der

        output2 = ykman_cli(
            "piv",
            "certificates",
            "export",
            hex(SLOT.AUTHENTICATION),
            "-",
            "--format",
            "DER",
        ).stdout_bytes
        assert output2 == cert_bytes_der
