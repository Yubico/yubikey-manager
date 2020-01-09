import os
import unittest

from ..framework import cli_test_suite
from ykman.piv import OBJ
from .util import DEFAULT_MANAGEMENT_KEY


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

    return [ReadWriteObject]
