#  vim: set fileencoding=utf-8 :

import unittest

from .util import ykman_cli


class TestRunScript(unittest.TestCase):

    def test_inline_external_dependency_gets_installed(self):
        output = ykman_cli('script', '-', input='\n'.join([
            '__requires__ = ["numpy"]',
            'import numpy',
            'print((numpy.array([[1, 2], [3, 4]])**2).reshape(4))',
        ]))
        self.assertIn('[ 1  4  9 16]', output)
