from ..util import ykman_cli
from .test_cli_piv import PivTestCase


class Misc(PivTestCase):

    def test_info(self):
        output = ykman_cli('piv', 'info')
        self.assertIn('PIV version:', output)

    def test_reset(self):
        output = ykman_cli('piv', 'reset', '-f')
        self.assertIn('Success!', output)
