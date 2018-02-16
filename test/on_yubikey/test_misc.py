import time
from .util import (DestructiveYubikeyTestCase, ykman_cli)


class TestYkmanInfo(DestructiveYubikeyTestCase):

    def test_ykman_info(self):
        time.sleep(3)
        info = ykman_cli('info')
        self.assertIn('Device type:', info)
        self.assertIn('Serial number:', info)
        self.assertIn('Firmware version:', info)
