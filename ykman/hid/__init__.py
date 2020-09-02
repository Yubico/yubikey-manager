from __future__ import absolute_import

import sys


if sys.platform.startswith('linux'):
    from . import linux as backend
elif sys.platform.startswith('win32'):
    from . import windows as backend
elif sys.platform.startswith('darwin'):
    from . import mac as backend
else:
    raise Exception('Unsupported platform')


list_devices = backend.list_devices
