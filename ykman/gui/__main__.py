# Copyright (c) 2015 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, print_function

import signal
import sys
from PySide import QtCore, QtGui

from ykman import __version__
from ykman.yubicommon import qt
from . import messages as m
from .controller import Controller
from .view.info import InfoWidget
from ..util import list_yubikeys

class YkManApplication(qt.Application):

    def __init__(self):
        super(YkManApplication, self).__init__(m, __version__)

        QtCore.QCoreApplication.setOrganizationName(m.organization)
        QtCore.QCoreApplication.setOrganizationDomain(m.domain)
        QtCore.QCoreApplication.setApplicationName(m.app_name)

        self.ensure_singleton()

        self._controller = Controller(self.worker, self)
        self._controller.refresh()

        self._controller.numberOfKeysChanged.connect(self._update)
        self._controller.hasDeviceChanged.connect(self._update)

        self._init_window()
        self._update()

    def _init_window(self):
        self.window.setWindowTitle(m.win_title_1 % self.version)
        self.window.setWindowIcon(QtGui.QIcon(':/ykman.png'))

        self._info = InfoWidget(self._controller, self.window)

        self._no_key = QtGui.QLabel(m.no_key)
        self._no_key.setAlignment(QtCore.Qt.AlignCenter)

        self._busy_key = QtGui.QLabel(m.busy_key)
        self._busy_key.setAlignment(QtCore.Qt.AlignCenter)

        self._multiple_keys = QtGui.QLabel(m.multiple_keys)
        self._multiple_keys.setAlignment(QtCore.Qt.AlignCenter)

        self._widget_stack = QtGui.QStackedWidget()
        self._widget_stack.addWidget(self._info)
        self._widget_stack.addWidget(self._no_key)
        self._widget_stack.addWidget(self._busy_key)
        self._widget_stack.addWidget(self._multiple_keys)

        self.window.setCentralWidget(self._widget_stack)

        self.window.show()
        self.window.raise_()

    def _update(self):
        n_keys = self._controller.number_of_keys
        has_device = self._controller.has_device
        if n_keys == 0:
            self._widget_stack.setCurrentWidget(self._no_key)
        elif n_keys == 1 and has_device:
            self._widget_stack.setCurrentWidget(self._info)
        elif n_keys == 1 and not has_device:
            self._widget_stack.setCurrentWidget(self._busy_key)
        elif n_keys > 1:
            self._widget_stack.setCurrentWidget(self._multiple_keys)

def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = YkManApplication()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
