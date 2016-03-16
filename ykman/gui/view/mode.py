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

from PySide import QtGui
from functools import partial

from ykman.yubicommon import qt
from .. import messages as m
from ...util import Mode, TRANSPORT


class _RemoveDialog(QtGui.QMessageBox):

    def __init__(self, controller, parent=None):
        super(_RemoveDialog, self).__init__(parent)

        self._controller = controller

        self.setWindowTitle('Change mode')
        self.setIcon(QtGui.QMessageBox.Information)
        self.setText('remove device')
        self.setStandardButtons(QtGui.QMessageBox.NoButton)

        qt.connect_once(controller.hasDeviceChanged, self._close)
        self._timer = self.startTimer(1000)

    def _close(self, has_device):
        self.killTimer(self._timer)
        self.accept()

    def timerEvent(self, event):
        self._controller.refresh()


class ModeDialog(qt.Dialog):

    def __init__(self, controller, parent=None):
        super(ModeDialog, self).__init__(parent)

        self._controller = controller
        self._state = controller.enabled & sum(TRANSPORT)

        layout = QtGui.QVBoxLayout(self)
        layout.addWidget(QtGui.QLabel('Change mode'))

        boxes = QtGui.QHBoxLayout()
        self._boxes = []
        for t in TRANSPORT.split(controller.capabilities):
            cb = QtGui.QCheckBox(t.name)
            cb.setChecked(self._state & t)
            cb.stateChanged.connect(partial(self._state_changed, t))
            boxes.addWidget(cb)
            self._boxes.append(cb)

        layout.addLayout(boxes)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._set_mode)
        buttons.rejected.connect(self.reject)
        self._ok = buttons.button(QtGui.QDialogButtonBox.Ok)
        layout.addWidget(buttons)

        self.setWindowTitle('Configure enabled USB protocols')

    def _state_changed(self, transport, state):
        if state:
            self._state |= transport  # Set flag
        else:
            self._state &= ~transport  # Unset flag
        self._ok.setEnabled(bool(self._state))

    def _set_mode(self):
        self.close()
        self._controller.set_mode(self.mode)

        remove_dialog = _RemoveDialog(self._controller, self)
        remove_dialog.exec_()

    @property
    def mode(self):
        return Mode(self._state)
