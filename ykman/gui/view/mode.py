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
from ...driver import ModeSwitchError

class _RemoveDialog(QtGui.QMessageBox):

    def __init__(self, controller, parent=None):
        super(_RemoveDialog, self).__init__(parent)

        self._controller = controller

        self.setWindowTitle(m.configure_connections)
        self.setIcon(QtGui.QMessageBox.Information)
        self.setText(m.remove_device)
        self.setStandardButtons(QtGui.QMessageBox.NoButton)

        self._controller.hasDeviceChanged.connect(self._close)
        self._controller.numberOfKeysChanged.connect(self._close)
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
        self._state = 0

        layout = QtGui.QVBoxLayout(self)
        layout.addWidget(QtGui.QLabel('<h2>' + m.configure_protocols + '</h2>'))
        layout.addWidget(QtGui.QLabel(m.configure_protocols_desc))
        desc_lbl = QtGui.QLabel(m.configure_protocols_reinsert)
        desc_lbl.setWordWrap(True)
        layout.addWidget(desc_lbl)

        boxes = QtGui.QHBoxLayout()
        self._boxes = []
        for t in TRANSPORT.split(controller.capabilities):
            cb = QtGui.QCheckBox(t.name)
            cb.setChecked(controller.enabled & t)
            if TRANSPORT.has(TRANSPORT.usb_transports(), t):
                cb.stateChanged.connect(partial(self._state_changed, t))
                self._state |= controller.enabled & t
            else:
                cb.setEnabled(False)
            boxes.addWidget(cb)
            self._boxes.append(cb)

        layout.addLayout(boxes)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Ok |
                                         QtGui.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._set_mode)
        buttons.rejected.connect(self.reject)
        self._ok = buttons.button(QtGui.QDialogButtonBox.Ok)
        layout.addWidget(buttons)

        self.setWindowTitle(m.configure_connections)

    def _state_changed(self, transport, state):
        if state:
            self._state |= transport  # Set flag
        else:
            self._state &= ~transport  # Unset flag
        self._ok.setEnabled(bool(self._state))

    def _set_mode(self):
        def _cb(result):
            if isinstance(result, ModeSwitchError):
                QtGui.QMessageBox.critical(self, m.failed_configure_connections, 
                        m.failed_configure_connections_desc)
            else:
                self.close()
                remove_dialog = _RemoveDialog(self._controller, self)
                remove_dialog.exec_()

        self._controller.set_mode(self.mode, _cb)

    @property
    def mode(self):
        return Mode(self._state & TRANSPORT.usb_transports())
