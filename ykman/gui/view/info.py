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

from ...util import CAPABILITY, TRANSPORT
from .mode import ModeDialog
from .slot import SlotDialog


NON_FEATURE_CAPABILITIES = ['CCID', 'NFC']


def format_readable_list(items):
    if not items:
        return ''
    elif len(items) == 1:
        return items[0]
    else:
        return '{} and {}'.format(', '.join(items[:-1]), items[-1])


class _HeaderPanel(QtGui.QGroupBox):
    def __init__(self, controller, parent=None):
        super(_HeaderPanel, self).__init__('Device', parent)

        layout = QtGui.QHBoxLayout(self)

        self._device_name = QtGui.QLabel()
        layout.addWidget(self._device_name)

        self._serial = QtGui.QLabel()
        layout.addWidget(self._serial)

        controller.versionChanged.connect(self._set_version)
        self._set_version(controller.version)

        controller.hasDeviceChanged.connect(self._set_has_device)
        self._set_has_device(controller.has_device)

        controller.deviceNameChanged.connect(self._set_device_name)
        self._set_device_name(controller.device_name)

        controller.serialChanged.connect(self._set_serial)
        self._set_serial(controller.serial)


    def _set_has_device(self, has_device):
        if not has_device:
            self._set_serial(None)
            self._set_device_name('No YubiKey detected')
            self._set_version(None)

    def _set_device_name(self, name):
        self._device_name.setText(name)

    def _set_serial(self, serial):
        self._serial.setText('Serial: {}'.format(serial) if serial else '')

    def _set_version(self, version):
        if version:
            name = self._device_name.text()
            f_version = '({0[0]}.{0[1]})'.format(version) if 'NEO' in name \
                    else '({0[0]}.{0[1]}.{0[2]})'.format(version)
            self._device_name.setText(name + ' ' + f_version)

class _FeatureSection(QtGui.QGroupBox):

    names = dict((c, c.name + ':') for c in CAPABILITY)
    configurable = CAPABILITY.OTP | CAPABILITY.OPGP

    def __init__(self, controller, parent=None):
        super(_FeatureSection, self).__init__('Features', parent)
        self._controller = controller
        self._widgets = {}

        grid_layout = QtGui.QGridLayout(self)

        row_i = 0

        for c in (c for c in CAPABILITY if c.name not in NON_FEATURE_CAPABILITIES):
            label = QtGui.QLabel(self.names[c])
            status = QtGui.QLabel('N/A')
            widgets = [label, status]
            if c & self.configurable:
                configure = QtGui.QLabel('<a href="{}">configure</a>'.format(c))
                configure.linkActivated.connect(self._configure)
                widgets.append(configure)
            for col_i in range(len(widgets)):
                grid_layout.addWidget(widgets[col_i], row_i, col_i)
            self._widgets[c] = widgets
            row_i += 1

        controller.capabilitiesChanged.connect(self._update)
        controller.enabledChanged.connect(self._update)
        controller.hasDeviceChanged.connect(self._update)
        self._update()

    def _configure(self, link):
        feature = int(link)
        if feature == CAPABILITY.OTP:
            dialog = SlotDialog(self._controller, self.parent())
        else:
            print('TODO:', link)
            return
        dialog.exec_()

    def _update(self, value=None):
        for c, widgets in self._widgets.items():
            if c & self._controller.capabilities:
                if c & self._controller.enabled:
                    widgets[1].setText('Enabled')
                    if c & self.configurable:
                        widgets[2].setVisible(True)
                else:
                    widgets[1].setText('Disabled')
                    if c & self.configurable:
                        widgets[2].setVisible(False)
            else:
                widgets[1].setText('Not available')
                if c & self.configurable:
                    widgets[2].setVisible(False)


class _ModeSection(QtGui.QGroupBox):
    names = dict((t, t.name + ':') for t in TRANSPORT)

    def __init__(self, controller, parent=None):
        super(_ModeSection, self).__init__('Transport protocols', parent)
        self._controller = controller

        grid_layout = QtGui.QGridLayout(self)

        row_i = 0

        grid_layout.addWidget(QtGui.QLabel('Supported:'), row_i, 0)
        self._supported_label = QtGui.QLabel()
        grid_layout.addWidget(self._supported_label, row_i, 1, 1, 2)
        row_i += 1

        grid_layout.addWidget(QtGui.QLabel('Enabled:'), row_i, 0)
        self._enabled_label = QtGui.QLabel()
        grid_layout.addWidget(self._enabled_label, row_i, 1)
        self._configure_label = QtGui.QLabel('<a href="#">configure</a>')
        self._configure_label.linkActivated.connect(self._configure)
        grid_layout.addWidget(self._configure_label, row_i, 2)

        controller.capabilitiesChanged.connect(self._update)
        controller.enabledChanged.connect(self._update)
        controller.hasDeviceChanged.connect(self._update)
        controller.canModeSwitchChanged.connect(self._update)
        self._update()

    def _configure(self, url):
        dialog = ModeDialog(self._controller, self.parent())
        dialog.exec_()

    def _update(self, value=None):
        supported = [t.name for t in
                     TRANSPORT.split(self._controller.capabilities)]
        enabled = [t.name for t in TRANSPORT.split(self._controller.enabled)]
        self._supported_label.setText(format_readable_list(supported))
        self._enabled_label.setText(format_readable_list(enabled))
        self._configure_label.setVisible(self._controller.can_mode_switch)


class InfoWidget(QtGui.QWidget):

    def __init__(self, controller, parent=None):
        super(InfoWidget, self).__init__(parent)

        self._controller = controller
        self._build_ui()

        self.startTimer(1000)

    def timerEvent(self, event):
        if QtGui.QApplication.activeWindow() == self.parent():
            self._controller.refresh()

    def _build_ui(self):
        layout = QtGui.QVBoxLayout(self)

        spacer = QtGui.QWidget()
        spacer.setFixedWidth(280)
        layout.addWidget(spacer)

        self._header = _HeaderPanel(self._controller, self)
        layout.addWidget(self._header)

        self._features = _FeatureSection(self._controller, self)
        layout.addWidget(self._features)

        self._mode = _ModeSection(self._controller, self)
        layout.addWidget(self._mode)
