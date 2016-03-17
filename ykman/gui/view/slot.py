# Copyright (c) 2016 Yubico AB
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

from PySide import QtGui, QtCore

from ykman.yubicommon import qt
from .. import messages as m


class _SlotStatus(QtGui.QWidget):

    def __init__(self, parent=None):
        super(_SlotStatus, self).__init__(parent)

        layout = QtGui.QGridLayout(self)
        layout.addWidget(QtGui.QLabel('<h2>YubiKey slot configuration</h2>'), 0, 0, 1, 4)

        layout.addWidget(QtGui.QLabel('Slot 1 (short press):'), 1, 0)
        self._slot1_lbs = (QtGui.QLabel(), QtGui.QLabel(), QtGui.QLabel())
        self._slot1_lbs[1].linkActivated.connect(lambda x: self.parent().configure(int(x)))
        self._slot1_lbs[2].linkActivated.connect(lambda x: self.parent().erase(int(x)))
        layout.addWidget(self._slot1_lbs[0], 1, 1)
        layout.addWidget(self._slot1_lbs[1], 1, 2)
        layout.addWidget(self._slot1_lbs[2], 1, 3)

        layout.addWidget(QtGui.QLabel('Slot 2 (long press):'), 2, 0)
        self._slot2_lbs = (QtGui.QLabel(), QtGui.QLabel(), QtGui.QLabel())
        self._slot2_lbs[1].linkActivated.connect(lambda x: self.parent().configure(int(x)))
        self._slot2_lbs[2].linkActivated.connect(lambda x: self.parent().erase(int(x)))
        layout.addWidget(self._slot2_lbs[0], 2, 1)
        layout.addWidget(self._slot2_lbs[1], 2, 2)
        layout.addWidget(self._slot2_lbs[2], 2, 3)

        self._swap_slots = QtGui.QLabel('Reading state...')
        self._swap_slots.linkActivated.connect(lambda _: self.parent().swap())
        layout.addWidget(self._swap_slots, 3, 0)

        buttons = QtGui.QDialogButtonBox(QtGui.QDialogButtonBox.Close)
        buttons.rejected.connect(self.parent().back)
        layout.addWidget(buttons, 4, 0, 1, 4)

        parent.slot_status.connect(self._slots_cb)

    def _slots_cb(self, slots):
        (stat1, stat2) = slots
        self._slot1_lbs[0].setText('Configured' if stat1 else 'Blank')
        self._slot1_lbs[1].setText('<a href="1">{}</a>'.format('re-configure' if stat1 else 'configure'))
        self._slot1_lbs[2].setText('<a href="1">erase</a>' if stat1 else '')
        self._slot2_lbs[0].setText('Configured' if stat2 else 'Blank')
        self._slot2_lbs[1].setText('<a href="2">{}</a>'.format('re-configure' if stat2 else 'configure'))
        self._slot2_lbs[2].setText('<a href="2">erase</a>' if stat2 else '')

        if stat1 or stat2:
            self._swap_slots.setText('<a href="#">swap configurations</a>')
            self._swap_slots.setDisabled(False)
        else:
            color = QtGui.QApplication.palette() \
                .color(QtGui.QPalette.Disabled, QtGui.QPalette.WindowText)
            self._swap_slots.setText('<a href="#" style="color: {};">swap configurations</a>'.format(color.name()))
            self._swap_slots.setDisabled(True)


class _WizardPage(QtGui.QWidget):
    title_text = 'YubiKey Slot configuration'
    description = None
    reject_text = 'Previous'
    accept_text = 'Next'

    def __init__(self, slot, parent):
        super(_WizardPage, self).__init__(parent)

        self._slot = slot

        layout = QtGui.QFormLayout(self)
        layout.addRow(QtGui.QLabel('<h2>{}</h2>'.format(self.title_text)))

        if slot is not None and parent._slot_status[slot - 1]:
            layout.addRow(QtGui.QLabel('<b>WARNING:</b> This will overwrite the existing configuration!'))

        if self.description is not None:
            layout.addRow(QtGui.QLabel(self.description))

        self._build_ui(layout)

        buttons = QtGui.QDialogButtonBox()
        self._accept_btn = QtGui.QPushButton(self.accept_text)
        self._reject_btn = QtGui.QPushButton(self.reject_text)
        buttons.addButton(self._reject_btn, QtGui.QDialogButtonBox.RejectRole)
        buttons.addButton(self._accept_btn, QtGui.QDialogButtonBox.AcceptRole)
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(parent.back)
        layout.addRow(buttons)

    def setPrevEnabled(self, state):
        self._reject_btn.setEnabled(state)

    def setNextEnabled(self, state):
        self._accept_btn.setEnabled(state)

    def _build_ui(self, layout):
        pass

    def _accept(self):
        print('TODO: Next')


class _DeleteSlotPage(_WizardPage):
    description = 'Permanently deletes the contents of this slot.'
    accept_text = 'Delete'

    def __init__(self, slot, parent):
        super(_DeleteSlotPage, self).__init__(slot, parent)

    @property
    def title_text(self):
        return 'Erase YubiKey slot {}'.format(self._slot)

    def _accept(self):
        page = _WritingConfig(self.title_text, 'Erasing configuration...', self.parent())
        self.parent().push(page)
        self.parent()._controller.delete_slot(self._slot, lambda _: page.complete('Configuration erased!'))


class _SwapSlotsPage(_WizardPage):
    title_text = 'Swap YubiKey slots'
    description = 'Swaps the credentials between slots 1 and 2.'
    accept_text = 'Swap'

    def __init__(self, parent):
        super(_SwapSlotsPage, self).__init__(None, parent)

    def _accept(self):
        page = _WritingConfig(self.title_text, 'Writing configuration...', self.parent())
        self.parent().push(page)
        self.parent()._controller.swap_slots(
            lambda _: page.complete('Configuration successfully written!'))


class _ConfigureSlotType(_WizardPage):
    description = 'Select the type of functionality to program:'

    def __init__(self, slot, parent):
        super(_ConfigureSlotType, self).__init__(slot, parent)
        self.setNextEnabled(False)

    def _build_ui(self, layout):
        self._action = QtGui.QButtonGroup(self)
        self._action_otp = QtGui.QRadioButton('YubiKey OTP')
        self._action_cr = QtGui.QRadioButton('Challenge-response')
        self._action_pw = QtGui.QRadioButton('Static password')
        self._action_hotp = QtGui.QRadioButton('OATH-HOTP')
        self._action.addButton(self._action_otp)
        self._action.addButton(self._action_cr)
        self._action.addButton(self._action_pw)
        self._action.addButton(self._action_hotp)
        layout.addWidget(self._action_otp)
        layout.addWidget(self._action_cr)
        layout.addWidget(self._action_pw)
        layout.addWidget(self._action_hotp)
        self._action.buttonClicked.connect(lambda x: self.setNextEnabled(True))

    @property
    def title_text(self):
        return 'Configure YubiKey slot {}'.format(self._slot)

    def _accept(self):
        action = self._action.checkedButton()
        if action == self._action_otp:
            self.parent().push(_ConfigureOTP(self._slot, self.parent()))
        elif action == self._action_pw:
            self.parent().push(_ConfigureStaticPassword(self._slot, self.parent()))


class _ConfigureOTP(_WizardPage):
    description = 'When triggered, the YubiKey will output a one time password.'
    accept_text = 'Write configuration'

    def __init__(self, slot, parent):
        super(_ConfigureOTP, self).__init__(slot, parent)

    @property
    def title_text(self):
        return 'Configure YubiKey OTP for slot {}'.format(self._slot)

    def _build_ui(self, layout):
        layout.addRow('Secret key:', QtGui.QLineEdit())
        layout.addRow('Public identity:', QtGui.QLineEdit())
        layout.addRow('Private identity:', QtGui.QLineEdit())

    def _accept(self):
        page = _WritingConfig(self.title_text, 'Writing configuration...', self.parent())
        self.parent().push(page)
        print ('TODO: write config')
        page.complete('Configuration successfully written!')


class _ConfigureStaticPassword(_WizardPage):
    description = 'When triggered, the YubiKey will output a fixed password.'
    accept_text = 'Write configuration'

    def __init__(self, slot, parent):
        super(_ConfigureStaticPassword, self).__init__(slot, parent)
        self.setNextEnabled(False)

    @property
    def title_text(self):
        return 'Configure static password for slot {}'.format(self._slot)

    def _build_ui(self, layout):
        self._static_pw = QtGui.QLineEdit()
        self._static_pw.textChanged.connect(lambda t: self.setNextEnabled(bool(t)))
        layout.addRow('Password:', self._static_pw)

    def _accept(self):
        page = _WritingConfig(self.title_text, 'Writing configuration...', self.parent())
        self.parent().push(page)
        self.parent()._controller.program_static(
            self._slot, self._static_pw.text(),
            lambda _: page.complete('Configuration successfully written!'))


class _WritingConfig(_WizardPage):
    accept_text = 'Finish'

    def __init__(self, title, message, parent):
        self.title_text = title
        self._message = QtGui.QLabel(message)

        super(_WritingConfig, self).__init__(None, parent)
        self.setPrevEnabled(False)
        self.setNextEnabled(False)

    def _build_ui(self, layout):
        layout.addRow(self._message)

    def _accept(self):
        self.parent().reset()

    def complete(self, message):
        self._message.setText(message)
        self.setNextEnabled(True)


class SlotDialog(qt.Dialog):
    slot_status = QtCore.Signal(tuple)

    def __init__(self, controller, parent=None):
        super(SlotDialog, self).__init__(parent)

        self._controller = controller
        self._slot_status = (False, False)

        self.setWindowTitle('Configure YubiKey slots')

        QtGui.QStackedLayout(self)
        spacer = QtGui.QWidget()
        spacer.setFixedWidth(400)
        self.layout().addWidget(spacer)

        self.reset(True)

    def _slots_cb(self, res):
        self._slot_status = res
        self.slot_status.emit(res)

    def reset(self, initial=False):
        self._widget_stack = []
        if not initial:
            self.layout().removeWidget(self.layout().currentWidget())
        self.layout().insertWidget(0, _SlotStatus(self))
        self.layout().setCurrentIndex(0)
        self._controller.read_slots(self._slots_cb)

    def push(self, widget):
        current = self.layout().currentWidget()
        if current:
            self._widget_stack.append(current)
            self.layout().removeWidget(current)
        self.layout().insertWidget(0, widget)
        self.layout().setCurrentIndex(0)
        self.adjustSize()

    def back(self):
        if self._widget_stack:
            self.layout().removeWidget(self.layout().currentWidget())
            self.layout().insertWidget(0, self._widget_stack.pop())
            self.layout().setCurrentIndex(0)
            self.adjustSize()
        else:
            self.reject()

    def configure(self, slot):
        self.push(_ConfigureSlotType(slot, self))

    def erase(self, slot):
        self.push(_DeleteSlotPage(slot, self))

    def swap(self):
        self.push(_SwapSlotsPage(self))
