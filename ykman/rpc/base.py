# Copyright (c) 2021 Yubico AB
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


import logging

logger = logging.getLogger(__name__)


class NoSuchActionException(Exception):
    def __init__(selfi, name):
        super().__init__(f"No such action: {name}")


class NoSuchNodeException(Exception):
    def __init__(self, name):
        super().__init__(f"No such node: {name}")


MARKER_ACTION = "_rpc_action_marker"
MARKER_CHILD = "_rpc_child_marker"


def action(func):
    setattr(func, MARKER_ACTION, True)
    return func


def child(func):
    setattr(func, MARKER_CHILD, True)
    return func


class RpcNode:
    def __init__(self):
        self._child = None
        self._child_name = None

    def __call__(self, action, target, params, event, signal):
        if target:
            return self.get_child(target.pop(0))(action, target, params, event, signal)
        if action in self.list_actions():
            return self.get_action(action)(params, event, signal)
        if action in self.list_children():
            return self.get_child(action)("get", [], params, event, signal)
        raise NoSuchActionException(action)

    def close(self):
        if self._child:
            self._close_child()

    def get_data(self):
        return dict()

    def list_actions(self):
        return [
            name for name in dir(self) if hasattr(getattr(self, name), MARKER_ACTION)
        ]

    def get_action(self, name):
        if self._child:
            self._close_child()
        action = getattr(self, name, None)
        if hasattr(action, MARKER_ACTION):
            return action
        raise NoSuchActionException(name)

    def list_children(self):
        return {
            name: {} for name in dir(self) if hasattr(getattr(self, name), MARKER_CHILD)
        }

    def create_child(self, name):
        child = getattr(self, name, None)
        if hasattr(child, MARKER_CHILD):
            return child()
        raise NoSuchNodeException(name)

    def _close_child(self):
        if self._child:
            logger.debug("close existing child: %s", self._child_name)
            self._child.close()
            self._child = None
            self._child_name = None

    def get_child(self, name):
        if self._child and self._child_name != name:
            self._close_child()

        if not self._child:
            self._child = self.create_child(name)
            self._child_name = name
            logger.debug("created child: %s", name)

        return self._child

    @action
    def get(self, params, event, signal):
        return dict(
            data=self.get_data(),
            actions=self.list_actions(),
            children=self.list_children(),
        )
