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


import inspect
import logging

logger = logging.getLogger(__name__)


class NoSuchCommandException(Exception):
    def __init__(self):
        super().__init__("No such command")


def command(func):
    setattr(func, "_command", func.__name__)
    return func


class CommandNode:
    def __init__(self):
        self._commands = {
            f._command: f for _, f in inspect.getmembers(self) if hasattr(f, "_command")
        }

    def _register(self, name, func):
        self._commands[name] = func

    def __call__(self, command, request, event, signal):
        if not command:
            return self.invoke(request, event, signal)
        if len(command) != 1:
            raise NoSuchCommandException()
        head = command[0]
        if head in self._commands:
            logger.debug("invoke command: %s", head)
            return self._commands[head](request, event, signal)
        raise NoSuchCommandException()

    def invoke(self, request, event, signal):
        raise NoSuchCommandException()

    def close(self):
        pass


def child(func):
    setattr(func, "_child", func.__name__)
    return func


class ParentNode(CommandNode):
    def __init__(self):
        super().__init__()
        self._child = None
        self._child_name = None
        self._children = {
            f._child: f for _, f in inspect.getmembers(self) if hasattr(f, "_child")
        }

    def __call__(self, command, request, event, signal):
        name = command[0] if command else None

        if self._child and self._child_name != name:
            logger.debug("close existing child: %s", self._child_name)
            self._child.close()
            self._child = None
            self._child_name = None

        if not self._child and name:
            try:
                self._child = self.create_child(name)
                self._child_name = name
                logger.debug("created child: %s", name)
            except NoSuchCommandException:
                pass  # No child

        if self._child:
            return self._child(command[1:], request, event, signal)

        return super().__call__(command, request, event, signal)

    def close(self):
        if self._child:
            logger.debug("close child %s", self._child_name)
            self._child.close()
            self._child = None
            self._child_name = None
        super().close()

    def create_child(self, name):
        if name in self._children:
            return self._children[name]()
        raise NoSuchCommandException()
