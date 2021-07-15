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


from .device import RootNode

from queue import Queue
from threading import Thread, Event
from typing import Callable, Dict, List

import logging

logger = logging.getLogger(__name__)


def _handle_incoming(event, recv, error, cmd_queue):
    while True:
        request = recv()
        if not request:
            break
        try:
            if "signal" in request:
                # Cancel signals are handled here, the rest forwarded
                if request["signal"] == "cancel":
                    event.set()
                else:
                    # Ignore other signals
                    logger.error("Unhandled signal: %r", request)
            elif "action" in request:
                cmd_queue.join()  # Wait for existing command to complete
                event.clear()  # Reset event for next command
                cmd_queue.put(request)
            else:
                error(Exception("Unsupported message type"))
        except Exception as e:
            error(e)
    event.set()
    cmd_queue.put(None)


def process(
    send: Callable[[Dict], None],
    recv: Callable[[], Dict],
    handler: Callable[[str, List, Dict, Event, Callable[[str], None]], Dict],
) -> None:
    def error(e):
        logger.error("Returning error", exc_info=e)
        send(dict(result="error", message=str(e)))

    def signal(name: str, **kwargs):
        send(dict(signal=name, **kwargs))

    def success(data: Dict):
        send(dict(result="success", **data))

    event = Event()
    cmd_queue: Queue = Queue(1)
    read_thread = Thread(target=_handle_incoming, args=(event, recv, error, cmd_queue))
    read_thread.start()

    while True:
        request = cmd_queue.get()
        if request is None:
            break
        try:
            success(
                handler(
                    request.pop("action"),
                    request.pop("target", []),
                    request.pop("params", {}),
                    event,
                    signal,
                )
            )
        except Exception as e:
            error(e)
        cmd_queue.task_done()

    read_thread.join()


def run_rpc(
    send: Callable[[Dict], None],
    recv: Callable[[], Dict],
) -> None:
    process(send, recv, RootNode())
