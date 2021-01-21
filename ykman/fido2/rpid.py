# Copyright (c) 2018 Yubico AB
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

"""
These functions validate RP_ID and APP_ID according to simplified TLD+1 rules,
using a bundled copy of the public suffix list fetched from:

  https://publicsuffix.org/list/public_suffix_list.dat

Advanced APP_ID values pointing to JSON files containing valid facets are not
supported by this implementation.
"""

from __future__ import absolute_import, unicode_literals

import os
import six
from six.moves.urllib.parse import urlparse


tld_fname = os.path.join(os.path.dirname(__file__), "public_suffix_list.dat")
with open(tld_fname, "rb") as f:
    suffixes = [
        entry
        for entry in (line.decode("utf8").strip() for line in f.readlines())
        if entry and not entry.startswith("//")
    ]


def verify_rp_id(rp_id, origin):
    """Checks if a Webauthn RP ID is usable for a given origin.

    :param rp_id: The RP ID to validate.
    :param origin: The origin of the request.
    :return: True if the RP ID is usable by the origin, False if not.
    """
    if isinstance(rp_id, six.binary_type):
        rp_id = rp_id.decode()
    if not rp_id:
        return False
    if isinstance(origin, six.binary_type):
        origin = origin.decode()

    url = urlparse(origin)
    if url.scheme != "https":
        return False
    host = url.hostname
    if host == rp_id:
        return True
    if host.endswith("." + rp_id) and rp_id not in suffixes:
        return True
    return False


def verify_app_id(app_id, origin):
    """Checks if a FIDO U2F App ID is usable for a given origin.

    :param app_id: The App ID to validate.
    :param origin: The origin of the request.
    :return: True if the App ID is usable by the origin, False if not.
    """
    if isinstance(app_id, six.binary_type):
        app_id = app_id.decode()
    url = urlparse(app_id)
    if url.scheme != "https":
        return False
    return verify_rp_id(url.hostname, origin)
