# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Darwin entity collectors are all here.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"


def DarwinNetworkInterfaces(profile):
    """Walks the global list of interfaces.

    The head of the list of network interfaces is a kernel global [1].
    The struct we use [2] is just the public part of the data [3]. Addresses
    are related to an interface in a N:1 relationship [4]. AF-specific data
    is a normal sockaddr struct.

    Yields:
      Network interfaces.

    References:
      1:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L254
      2:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L528
      3:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/dlil.c#L188
      4:
      https://github.com/opensource-apple/xnu/blob/10.9/bsd/net/if_var.h#L816

    """
    ifnet_head = profile.get_constant_object(
        "_dlil_ifnet_head",
        target="Pointer",
        target_args=dict(
            target="ifnet"
        )
    )

    for interface in ifnet_head.walk_list("if_link.tqe_next"):
        yield interface, ParseDarwinNetworkInterface(interface)


