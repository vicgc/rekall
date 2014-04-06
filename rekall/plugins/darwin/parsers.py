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
Darwin base object parsers are all here.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall.plugins.darwin import components


def ParseDarwinNetworkInterface(interface):
    yield components.Named(
        name="%s%d" % (
            interface.if_name.deref(),
            interface.if_unit,
        ),
    )

    yield components.NetworkInterface(
        addresses=[
            (x.ifa_addr.sa_family, x.ifa_addr.deref())
            for x
            in interface.if_addrhead.tqh_first.walk_list("ifa_link.tqe_next")
        ],
    )


def ParseDarwinProcess(proc):
    yield components.Process(
        pid=proc.pid,
        parent_process=proc.ppid,
        command=proc.p_comm,
    )

    yield components.Named(
        name=proc.p_comm,
    )


def ParseDarwinHandle(fileproc, proc, fd, flags):
    yield components.Handle(
        process=proc.pid,
        resource=fileproc.autocast_fg_data(),
        fd=fd,
        flags=flags,
    )


def ParseDarwinFile(vnode, fileproc):
    yield components.File(
        handle=fileproc,
        full_path=vnode.full_path,
    )


def ParseDarwinSocket(socket, fileproc):
    pass

