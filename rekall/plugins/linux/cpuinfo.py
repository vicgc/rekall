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
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

from rekall.plugins.linux import common

class Banner(common.LinuxPlugin):
    """Prints the Linux banner information."""

    __name = "banner"

    def render(self, renderer):
        renderer.table_header([("Banner", "banner", "<80")])

        banner = self.profile.get_constant_object(
            "linux_banner", target="String", vm=self.kernel_address_space)

        renderer.table_row(banner)


class CpuInfo(common.LinuxPlugin):
    ''' prints info about each active processor '''

    __name = "cpuinfo"

    def online_cpus(self):
        """returns a list of online cpus (the processor numbers)"""
        #later kernels..
        cpus = (self.profile.get_constant("cpu_online_bits") or
                self.profile.get_constant("cpu_present_map"))
        if not cpus:
            raise AttributeError("Unable to determine number of online CPUs "
                                 "for memory capture")

        bmap = self.profile.Object("unsigned long", offset=cpus, vm=self.kernel_address_space)

        for i in xrange(0, 8):
            if bmap & (1 << i):
                yield i

    def calculate(self):

        cpus = list(self.online_cpus())

        if len(cpus) > 1 and self.profile.get_constant("per_cpu__cpu_info"):
            return self.get_info_smp()

        elif self.profile.get_constant("boot_cpu_data"):
            return self.get_info_single()

        else:
            raise AttributeError("Unable to get CPU info for memory capture")

    def get_info_single(self):
        cpu = self.profile.Object("cpuinfo_x86",
                                  offset=self.profile.get_constant("boot_cpu_data"),
                                  vm=self.kernel_address_space)
        yield 0, cpu

    # pulls the per_cpu cpu info
    # will break apart the per_cpu code if a future plugin needs it
    def get_info_smp(self):
        cpus = list(self.online_cpus())

        # get the highest numbered cpu
        max_cpu = cpus[-1]

        per_offsets = self.profile.Array(
            target='unsigned long', count=max_cpu,
            offset=self.profile.get_constant("__per_cpu_offset"),
            vm=self.kernel_address_space)

        i = 0

        for i in cpus:
            offset = per_offsets[i]

            addr = self.get_constant("per_cpu__cpu_info") + offset.v()
            var = self.profile.Object("cpuinfo_x86", offset=addr,
                                      vm=self.kernel_address_space)
            yield i, var

    def render(self, renderer):
        renderer.table_header([("CPU", "processor", "<4"),
                               ("Vendor", "vendor", "<20"),
                               ("Model", "model", "<80")
                               ])
        for processor, cpu in self.calculate():
            renderer.table_row(processor, cpu.x86_vendor_id, cpu.x86_model_id)

