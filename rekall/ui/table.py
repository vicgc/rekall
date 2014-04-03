# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
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
#


class BaseTable(object):
    """A table is a helper object for renderer."""

    def __init__(self, columns=None):
        pass

    def render_header(self, renderer):
        pass

    def render_row(self, renderer, row=None, highlight=None):
        pass


class BaseColumn(object):
    def __init__(self, name=None, cname=None, formatter=None):
        self.name = name
        self.cname = cname
        self.formatter = formatter
    
    def render_header(self):
        return self.cname

    def render_cell(self, target):
        return self.formatter.format_field(target, "s")

