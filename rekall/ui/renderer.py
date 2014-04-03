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


class BaseRenderer(object):
    """All renderers inherit from this."""

    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, session=None, fd=None, formatter=None, pager=None,
                 colorizer=None, sort=None):
        self.session = session

        self.fd = fd
        self.fd_isatty = False

        self.formatter = formatter or Formatter()
        self.colorizer = colorizer or Colorizer(
            fd, nocolor=session.GetParameter("nocolors") if session else False
        )
        self.pager = pager

    def start(self, plugin_name=None, kwargs=None):
        """Tells the plugin to prepare to output.

        Args:
          plugin_name: The name of the plugin providing output.
          kwargs: Args of the plugin.
        """
        pass

    def end(self):
        """Tells the renderer that output is done for now."""
        pass

    def write(self, data):
        """Renderer should output data."""
        pass

    def section(self, name=None, width=50):
        """Starts a new section.

        Sections are used to separate distinct entires (e.g. reports of
        different files).
        """
        if name is None:
            self.write("*" * width + "\n")
            return

        pad_len = width - len(name) - 2  # 1 space on each side.
        padding = "*" * (pad_len / 2)  # Name is centered.

        self.write("{} {} {}\n".format(padding, name, padding))

    def format(self, formatstring, *data):
        """Write formatted data.

        For renderers that need access to the raw data (e.g. to check for
        NoneObjects), it is preferred to call this method directly rather than
        to format the string in the plugin itself.

        By default we just call the format string directly.
        """
        self.write(self.formatter.format(formatstring, *data))

    def flush(self):
        """Renderer should flush data."""
        pass

    def table_header(self, title_format_list=None, suppress_headers=False,
                     name=None):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.

        Args:
           title_format_list: A list of (Name, formatstring) tuples describing
              the table headers.

           suppress_headers: If True table headers will not be written (still
              useful for formatting).

           name: The name of this table.
        """
        pass

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table.

        Supported kwargs:
          highlight: Highlight this raw according to the color scheme
            (e.g. important, good)
        """
        pass

    def record(self, record_data):
        """Writes a single complete record.

        A record consists of one object of related fields.

        Args:
          data: A list of tuples (name, short_name, formatstring, data)
        """
        for name, _, formatstring, data in record_data:
            self.format("%s: %s\n" % (name, formatstring), data)

        self.format("\n")

    def color(self, target, **kwargs):
        return self.colorizer.Render(target, **kwargs)


