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

"""This module implements a text based renderer, along with helpers."""


class TextRenderer(BaseRenderer):
    """Renderer that outputs text readable by humans and other sentients."""

    tablesep = " "
    elide = False
    last_message_len = 0


class TestRenderer(TextRenderer):
    """A special renderer which makes parsing the output of tables easier."""

    def __init__(self, **kwargs):
        super(TestRenderer, self).__init__(tablesep="||", **kwargs)


class TextTable(object):
    """A table is a collection of columns.

    This table formats all its cells using proportional text font.

    Args:
      columns: Column spec tuples (see Renderer).

      tablesep: Column separator.

      sort: Tuple of column names to sort by.

      address_size: Width (in characters) of a printed pointer.

      suppress_headers: Don't print headers.

      elide: Causes strings that are over the length limit to be shortened
        in the middle.
    """

    def __init__(self, columns=None, tablesep=" ", elide=False, sort=None,
                 suppress_headers=False, address_size=10, **kwargs):
        super(TextTable, self).__init__(**kwargs)

        self.columns = [
            TextColumn(*args, address_size=address_size, table=self)
            for args in columns]

        self.tablesep = tablesep
        self.elide = elide
        self.suppress_headers = suppress_headers
        self.sort = sort

    def write_row(self, renderer, cells, highlight=False):
        """Writes a row of the table.

        Args:
          renderer: The renderer we use to write on.
          cells: A list of cell contents. Each cell content is a list of lines
            in the cell.
        """
        foreground, background = HIGHLIGHT_SCHEME.get(
            highlight, (None, None))

        # Ensure that all the cells are the same width.
        justified_cells = []
        cell_widths = []
        max_height = 0
        for cell in cells:
            max_width = max([len(line) for line in cell])
            max_height = max(max_height, len(cell))
            justified_cell = []
            for line in cell:
                justified_cell.append(line + (' ' * (max_width-len(line))))

            justified_cells.append(justified_cell)
            cell_widths.append(max_width)

        for line in range(max_height):
            line_components = []
            for i in range(len(justified_cells)):
                try:
                    line_components.append(justified_cells[i][line])
                except IndexError:
                    line_components.append(" " * cell_widths[i])

            renderer.write(
                renderer.color(
                    self.tablesep.join(line_components),
                    foreground=foreground, background=background) + "\n")

    def render_header(self, renderer):
        # The headers must always be calculated so we can work out the column
        # widths.
        headers = [c.render_header() for c in self.columns]

        if not self.suppress_headers:
            self.write_row(renderer, headers)

    def render_row(self, renderer, row=None, highlight=None):
        self.write_row(
            renderer,
            [c.render_cell(x) for c, x in zip(self.columns, row)],
            highlight=highlight)


class TextColumn(object):
    """An implementation of a Column."""

    def __init__(self, name=None, cname=None, formatstring="s", address_size=14,
                 header_format=None, table=None):
        self.name = name or "-"
        self.cname = cname or "-"
        self.table = table
        self.wrap = None

        # How many places should addresses be padded?
        self.address_size = address_size
        self.parse_format(formatstring=formatstring,
                          header_format=header_format)

        # The format specifications is a dict.
        self.formatter = Formatter()
        self.header_width = 0

    def parse_format(self, formatstring=None, header_format=None):
        """Parse the format string into the format specification.

        We support some extended forms of format string which we process
        especially here:

        [addrpad] - This is a padded address to width self.address_size.
        [addr] - This is a non padded address.
        [wrap:width] - This wraps a stringified version of the target in the
           cell.
        """
        # Leading ! turns off eliding.
        if formatstring.startswith("!"):
            self.table.elide = True
            formatstring = formatstring[1:]

        # This means unlimited width.
        if formatstring == "":
            self.header_format = self.formatstring = ""

            # Eliding is not possible without column width limits.
            self.table.elide = False
            return

        m = re.search(r"\[addrpad\]", formatstring)
        if m:
            self.formatstring = "#0%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            # Never elide addresses - makes them unreadable.
            self.table.elide = False
            return

        m = re.search(r"\[addr\]", formatstring)
        if m:
            self.formatstring = ">#%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            self.table.elide = False
            return

        # Look for the wrap specifier.
        m = re.search(r"\[wrap:([^\]]+)\]", formatstring)
        if m:
            self.formatstring = "s"
            self.wrap = int(m.group(1))
            self.header_format = "<%ss" % self.wrap
            return

        # Fall through to a simple format specifier.
        self.formatstring = formatstring

        if header_format is None:
            self.header_format = re.sub("[Xx]", "s", formatstring)

    def render_header(self):
        """Renders the cell header."""
        header_cell = self.render_cell(
            self.name, formatstring=self.header_format, elide=False)
        self.header_width = max([len(line) for line in header_cell])

        # Append a dashed line as a table header separator.
        header_cell.append("-" * self.header_width)

        return header_cell

    def elide_string(self, string, length):
        """Elides the middle of a string if it is longer than length."""
        if length == -1:
            return string

        if len(string) < length:
            return (" " * (length - len(string))) + string

        elif len(string) == length:
            return string

        else:
            if length < 5:
                logging.error("Cannot elide a string to length less than 5")

            even = ((length + 1) % 2)
            length = (length - 3) / 2
            return string[:length + even] + "..." + string[-length:]

    def render_cell(self, target, formatstring=None, elide=None):
        """Renders obj according to the format string."""
        if formatstring is None:
            formatstring = self.formatstring

        if isinstance(target, Colorizer):
            result = []
            for x in self.render_cell(target.target, formatstring=formatstring,
                                      elide=elide):
                result.append(target.Render(x))
            return result

        # For NoneObjects we just render dashes. (Other renderers might want to
        # actually record the error, we ignore it here.).
        elif target is None or isinstance(target, obj.NoneObject):
            return ['-' * len(self.formatter.format_field(1, formatstring))]

        # Simple formatting.
        result = self.formatter.format_field(target, formatstring).splitlines()

        # Support line wrapping.
        if self.wrap:
            old_result = result
            result = []
            for line in old_result:
                result.extend(textwrap.wrap(line, self.wrap))

        elif elide is None:
            elide = self.table.elide

        if elide:
            # we take the header width as the maximum width of this column.
            result = [
                self.elide_string(line, self.header_width) for line in result]

        if isinstance(target, bool):
            color = "GREEN" if target else "RED"
            result = [
                self.table.renderer.color(x, foreground=color) for x in result]

        return result or [""]

