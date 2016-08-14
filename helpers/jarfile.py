#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Code for handling Java jar files.
Jar files are just zip files with a particular interpretation for certain files
in the zip under the META-INF/ directory. So we can read and write them using
the standard zipfile module.
The specification for jar files is at
http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html
"""
from __future__ import with_statement
import zipfile

_MANIFEST_NAME = 'META-INF/MANIFEST.MF'


class Error(Exception):
    pass


class InvalidJarError(Error):
    pass


class JarWriteError(Error):
    pass


class Manifest(object):
    """The parsed manifest from a jar file.
    Attributes:
      main_section: a dict representing the main (first) section of the manifest.
        Each key is a string that is an attribute, such as 'Manifest-Version', and
        the corresponding value is a string that is the value of the attribute,
        such as '1.0'.
      sections: a dict representing the other sections of the manifest. Each key
        is a string that is the value of the 'Name' attribute for the section,
        and the corresponding value is a dict like the main_section one, for the
        other attributes.
    """

    def __init__(self, main_section, sections):
        self.main_section = main_section
        self.sections = sections


def read_manifest(jar_file_name):
    """Read and parse the manifest out of the given jar.
    Args:
      jar_file_name: the name of the jar from which the manifest is to be read.
    Returns:
      A parsed Manifest object, or None if the jar has no manifest.
    Raises:
      IOError: if the jar does not exist or cannot be read.
    """
    with zipfile.ZipFile(jar_file_name) as jar:
        try:
            manifest_string = jar.read(_MANIFEST_NAME)
        except KeyError:
            return None
        return _parse_manifest(manifest_string)


def _parse_manifest(manifest_string):
    """Parse a Manifest object out of the given string.
    Args:
      manifest_string: a str or unicode that is the manifest contents.
    Returns:
      A Manifest object parsed out of the string.
    Raises:
      InvalidJarError: if the manifest is not well-formed.
    """
    manifest_string = '\n'.join(manifest_string.splitlines()).rstrip('\n')
    section_strings = manifest_string.split('\n\n')
    parsed_sections = [_parse_manifest_section(s) for s in section_strings]
    main_section = parsed_sections[0]
    try:
        sections = dict((entry['Name'], entry) for entry in parsed_sections[1:])
    except KeyError:
        raise InvalidJarError('Manifest entry has no Name attribute')
    return Manifest(main_section, sections)


def _parse_manifest_section(section):
    """Parse a dict out of the given manifest section string.
    Args:
      section: a str or unicode that is the manifest section. It looks something
        like this (without the >):
        > Name: section-name
        > Some-Attribute: some value
        > Another-Attribute: another value
    Returns:
      A dict where the keys are the attributes (here, 'Name', 'Some-Attribute',
      'Another-Attribute'), and the values are the corresponding attribute values.
    Raises:
      InvalidJarError: if the manifest section is not well-formed.
    """
    section = section.replace('\n ', '')
    try:
        return dict(line.split(': ', 1) for line in section.split('\n'))
    except ValueError:
        raise InvalidJarError('Invalid manifest %r' % section)
