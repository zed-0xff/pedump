pedump
======

Description
-----------
A pure ruby implementation of win32 PE binary files dumper, including:

 * MZ Header
 * DOS stub
 * ['Rich' Header](http://ntcore.com/files/richsign.htm)
 * PE Header
 * Data Directory
 * Sections
 * Resources
 * Strings
 * Imports & Exports
 * PE Packer/Compiler detection
 * a conventient way to upload your PE's to http://pedump.me for a nice HTML tables with image previews, candies & stuff

Installation
------------
    gem install pedump

Usage and documentation
-----------------------

% pedump -h

License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
