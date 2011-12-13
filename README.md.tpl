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

Usage
-----

% pedump -h

### MZ Header

% pedump --mz calc.exe

### 'Rich' Header

% pedump --rich calc.exe

### PE Header

% pedump --pe calc.exe

### Data Directory

% pedump --data-directory calc.exe

### Sections

% pedump --sections calc.exe

### Resources

% pedump --resources calc.exe

### Strings

% pedump --strings calc.exe.mui

### Imports

% pedump --imports calc.exe

### Exports

% pedump --exports calc.exe

### Packer / Compiler detection

% pedump --packer calc.exe

License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
