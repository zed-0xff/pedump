pedump    [![Build Status](https://secure.travis-ci.org/zed-0xff/pedump.png)](http://secure.travis-ci.org/zed-0xff/pedump)  [![Dependency Status](https://gemnasium.com/zed-0xff/pedump.png)](https://gemnasium.com/zed-0xff/pedump)
======

Description
-----------
A pure ruby implementation of win32 PE binary files dumper.

Supported formats:

 * DOS MZ EXE
 * win16 NE
 * win32 PE
 * win64 PE

Can dump:

 * MZ/NE/PE Header
 * DOS stub
 * ['Rich' Header](http://ntcore.com/files/richsign.htm)
 * Data Directory
 * Sections
 * Resources
 * Strings
 * Imports & Exports
 * VS_VERSIONINFO parsing
 * PE Packer/Compiler detection
 * a convenient way to upload your PE's to http://pedump.me for a nice HTML tables with image previews, candies & stuff

Installation
------------
    gem install pedump

Usage
-----

% pedump -h

### MZ Header

% pedump --mz calc.exe

### DOS stub

% pedump --dos-stub calc.exe

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

% pedump --imports zlib.dll

### Exports

% pedump --exports zlib.dll

### VS_VERSIONINFO parsing

% pedump --version-info calc.exe

### Packer / Compiler detection

% pedump --packer zlib.dll

#### pedump can mimic 'file' command output:

    #pedump --packer-only -qqq samples/*
    
    samples/StringLoader.dll:                 Microsoft Visual C++ 6.0 DLL (Debug)
    samples/control.exe:                      ASPack v2.12
    samples/gms_v1_0_3.exe:                   UPX 2.90 [LZMA] (Markus Oberhumer, Laszlo Molnar & John Reiser)
    samples/unpackme.exe:                     ASProtect 1.33 - 2.1 Registered (Alexey Solodovnikov)
    samples/zlib.dll:                         Microsoft Visual C v2.0

License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
