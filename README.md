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

    Usage: pedump [options]
        -V, --version                    Print version information and exit
        -v, --[no-]verbose               Run verbosely
        -F, --force                      Try to dump by all means
                                         (can cause exceptions & heavy wounds)
        -f, --format FORMAT              Output format: bin,c,dump,hex,inspect,table
                                         (default: table)
            --mz
            --dos-stub
            --rich
            --pe
            --data-directory
            --sections
            --strings
            --resources
            --resource-directory
            --imports
            --exports
            --packer
        -P, --packer-only                packer/compiler detect only,
                                         mimics 'file' command output
            --all                        Dump all but resource-directory (default)
            --va2file VA                 Convert RVA to file offset
        -W, --web                        Uploads files to a http://pedump.me
                                         for a nice HTML tables with image previews,
                                         candies & stuff

License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
