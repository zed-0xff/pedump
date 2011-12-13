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

    # pedump -h

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

### MZ Header

    # pedump --mz calc.exe

    === MZ Header ===
    
                         signature:                     "MZ"
               bytes_in_last_block:        144          0x90
                    blocks_in_file:          3             3
                        num_relocs:          0             0
                 header_paragraphs:          4             4
              min_extra_paragraphs:          0             0
              max_extra_paragraphs:      65535        0xffff
                                ss:          0             0
                                sp:        184          0xb8
                          checksum:          0             0
                                ip:          0             0
                                cs:          0             0
                reloc_table_offset:         64          0x40
                    overlay_number:          0             0
                         reserved0:          0             0
                            oem_id:          0             0
                          oem_info:          0             0
                         reserved2:          0             0
                         reserved3:          0             0
                         reserved4:          0             0
                         reserved5:          0             0
                         reserved6:          0             0
                            lfanew:        232          0xe8

License
-------
Released under the MIT License.  See the [LICENSE](https://github.com/zed-0xff/pedump/blob/master/LICENSE.txt) file for further details.
