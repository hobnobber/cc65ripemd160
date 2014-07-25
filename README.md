cc65ripemd160
=============

RIPEMD-160 command line utility for 6502 based computers

Tested to work with Atari 8bit (800XL / 130XE) using SpartaDos and SpartaDOS X (SDX). 
Not tested but should work with MyDOS.
Not tested but should work with other 6502 based computers like:
  VIC20
  Apple IIe
  Apple ][+
  Commodor 64
  Commodor 128

Usage: RMD160 <command> [options]

Commands:
 /H        Generate RIPEMD-160 hash
 /T        Run all tests
 /V        Display version info
 /?        Display help info
 
Options:
 /I <file> Input file, defaults to STDIN
 /O <file> Output file, defaults to STDOUT
 /Q        Quiet mode, defaulted to off
 
Program returns 0 if succesful and 1 if failed.

Bitcoin donations: 17uKHtsQegbvFpHwMKySVS558m6ZzaVLLk
