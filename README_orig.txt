 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                        -- DESCRIPTION --                        |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

Melkor - An ELF File Format Fuzzer

Melkor, a fictional character from J. R. R. Tolkien's Middle-earth 
legendarium, was the first Dark Lord and master of Sauron. He's 
mentioned briefly in The Lord of the Rings and is known for:

"... Melkor had captured a number of ELVES before the Valar 
attacked him, and he tortured and corrupted them, breeding the 
first Orcs." (http://en.wikipedia.org/wiki/Morgoth)

"... Melkor was cunning and more filled with malice than ever. 
Seeing the bliss of the ELVES and remembering that it was for their 
sake that he was overthrown, Melkor desired above all things to 
corrupt them." (http://lotr.wikia.com/wiki/Melkor)

"Orcs...This has been so from the day they were bred by Melkor from 
corrupted, tortured and mutilated ELVES that may also have been 
forced to breed with other unnatural abominations in the dominion 
of the Dark Powers." (http://lotr.wikia.com/wiki/Orcs)

To honor his name, this piece of code takes an ELF, corrupts it and
creates as much Orcs as you want.

Melkor is a hybrid fuzzer (mutation-based and generation-based).
It mutates the existing data in an ELF sample given to create orcs
(malformed ELFs), however, it doesn't change values randomly (dumb 
fuzzing), instead, it fuzzes certain metadata with semi-valid values
through the use of fuzzing rules (knowledge base). Written in C, 
Melkor is a very intuitive and easy-to-use fuzzer to find functional
(and security) bugs in ELF parsers.

The fuzzing rules were designed with the following inputs in mind:
- ELF Specification violations
  * TIS ELF Specification 1.2 (May, 1995)
  * ELF-64 Object File Format 1.5 (May 1998)
- Misc ideas & considerations
- Parsing patterns in ELF software

You will find the fuzzing rules in detail and some other schematics
in the docs/ directory.



 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                        -- REQUIREMENTS --                       |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

- make
- gcc



 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                  -- COMPILATION & USAGE --                      |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
The compilation is very straightforward, just type:
$make

It will create the file 'melkor', which is the fuzzer itself, and
some other ELF files inside the templates/ folder, including normal
ELF files such as a normal ELF executable, some shared libraries, 
an static ELF (standalone executable) and some others.

By running melkor, a list of options will be shown and you will
realize that it's very intuitive and easy-to-use. All you have to
supply is the name of an ELF to be used as a template, which could
be any of the ones inside the templates/ dir.

Depending on what kind of software you want to test, you have to
choose which metadata you want to fuzz. For example, if you want
to test an OS loader, you probably might want to fuzz only the
Program Header Table (-P) and/or the Dynamic Section (-D). On the
other hand, perhaps you might want to fuzz the Section Header
Table and the ELF Header to test any antivirus engine or debugger.
Fuzzing the Symbols Tables (-s) and/or Relocations Tables (-R) on
relocatable files (.o) or shared libraries (.so) to test compilers
and/or linkers. The String Tables could be fuzzed as well (-Z).
It's up to you to decide how badly you want to corrupt an ELF }:-)

Once the orcs have been created inside the orcs_*/ dir, it's time
to test them with the help of test_fuzzed.sh, where you can simply
specify the name of the folder with the orcs to be run (OS loader
testing) or add an extra parameter to specify which program (and
its parameters) you'd like to test against every malformed ELF 
within the orcs folder. This script has the option to fuzz some
environment variables (defined as fuzzing rules as well).
Showing logs with #dmesg after running the script could be useful
to identify which program/library crashed and where that crash was.
Some examples are shown running the script without parameters.

If you want test the malformed ELFs (orcs) automatically on Windows
environment, there is included a batch script (win_test_fuzzed.bat)
with almost the same functionality of the script for *NIX.

Happy Fuzzing !


 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                           -- DIRS --                            |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

- docs/      Contains related documentation such as the detailed
             list of fuzzing rules as well as the list of ELF
             metadata dependencies.

- templates/ It has some ELF files compiled at the same time than
             melkor and could be used to feed melkor:
             foo.c    -> foo.o (ELF object)-> foo (ELF executable)
             foo.c    -> foo_static (ELF static executable)
             libfoo.c -> libfoo.so (ELF shared object)
             and some others. Type "$make templ" to see in detail
             which other ELF templates are created.

- orcs_*/    Will contain the malformed ELF files (based on the 
             given template file) created after the fuzzing process.

- src/       Melkor source code.



 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                           -- BUGS --                            |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

Please read BUGS.txt



 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                          -- CONTACT --                          |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

Name:      Alejandro Hernandez H. [nitr0us]
Twitter:   http://twitter.com/nitr0usmx
Email:     nitrousenador [at] gmail [dot] com
Website:   http://www.brainoverflow.org
Blog:      http://chatsubo-labs.blogspot.com



 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                        -- IN MEMORIAL --                        |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

This project is dedicated to the memory of one of my best friends,
Aaron Alba.



 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~
|                          -- LICENSE --                          |
 ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~

Melkor - An ELF File Format Fuzzer
Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License 
along with this program. If not, see <http://www.gnu.org/licenses/>.
