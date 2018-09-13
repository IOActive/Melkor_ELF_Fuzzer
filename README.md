# elf_fuzzer #
*elf_fuzzer* is fork of [Melkor_ELF_Fuzzer](https://github.com/IOActive/Melkor_ELF_Fuzzer) that ports it to several UNIX systems like FreeBSD. Since *Melkor_ELF_Fuzzer* does not seem to be actively developed, I decided to create this hard fork.

It should compile on (using `Makefile.bsd`)
- FreeBSD 11.2
- OpenBSD 6.4
- NetBSD 8.0
and ofcourse on Linux-based systems as *Melkor_ELF_Fuzzer* does (use `Makefile`).

## Bugs ## 

- [CVE-2018-6924](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2018-6924) / [FreeBSD-SA-18:12.elf](https://www.freebsd.org/security/advisories/FreeBSD-SA-18:12.elf.asc): FreeBSD kernel
- [OpenBSD 6.3 errata 012](https://ftp.openbsd.org/pub/OpenBSD/patches/6.3/common/012_execsize.patch.sig) / [OpenBSD 6.2 errata 018](https://ftp.openbsd.org/pub/OpenBSD/patches/6.2/common/018_execsize.patch.sig): OpenBSD kernel

## Credits ## 

Thanks to Alejandro Hernandez H. (nitr0us) for the original version of Melkor_ELF_Fuzzer.

## Future Work ##

To make it even greater, here are some ideas (mostly from nitr0us):

- Fuzz the (symbol) Hash Table(s) (SHT_HASH | SHT_GNU_HASH)
  These rules are marked in red in docs/Melkor_Fuzzing_Rules.pdf

- Fuzz the debug information (DWARF format)
  This rule is marked in orange in docs/Melkor_Fuzzing_Rules.pdf
  An example of a malformed DWARF payload can be seen at:
  http://www.exploit-db.com/exploits/23523/

- Smart fuzzing of SHT_REL or SHT_RELA based on the relocation scheme used
  More info: http://www.mindfruit.co.uk/2012/06/relocations-relocations.html

- Fuzz uncommon data structs in /usr/include/elf.h such as Elf*_Syminfo,
  Elf*_Verdef, etc.
