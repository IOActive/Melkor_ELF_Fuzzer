#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#define VERSION "v1.0"

#define SWAP32(v) ((((v) & 0x000000ff) << 24) | \
                   (((v) & 0x0000ff00) <<  8) | \
                   (((v) & 0x00ff0000) >>  8) | \
                   (((v) & 0xff000000) >> 24))

/* FUZZING MODES */
#define	AUTO	(1 <<  0) // Autodetect (based on e_type)
#define	HDR	(1 <<  1) // Elf Header
#define	SHT	(1 <<  2) // Section Header Table
#define	PHT	(1 <<  3) // Program Header Table
#define	SYM	(1 <<  4) // Symbols Table
#define DYN	(1 <<  5) // Dynamic info
#define REL	(1 <<  6) // Relocation data
#define NOTE	(1 <<  7) // Notes section
#define STRS	(1 <<  8) // Strings in the file
#define ALL	(HDR | SHT | PHT | SYM | DYN | REL | NOTE | STRS)
#define ALLB	(SHT | PHT | SYM | DYN | REL | NOTE | STRS)


/* -DDEBUG was deleted from CFLAGS in Makefile.
   Add -DDEBUG if you want to print extra info.
*/
#ifdef DEBUG
#define debug(...) if(!quiet) printf(__VA_ARGS__)
#else
#define debug(...) //
#endif


/* Function pointer type 'func_ptr'. 
   It will be used to create arrays of function pointers in fuzz_*.c 
*/
typedef int (*func_ptr)(void);

int PAGESIZE; // Set at runtime with getpagesize() in melkor.c

#ifndef PT_GNU_STACK
#define PT_GNU_STACK 0x6474e551 // Indicates executable stack
#endif

#ifndef PT_GNU_RELRO
#define PT_GNU_RELRO 0x6474e552 // Read-only after relocation
#endif

#ifndef PT_PAX_FLAGS
#define PT_PAX_FLAGS 0x65041580 // PAX Flags
#endif

// SHT_GNU_*
#ifndef SHT_GNU_ATTRIBUTES
#define SHT_GNU_ATTRIBUTES 0x6ffffff5
#endif

#ifndef SHT_GNU_HASH
#define SHT_GNU_HASH 0x6ffffff6
#endif

#ifndef SHT_GNU_LIBLIST
#define SHT_GNU_LIBLIST 0x6ffffff7
#endif

#ifndef SHT_GNU_verdef
#define SHT_GNU_verdef 0x6ffffffd
#endif

#ifndef SHT_GNU_verneed
#define SHT_GNU_verneed 0x6ffffffe
#endif

#ifndef SHT_GNU_versym
#define SHT_GNU_versym 0x6fffffff
#endif

/* ELF STUFF */
/*** 32 - 64 BITS COMPAT ***/
#if defined(__i386__)           /**** x86 ****/
// Data Types
#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Sword Elf32_Sword
#define Elf_Xword Elf32_Xword
#define Elf_Sxword Elf32_Sxword
#define Elf_Addr Elf32_Addr
#define Elf_Off Elf32_Off
#define Elf_Section Elf32_Section

// Data Structs
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define Elf_Phdr Elf32_Phdr
#define Elf_Dyn Elf32_Dyn
#define Elf_Nhdr Elf32_Nhdr

// Macros
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_INFO ELF32_ST_INFO
#define ELF_ST_VISIBILITY ELF32_ST_VISIBILITY
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_INFO ELF32_R_INFO

#define HEX "%.8x"

#elif defined(__x86_64__)       /**** x86_64 ****/
// Data Types
#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Sword Elf64_Sword
#define Elf_Xword Elf64_Xword
#define Elf_Sxword Elf64_Sxword
#define Elf_Addr Elf64_Addr
#define Elf_Off Elf64_Off
#define Elf_Section Elf64_Section

// Data Structs
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rel
#define Elf_Rela Elf64_Rela
#define Elf_Phdr Elf64_Phdr
#define Elf_Dyn Elf64_Dyn
#define Elf_Nhdr Elf64_Nhdr

// Macros
#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_INFO ELF64_ST_INFO
#define ELF_ST_VISIBILITY ELF64_ST_VISIBILITY
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_INFO ELF64_R_INFO

#define HEX "%.16lx"
#else
#error  "Unsupported arch !"
#endif


/* PROTOTYPES */
void usage(const char *);
void banner();
int  elf_identification(int);
void verifySHT(void);
void verifyPHT(void);

FILE *start_logger(char *, char *);
void stop_logger(FILE *);

void fuzz_hdr(void);
void fuzz_sht(void);
void fuzz_pht(void);
void fuzz_sym(void);
void fuzz_dyn(void);
void fuzz_rel(void);
void fuzz_note(void);
void fuzz_strs(void);

unsigned int getseed(void);
Elf_Addr getElf_Addr(void);
Elf_Off getElf_Off(void);
Elf_Word getElf_Word(void);
Elf_Xword getElf_Xword(void);
Elf_Half getElf_Half(void);
Elf_Section getElf_Section(void);
char *get_fmt_str(void);
char *get_fuzzed_path(void);

Elf_Section findSectionIndexByName(char *);
void fuzzName(void);
void fuzzSize(void);
void fuzzEntSize(void);
void fuzzFlags(void);
void fuzzAddrAlign(void);

Elf_Addr get_d_ptr_by_d_tag(Elf_Sword);
Elf_Word get_d_val_by_d_tag(Elf_Sword);
