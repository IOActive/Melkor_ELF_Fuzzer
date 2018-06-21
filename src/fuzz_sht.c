/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"
#include <sys/stat.h>

#ifdef BSD
#define SHT_NUM 19
#endif

#define N_RULES_SHT 37 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr sht[N_RULES_SHT + 1];
int sh = 0; // Section Header. Used inside the for() loop in fuzz_sht() and will be used in the rules

void initialize_sht_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int mode; // Metadata to fuzz (parameters given in argv[])
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern struct stat elfstatinfo;
extern char *dirname_orcfname;
extern char *elfptr, *orcptr;
extern Elf_Ehdr *elfHDR;
extern Elf_Ehdr	*orcHDR;
extern Elf_Shdr *elfSHT;
extern Elf_Shdr	*orcSHT;
extern Elf_Shdr *orcOrigSHT;
extern Elf_Off elfshstrtab_offset;

void fuzz_sht()
{
	int rule;

	for(sh = 0; sh < orcHDR->e_shnum; sh++, orcSHT++)
		for(rule = 1; rule <= N_RULES_SHT; rule++)
			if((rand() % like_a) < like_b)
				if(sht[rule]()){
					printf(". ");
					debug("SHT[%d] rule [%.2d] executed\n", sh, rule);
					fprintf(logfp, " | SHT[%d] rule [%.2d] executed\n", sh, rule);
				}
}

int sht1(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & SYM)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				if(rand() % 3 < 2)
					return 0;
			break;
		default:
			if(rand() % 2)
				return 0;
	}

	fuzzName();

	fprintf(logfp, "(SHT[%d]->sh_name = 0x%x)", sh, orcSHT->sh_name);

	return 1;
}

int sht2(void)
{
	if(rand() % 3 == 0)
		return 0;

	orcSHT->sh_addr = getElf_Addr();

	fprintf(logfp, "(SHT[%d]->sh_addr = 0x"HEX")", sh, orcSHT->sh_addr);

	return 1;
}

int sht3(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & (SYM | REL)) // In REL, sh_offset of the symbol table will be needed
				return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				return 0;
			break;
		default:
			if(rand() % 5 < 4) // 80% chance
				return 0;
	}

	orcSHT->sh_offset = getElf_Off();

	fprintf(logfp, "(SHT[%d]->sh_offset = 0x"HEX")", sh, orcSHT->sh_offset);

	return 1;
}

int sht4(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				if(rand() % 2) // 50% chance
					return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				if(rand() % 2)
					return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				if(rand() % 4 < 3)
					return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & SYM)
				if(rand() % 4 < 3)
					return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				if(rand() % 4 < 3)
					return 0;
			break;
		default:
			if(rand() % 3 < 2)
				return 0;
	}

	fuzzSize();

	fprintf(logfp, "(SHT[%d]->sh_size = 0x"HEX")", sh, orcSHT->sh_size);

	return 1;
}

int sht5(void)
{
	fuzzAddrAlign();

	fprintf(logfp, "(SHT[%d]->sh_addralign = 0x"HEX")", sh, orcSHT->sh_addralign);

	return 1;
}

int sht6(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_DYNAMIC:
			if(mode & DYN)
				if(rand() % 4 < 3)
					return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & SYM)
				if(rand() % 4 < 3)
					return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				if(rand() % 4 < 3)
					return 0;
			break;
		default:
			if(rand() % 2)
				return 0;
	}

	fuzzEntSize();

	fprintf(logfp, "(SHT[%d]->sh_entsize = 0x"HEX")", sh, orcSHT->sh_entsize);

	return 1;
}

int sht7(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
				return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				return 0;
			break;
		default:
			if(rand() % 4 < 3)
				return 0;
	}

	if(rand() % 4 < 3){ // 75% chance
		Elf_Word t;

		while((t = rand() % SHT_NUM)){
			switch(t){ // Metadata dependencies
				case SHT_STRTAB:
					if(mode & STRS)
						continue;
					break;
				case SHT_NOTE:
					if(mode & NOTE)
						continue;
					break;
				case SHT_DYNAMIC:
					if(mode & DYN)
						continue;
					break;
				case SHT_SYMTAB:
				case SHT_DYNSYM:
					if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
						continue;
					break;
				case SHT_REL:
				case SHT_RELA:
					if(mode & REL)
						continue;
					break;
				default:
					break;
			}

			break;
		}

		orcSHT->sh_type = t;
	} else
		orcSHT->sh_type = getElf_Word();

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x)", sh, orcSHT->sh_type);

	return 1;
}

int sht8(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
				return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				return 0;
			break;
		default:
			if(rand() % 5 < 4) // 80% chance
				return 0;
	}

	int r = rand();

	if(r % 4 == 0)
		orcSHT->sh_type = SHT_LOPROC + 1;
	else if(r % 4 == 1)
		orcSHT->sh_type = SHT_HIPROC;
	else if(r % 4 == 2)
		orcSHT->sh_type = SHT_LOUSER + 1;
	else
		orcSHT->sh_type = SHT_HIUSER;

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x)", sh, orcSHT->sh_type);

	return 1;
}

int sht9(void)
{
	if(orcSHT->sh_type != SHT_NULL)
		return 0;

	fuzzName();
	fuzzSize();
	fuzzEntSize();
	orcSHT->sh_offset = getElf_Off();

	fprintf(logfp, "(SHT[%d]->sh_name = 0x%x,", sh, orcSHT->sh_name);
	fprintf(logfp, " sh_offset = 0x"HEX",", orcSHT->sh_offset);
	fprintf(logfp, " sh_size = 0x"HEX",", orcSHT->sh_size);
	fprintf(logfp, " sh_entsize = 0x"HEX")", orcSHT->sh_entsize);

	return 1;
}

int sht10(void)
{
	fuzzFlags();

	fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", sh, orcSHT->sh_flags);

	return 1;
}
int sht11(void)
{
	if(orcSHT->sh_type != SHT_DYNAMIC &&
		orcSHT->sh_type != SHT_HASH &&
		orcSHT->sh_type != SHT_GNU_HASH)
		return 0;

	Elf_Word l;

	if(rand() % 2)
		orcSHT->sh_info = 1 + (rand() % (orcHDR->e_shnum - 1));
	else
		orcSHT->sh_info = getElf_Word();

	if(orcSHT->sh_type == SHT_DYNAMIC){
		if(mode & DYN){
			if(rand() % 2){
				fprintf(logfp, "(SHT[%d]->sh_info = 0x%x)", sh, orcSHT->sh_info);

				return 1;
			} else {
				if(rand() % 4 < 3){
					while((l = 1 + (rand() % (orcHDR->e_shnum - 1))))
						if(orcOrigSHT[l].sh_type != SHT_STRTAB)
							break;
				} else
					l = (Elf_Word) getElf_Half();

				orcSHT->sh_link = l;
			}
		} else {
			if(rand() % 2)
				orcSHT->sh_link = 1 + (rand() % (orcHDR->e_shnum - 1));
			else
				orcSHT->sh_link = (Elf_Word) getElf_Half();
		}
	} else { // HASH
		if(rand() % 4 < 3){
			while((l = 1 + (rand() % (orcHDR->e_shnum - 1))))
				if(orcOrigSHT[l].sh_type != SHT_SYMTAB && orcOrigSHT[l].sh_type != SHT_DYNSYM)
					break;
		} else
			l = (Elf_Word) getElf_Half();

		orcSHT->sh_link = l;
	}

	fprintf(logfp, "(SHT[%d]->sh_link = 0x%x,", sh, orcSHT->sh_link);
	fprintf(logfp, " sh_info = 0x%x)", orcSHT->sh_info);

	return 1;
}

int sht12(void)
{
	if(orcSHT->sh_type != SHT_REL &&
		orcSHT->sh_type != SHT_RELA)
		return 0;

	Elf_Word l;

	if(mode & REL){
		if(rand() % 2){
			if(rand() % 2)
				orcSHT->sh_info = 1 + (rand() % (orcHDR->e_shnum - 1));
			else
				orcSHT->sh_info = getElf_Word();

			fprintf(logfp, "(SHT[%d]->sh_info = 0x%x)", sh, orcSHT->sh_info);

			return 1;
		} else
			return 0;
	} else {
		if(rand() % 4 < 3){
			while((l = 1 + (rand() % (orcHDR->e_shnum - 1))))
				if(orcOrigSHT[l].sh_type != SHT_SYMTAB && orcOrigSHT[l].sh_type != SHT_DYNSYM)
					break;
		} else
			l = (Elf_Word) getElf_Half();

		orcSHT->sh_link = l;

		if(rand() % 2)
			orcSHT->sh_info = 1 + (rand() % (orcHDR->e_shnum - 1));
		else
			orcSHT->sh_info = getElf_Word();
	}

	fprintf(logfp, "(SHT[%d]->sh_link = 0x%x,", sh, orcSHT->sh_link);
	fprintf(logfp, " sh_info = 0x%x)", orcSHT->sh_info);

	return 1;
}

int sht13(void)
{
	if(orcSHT->sh_type != SHT_SYMTAB &&
		orcSHT->sh_type != SHT_DYNSYM)
		return 0;

	if(mode & REL) // In REL, sh_link is the associated symbol table
		if(rand() % 3 < 2)
			return 0;

	if(mode & SYM)
		if(rand() % 2)
			return 0;

	if(rand() % 2){
		if(rand() % 2)
			orcSHT->sh_info = 1 + (rand() % (orcHDR->e_shnum - 1));
		else
			orcSHT->sh_info = (Elf_Word) getElf_Half();

		Elf_Word l;

		if(rand() % 4 < 3){
			while((l = 1 + (rand() % (orcHDR->e_shnum - 1))))
				if(orcOrigSHT[l].sh_type != SHT_STRTAB)
					break;
		} else
			l = (Elf_Word) getElf_Half();

		orcSHT->sh_link = l;
	} else
		return 0;

	fprintf(logfp, "(SHT[%d]->sh_link = 0x%x,", sh, orcSHT->sh_link);
	fprintf(logfp, " sh_info = 0x%x)", orcSHT->sh_info);

	return 1;
}

int sht14(void)
{
	if(orcSHT->sh_type != SHT_NOBITS)
		return 0;

	fuzzFlags();
	fuzzSize();

	fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX",", sh, orcSHT->sh_flags);
	fprintf(logfp, " sh_size = 0x"HEX")", orcSHT->sh_size);

	return 1;
}

int sht15(void)
{
	Elf_Section ndx;

	if(!(ndx = findSectionIndexByName(".data")))
		return 0;

	// Return if not the current section header being fuzzed
	if(ndx != sh)
		return 0;

	if(rand() % 2){
		if(rand() % 2){
			Elf_Word t;

			while((t = rand() % SHT_NUM)){
				switch(t){
					case SHT_STRTAB:
						if(mode & STRS)
							continue;
						break;
					case SHT_NOTE:
						if(mode & NOTE)
							continue;
						break;
					case SHT_DYNAMIC:
						if(mode & DYN)
							continue;
						break;
					case SHT_SYMTAB:
					case SHT_DYNSYM:
						if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
							continue;
						break;
					case SHT_REL:
					case SHT_RELA:
						if(mode & REL)
							continue;
						break;
					default:
						break;
				}

				break;
			}

			orcSHT->sh_type = t;
		} else
			orcSHT->sh_type = getElf_Word();
	}

	fuzzFlags();
	fuzzSize();

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x,", sh, orcSHT->sh_type);
	fprintf(logfp, " sh_size = 0x"HEX",", orcSHT->sh_size);
	fprintf(logfp, " sh_flags = 0x"HEX")", orcSHT->sh_flags);

	return 1;
}

int sht16(void)
{
	if(orcSHT->sh_type != SHT_HASH &&
		orcSHT->sh_type != SHT_GNU_HASH)
		return 0;

	fuzzSize();
	fuzzEntSize();
	fuzzFlags();
	fuzzAddrAlign();

	fprintf(logfp, "(SHT[%d]->sh_size = 0x"HEX",", sh, orcSHT->sh_size);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " sh_entsize = 0x"HEX",", orcSHT->sh_entsize);
	fprintf(logfp, " sh_addralign = 0x"HEX")", orcSHT->sh_addralign);

	return 1;
}

int sht17(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section dar = findSectionIndexByName(".debug_aranges");
	Elf_Section din = findSectionIndexByName(".debug_info");
	Elf_Section dab = findSectionIndexByName(".debug_abbrev");
	Elf_Section dli = findSectionIndexByName(".debug_line");
	Elf_Section dst = findSectionIndexByName(".debug_str");

	if(dar != sh && din != sh && dab != sh && dli != sh && dst != sh)
		return 0;

	if(rand() % 2){
		if(rand() % 2){
			Elf_Word t;

			while((t = rand() % SHT_NUM)){
				switch(t){
					case SHT_STRTAB:
						if(mode & STRS)
							continue;
						break;
					case SHT_NOTE:
						if(mode & NOTE)
							continue;
						break;
					case SHT_DYNAMIC:
						if(mode & DYN)
							continue;
						break;
					case SHT_SYMTAB:
					case SHT_DYNSYM:
						if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
							continue;
						break;
					case SHT_REL:
					case SHT_RELA:
						if(mode & REL)
							continue;
						break;
					default:
						break;
				}

				break;
			}

			orcSHT->sh_type = t;
		} else
			orcSHT->sh_type = getElf_Word();
	}

	fuzzFlags();
	fuzzSize();
	fuzzEntSize();

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x,", sh, orcSHT->sh_type);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " sh_size = 0x"HEX",", orcSHT->sh_size);
	fprintf(logfp, " sh_entsize = 0x"HEX")", orcSHT->sh_entsize);

	return 1;
}

int sht18(void)
{
	if(orcSHT->sh_type != SHT_DYNAMIC)
		return 0;

	orcSHT->sh_flags &= ~SHF_ALLOC;
	orcSHT->sh_flags &= ~SHF_WRITE;

	fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", sh, orcSHT->sh_flags);

	return 1;
}

int sht19(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section rodata  = findSectionIndexByName(".rodata");
	Elf_Section rodata1 = findSectionIndexByName(".rodata1");

	if(rodata != sh && rodata1 != sh)
		return 0;

	if(rand() % 2){
		if(rand() % 2){
			Elf_Word t;

			while((t = rand() % SHT_NUM)){
				switch(t){
					case SHT_STRTAB:
						if(mode & STRS)
							continue;
						break;
					case SHT_NOTE:
						if(mode & NOTE)
							continue;
						break;
					case SHT_DYNAMIC:
						if(mode & DYN)
							continue;
						break;
					case SHT_SYMTAB:
					case SHT_DYNSYM:
						if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
							continue;
						break;
					case SHT_REL:
					case SHT_RELA:
						if(mode & REL)
							continue;
						break;
					default:
						break;
				}

				break;
			}

			orcSHT->sh_type = t;
		} else
			orcSHT->sh_type = getElf_Word();
	}

	fuzzFlags();
	fuzzSize();
	fuzzEntSize();

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x,", sh, orcSHT->sh_type);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " sh_size = 0x"HEX",", orcSHT->sh_size);
	fprintf(logfp, " sh_entsize = 0x"HEX")", orcSHT->sh_entsize);

	return 1;
}

int sht20(void)
{
	if(orcSHT->sh_type != SHT_NOTE)
		return 0;

	if(mode & NOTE)
		if(rand() % 2)
			return 0;

#if defined(__i386__)
	Elf_Word s;
#elif defined(__x86_64__)
	Elf_Xword s;
#endif

	int r = rand();

	if(r % 3 == 0) // If running in 64 bits, set a size modulo the 32-bits struct's size and viceversa
#if defined(__i386__)
		s = sizeof(Elf64_Nhdr);
#elif defined(__x86_64__)
		s = sizeof(Elf32_Nhdr);
#endif
	else if(r % 3 == 1){
		while((s = rand() & 0x00ffffff))
			if(s % 4 != 0)
				break;
	} else // Just the size of the header of the running platform
		s = sizeof(Elf_Nhdr);

	orcSHT->sh_size = s;

	fuzzFlags();
	fuzzEntSize();
	fuzzAddrAlign();

	fprintf(logfp, "(SHT[%d]->sh_size = 0x"HEX",", sh, orcSHT->sh_size);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " sh_entsize = 0x"HEX",", orcSHT->sh_entsize);
	fprintf(logfp, " sh_addralign = 0x"HEX")", orcSHT->sh_addralign);

	return 1;
}

int sht21(void)
{
	if(orcSHT->sh_type != SHT_STRTAB)
		return 0;

	if(mode & STRS)
		if(rand() % 2)
			return 0;

	fuzzFlags();
	fuzzSize();
	fuzzEntSize();
	fuzzAddrAlign();

	fprintf(logfp, "(SHT[%d]->sh_size = 0x"HEX",", sh, orcSHT->sh_size);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " sh_entsize = 0x"HEX",", orcSHT->sh_entsize);
	fprintf(logfp, " sh_addralign = 0x"HEX")", orcSHT->sh_addralign);

	return 1;
}

int sht22(void)
{
	if(orcSHT->sh_type != SHT_SYMTAB &&
		orcSHT->sh_type != SHT_DYNSYM)
		return 0;

	if(mode & SYM)
		if(rand() % 4 < 3)
			return 0;

	fuzzFlags();
	fuzzSize();
	fuzzEntSize();
	fuzzAddrAlign();

	fprintf(logfp, "(SHT[%d]->sh_size = 0x"HEX",", sh, orcSHT->sh_size);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " sh_entsize = 0x"HEX",", orcSHT->sh_entsize);
	fprintf(logfp, " sh_addralign = 0x"HEX")", orcSHT->sh_addralign);

	return 1;
}

int sht23(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section ndx;

	if(!(ndx = findSectionIndexByName(".text")))
		return 0;

	// Return if not the current section header being fuzzed
	if(ndx != sh)
		return 0;

	if(rand() % 2){
		Elf_Word t;

		while((t = rand() % SHT_NUM)){
			switch(t){
				case SHT_PROGBITS:
					continue;
					break;
				case SHT_STRTAB:
					if(mode & STRS)
						continue;
					break;
				case SHT_NOTE:
					if(mode & NOTE)
						continue;
					break;
				case SHT_DYNAMIC:
					if(mode & DYN)
						continue;
					break;
				case SHT_SYMTAB:
				case SHT_DYNSYM:
					if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
						continue;
					break;
				case SHT_REL:
				case SHT_RELA:
					if(mode & REL)
						continue;
					break;
				default:
					break;
			}

			break;
		}

		orcSHT->sh_type = t;
	} else
		orcSHT->sh_type = getElf_Word();

	int r = rand();

	if(r % 3 == 0){
		orcSHT->sh_flags &= ~SHF_ALLOC;
		orcSHT->sh_flags &= ~SHF_EXECINSTR;
	} else if(r % 3 == 1)
		orcSHT->sh_flags = getElf_Word();
	else
		orcSHT->sh_flags = 0x00;

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x,", sh, orcSHT->sh_type);
	fprintf(logfp, " sh_flags = 0x"HEX")", orcSHT->sh_flags);

	return 1;
}

int sht24(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section init = findSectionIndexByName(".init");
	Elf_Section fini = findSectionIndexByName(".fini");

	if(init != sh && fini != sh)
		return 0;

	if(rand() % 2){
		Elf_Word t;

		while((t = rand() % SHT_NUM)){
			switch(t){
				case SHT_PROGBITS:
					continue;
					break;
				case SHT_STRTAB:
					if(mode & STRS)
						continue;
					break;
				case SHT_NOTE:
					if(mode & NOTE)
						continue;
					break;
				case SHT_DYNAMIC:
					if(mode & DYN)
						continue;
					break;
				case SHT_SYMTAB:
				case SHT_DYNSYM:
					if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
						continue;
					break;
				case SHT_REL:
				case SHT_RELA:
					if(mode & REL)
						continue;
					break;
				default:
					break;
			}

			break;
		}

		orcSHT->sh_type = t;
	} else
		orcSHT->sh_type = getElf_Word();

	int r = rand();

	if(r % 3 == 0){
		orcSHT->sh_flags &= ~SHF_ALLOC;
		orcSHT->sh_flags &= ~SHF_EXECINSTR;
	} else if(r % 3 == 1)
		orcSHT->sh_flags = getElf_Word();
	else
		orcSHT->sh_flags = 0x00;

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x,", sh, orcSHT->sh_type);
	fprintf(logfp, " sh_flags = 0x"HEX")", orcSHT->sh_flags);

	return 1;
}

int sht25(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section interp;

	if(!(interp = findSectionIndexByName(".interp")))
		return 0;

	if(interp != sh)
		return 0;

	if(rand() % 2)
		orcSHT->sh_type = SHT_NULL;

	if(rand() % 2)
		orcSHT->sh_flags &= ~SHF_ALLOC;
	else
		orcSHT->sh_flags = 0x00;

	// Using the original sh_offset of the ELF. sh_offset in the ORC might be already fuzzed
	strncpy(orcptr + elfSHT[interp].sh_offset, dirname_orcfname, strlen(dirname_orcfname));
	*(orcptr + elfSHT[interp].sh_offset + strlen(dirname_orcfname)) = '\0';

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x,", sh, orcSHT->sh_type);
	fprintf(logfp, " sh_flags = 0x"HEX",", orcSHT->sh_flags);
	fprintf(logfp, " .interp = %s)", orcptr + elfSHT[interp].sh_offset);

	return 1;
}

int sht26(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section got = findSectionIndexByName(".got");

	if(got != sh)
		return 0;

	orcSHT->sh_flags &= ~SHF_WRITE;

	fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", sh, orcSHT->sh_flags);

	return 1;
}

int sht27(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section plt = findSectionIndexByName(".plt");

	if(plt != sh)
		return 0;

	if(rand() % 4 < 3){ // 75% chance
		orcSHT->sh_flags &= ~SHF_EXECINSTR;

		fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", sh, orcSHT->sh_flags);

		return 1;
	} else { // Binary patch: the second jmp instruction in the PLT
		unsigned int jmp_asm;
		int r = rand();

		// The 1st jmp in PLT is 6 bytes length in x86 and x86_64
		*(orcptr + elfSHT[plt].sh_offset + 6) = 0xff; // jmp opcode
		*(orcptr + elfSHT[plt].sh_offset + 7) = 0x25; // jmp opcode

		if(r % 4 == 0) // jmp to the original entrypoint
			jmp_asm = (unsigned int) elfHDR->e_entry;
		else if(r % 4 == 1){ // jmp to _init (".init".sh_addr)
			Elf_Section init;

			if(!(init = findSectionIndexByName(".init")))
				return 0;

			jmp_asm = (unsigned int) elfSHT[init].sh_addr;
		} else if(r % 4 == 2){ // jmp to _fini (".fini".sh_addr)
			Elf_Section fini;

			if(!(fini = findSectionIndexByName(".fini")))
				return 0;

			jmp_asm = (unsigned int) elfSHT[fini].sh_addr;
		} else { // jmp to a semi-random address
			jmp_asm = (unsigned int) getElf_Addr();
			if(rand() % 2)
				jmp_asm = SWAP32(jmp_asm); // little-endian conversion, just for phun ;D
		}

		memcpy(orcptr + elfSHT[plt].sh_offset + 8, &jmp_asm, sizeof(jmp_asm));

		fprintf(logfp, "(SHT[%d]->(sh_offset + 6) = jmp 0x%x)", sh, jmp_asm);

		return 1;
	}
}

int sht28(void)
{
	if(orcSHT->sh_type != SHT_STRTAB)
		return 0;

	if(sh == elfHDR->e_shstrndx)
		return 0;

	if(rand() % 2){
		if(mode & STRS)
			return 0;

		if(mode & REL) // If REL is fuzzed, the sh_offset of the string tab will be needed
			if(rand() % 3 < 2)
				return 0;

		orcSHT->sh_offset = elfstatinfo.st_size; // Pointing at the end of the file
		orcSHT->sh_size = 0x1337;
	} else {
		if(mode & STRS)
			if(rand() % 2)
				return 0;

		orcSHT->sh_size = 0;
	}

	fprintf(logfp, "(SHT[%d]->sh_offset = 0x"HEX",", sh, orcSHT->sh_offset);
	fprintf(logfp, " sh_size = 0x"HEX")", orcSHT->sh_size);

	return 1;
}

int sht29(void)
{
	if(orcSHT->sh_type != SHT_HASH &&
		orcSHT->sh_type != SHT_GNU_HASH)
		return 0;

	if(rand() % 4 < 3)
		return 0;

	orcSHT->sh_type = getElf_Word();

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x)", sh, orcSHT->sh_type);

	return 1;
}

int sht30(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & SYM)
				if(rand() % 3 < 2)
					return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				if(rand() % 3 < 2)
					return 0;
			break;
		default:
			if(rand() % 4 < 3)
				return 0;
	}

	Elf_Section text = findSectionIndexByName(".text");
	Elf_Section data = findSectionIndexByName(".data");
	Elf_Section got  = findSectionIndexByName(".got");
	Elf_Section bss  = findSectionIndexByName(".bss");
	Elf_Section gotplt  = findSectionIndexByName(".got.plt");

	int r = rand();

	if(r % 5 == 0){
		if(!text)
			return 0;

		orcSHT->sh_name = elfSHT[text].sh_name;
	} else if(r % 5 == 1){
		if(!data)
			return 0;

		orcSHT->sh_name = elfSHT[data].sh_name;
	} else if(r % 5 == 2){
		if(!got)
			return 0;

		orcSHT->sh_name = elfSHT[got].sh_name;
	} else if(r % 5 == 3){
		if(!bss)
			return 0;

		orcSHT->sh_name = elfSHT[bss].sh_name;
	} else {
		if(!gotplt)
			return 0;

		orcSHT->sh_name = elfSHT[gotplt].sh_name;
	}

	fprintf(logfp, "(SHT[%d]->sh_name = 0x%x)", sh, orcSHT->sh_name);

	return 1;
}

int sht31(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
				return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				return 0;
			break;
		default:
			if(rand() % 5 < 4) // 80% chance
				return 0;
	}

	if(rand() % 2)
		orcSHT->sh_type = SHT_LOOS;
	else
		orcSHT->sh_type = SHT_HIOS;

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x)", sh, orcSHT->sh_type);

	return 1;
}

int sht32(void)
{
	orcSHT->sh_flags |= SHF_MASKOS;

	fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", sh, orcSHT->sh_flags);

	return 1;
}

int sht33(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & (SYM | REL)) // In REL, sh_type of the symbol table will be needed
				return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				return 0;
			break;
		default:
			if(rand() % 5 < 4) // 80% chance
				return 0;
	}

	int r = rand();

	if(r % 6 == 0)
		orcSHT->sh_type = SHT_GNU_ATTRIBUTES;
	else if(r % 6 == 1)
		orcSHT->sh_type = SHT_GNU_HASH;
	else if(r % 6 == 2)
		orcSHT->sh_type = SHT_GNU_LIBLIST;
	else if(r % 6 == 3)
		orcSHT->sh_type = SHT_GNU_verdef;
	else if(r % 6 == 4)
		orcSHT->sh_type = SHT_GNU_verneed;
	else
		orcSHT->sh_type = SHT_GNU_versym;

	fprintf(logfp, "(SHT[%d]->sh_type = 0x%x)", sh, orcSHT->sh_type);

	return 1;
}

int sht34(void)
{
	int fuzzed = 0;

	if(orcSHT->sh_flags & SHF_WRITE){
		orcSHT->sh_flags &= ~SHF_ALLOC;
		fuzzed++;
	}

	if(orcSHT->sh_flags & SHF_EXECINSTR){
		orcSHT->sh_flags &= ~SHF_ALLOC;
		fuzzed++;
	}

	if(!fuzzed)
		return 0;

	fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", sh, orcSHT->sh_flags);

	return 1;
}

int sht35(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	if(orcSHT->sh_type != SHT_INIT_ARRAY &&
		orcSHT->sh_type != SHT_FINI_ARRAY)
		return 0;

	if(rand() % 2)
		return 0;

	Elf_Addr addr;
	int r = rand();

	if(r % 4 == 0) // jmp to the original entrypoint
		addr = elfHDR->e_entry;
	else if(r % 4 == 1){ // jmp to _init (".init".sh_addr)
		Elf_Section init;

		if(!(init = findSectionIndexByName(".init")))
			return 0;

		addr = elfSHT[init].sh_addr;
	} else if(r % 4 == 2){ // jmp to _fini (".fini".sh_addr)
		Elf_Section fini;

		if(!(fini = findSectionIndexByName(".fini")))
			return 0;

		addr = elfSHT[fini].sh_addr;
	} else
		addr = getElf_Addr();

	memcpy(orcptr + elfSHT[sh].sh_offset, &addr, sizeof(addr));

	fprintf(logfp, "(SHT[%d]->(sh_offset + 0) = 0x"HEX")", sh, addr);

	return 1;
}

int sht36(void)
{
	// Metadata dependencies
	switch(orcSHT->sh_type){
		case SHT_STRTAB:
			if(mode & STRS)
				if(rand() % 2) // 50% chance
					return 0;
			break;
		case SHT_NOTE:
			if(mode & NOTE)
				if(rand() % 2)
					return 0;
			break;
		case SHT_DYNAMIC:
			if(mode & DYN)
				if(rand() % 4 < 3)
					return 0;
			break;
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			if(mode & SYM)
				if(rand() % 4 < 3)
					return 0;
			break;
		case SHT_RELA:
		case SHT_REL:
			if(mode & REL)
				if(rand() % 4 < 3)
					return 0;
			break;
		default:
			if(rand() % 3 < 2)
				return 0;
	}

	orcSHT->sh_size++;
	orcSHT->sh_entsize--;

	fprintf(logfp, "(SHT[%d]->sh_size = 0x"HEX",", sh, orcSHT->sh_size);
	fprintf(logfp, " sh_entsize = 0x"HEX")", orcSHT->sh_entsize);

	return 1;
}

int sht37(void)
{
	if(sh == 0) // Avoid the first entry of the SHT
		return 0;

	Elf_Section tbss  = findSectionIndexByName(".tbss");
	Elf_Section tdata = findSectionIndexByName(".tdata");

	if(!tbss && !tdata)
		return 0;

	if(tbss != sh && tdata != sh)
		return 0;

	int fuzzed = 0;

	if(tbss){
		orcOrigSHT[tbss].sh_flags &= ~SHF_TLS;
		fuzzed++;
	}

	if(tdata){
		orcOrigSHT[tdata].sh_flags &= ~SHF_TLS;
		fuzzed++;
	}

	if(!fuzzed)
		return 0;

	if(tbss && tdata){
		fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX",", tdata, orcOrigSHT[tdata].sh_flags);
		fprintf(logfp, " SHT[%d]->sh_flags = 0x"HEX")", tbss, orcOrigSHT[tbss].sh_flags);
	} else if(tbss)
		fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", tbss, orcOrigSHT[tbss].sh_flags);
	else
		fprintf(logfp, "(SHT[%d]->sh_flags = 0x"HEX")", tdata, orcOrigSHT[tdata].sh_flags);

	return 1;
}


// Will trust only in the original (unmodified) ELF data.
// Previous rules might already fuzzed sh_name and could SIGSEGV here is orc sh_name is used
Elf_Section findSectionIndexByName(char *name)
{
	int k;
	Elf_Shdr *tmpSHT = elfSHT;

	for(k = 0; k < elfHDR->e_shnum; k++, tmpSHT++)
		if(strcmp(elfptr + elfshstrtab_offset + tmpSHT->sh_name, name) == 0)
			return k;

	return SHT_NULL; // Zero
}

void fuzzName()
{
	if(rand() % 3 == 0){
		if(rand() % 2)
			orcSHT->sh_name = getElf_Word();
		else
			orcSHT->sh_name = getElf_Half();
	} else {
		if(rand() % 3 == 0)
			orcSHT->sh_name = 0x00;
		else
			orcSHT->sh_name = (rand() % 0xff);
	}
}

void fuzzSize()
{
	if((rand() % 4) < 3){ // 75% chance
		if(rand() % 2)
#if defined(__i386__)
			orcSHT->sh_size = getElf_Word();
#elif defined(__x86_64__)
			orcSHT->sh_size = getElf_Xword();
#endif
		else
			orcSHT->sh_size = getElf_Half();
	} else
		orcSHT->sh_size = 0x00;
}

void fuzzEntSize()
{
	if((rand() % 4) < 3){ // 75% chance
		if(rand() % 2)
#if defined(__i386__)
			orcSHT->sh_entsize = getElf_Word();
#elif defined(__x86_64__)
			orcSHT->sh_entsize = getElf_Xword();
		else
			orcSHT->sh_entsize = getElf_Half();
#endif
	} else
		orcSHT->sh_entsize = 0x00;
}

void fuzzFlags()
{
	int r = rand();

	if(r % 3 == 0){
		r = rand();

		// Set SHF_x
		if(r % 5 == 0)
			orcSHT->sh_flags  = (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_TLS | SHF_MASKPROC);
		else if(r % 5 == 1)
			orcSHT->sh_flags |= SHF_WRITE;
		else if(r % 5 == 2)
			orcSHT->sh_flags |= SHF_ALLOC;
		else if(r % 5 == 3)
			orcSHT->sh_flags |= SHF_TLS;
		else
			orcSHT->sh_flags |= SHF_EXECINSTR;
	} else if(r % 3 == 1){
		r = rand();

		// Unset SHF_x
		if(r % 5 == 0)
			orcSHT->sh_flags  = 0x00;
		else if(r % 5 == 1)
			orcSHT->sh_flags &= ~SHF_WRITE;
		else if(r % 5 == 2)
			orcSHT->sh_flags &= ~SHF_ALLOC;
		else if(r % 5 == 3)
			orcSHT->sh_flags &= ~SHF_TLS;
		else
			orcSHT->sh_flags &= ~SHF_EXECINSTR;
	} else {
#if defined(__i386__)
		orcSHT->sh_flags = getElf_Word();
#elif defined(__x86_64__)
		orcSHT->sh_flags = getElf_Xword();
#endif
	}
}

void fuzzAddrAlign()
{
	if(rand() % 2){ // 50% chance
#if defined(__i386__)
		while((orcSHT->sh_addralign = getElf_Word()))
#elif defined(__x86_64__)
		while((orcSHT->sh_addralign = getElf_Xword()))
#endif
			// Bitwise: x & (x - 1) != 0 if x is NOT a power of 2
			if((orcSHT->sh_addralign & (orcSHT->sh_addralign - 1)) != 0)
				break;
	} else {
		if(rand() % 2) // 25%
			orcSHT->sh_addralign = PAGESIZE - 1;
		else // 25%
			orcSHT->sh_addralign = PAGESIZE + 1;
	}
}

void initialize_sht_funcs(void)
{
	sht[1]  = &sht1;
	sht[2]  = &sht2;
	sht[3]  = &sht3;
	sht[4]  = &sht4;
	sht[5]  = &sht5;
	sht[6]  = &sht6;
	sht[7]  = &sht7;
	sht[8]  = &sht8;
	sht[9]  = &sht9;
	sht[10] = &sht10;
	sht[11] = &sht11;
	sht[12] = &sht12;
	sht[13] = &sht13;
	sht[14] = &sht14;
	sht[15] = &sht15;
	sht[16] = &sht16;
	sht[17] = &sht17;
	sht[18] = &sht18;
	sht[19] = &sht19;
	sht[20] = &sht20;
	sht[21] = &sht21;
	sht[22] = &sht22;
	sht[23] = &sht23;
	sht[24] = &sht24;
	sht[25] = &sht25;
	sht[26] = &sht26;
	sht[27] = &sht27;
	sht[28] = &sht28;
	sht[29] = &sht29;
	sht[30] = &sht30;
	sht[31] = &sht31;
	sht[32] = &sht32;
	sht[33] = &sht33;
	sht[34] = &sht34;
	sht[35] = &sht35;
	sht[36] = &sht36;
	sht[37] = &sht37;
}
