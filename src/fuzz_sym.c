/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define N_RULES_SYM 15 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr sym[N_RULES_SYM + 1];

void initialize_sym_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int mode; // Metadata to fuzz (parameters given in argv[])
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern unsigned int secnum;
extern unsigned int entry;
extern Elf_Ehdr *orcHDR;
extern Elf_Sym *orcSYM;

void fuzz_sym()
{
	int rule;

	for(rule = 1; rule <= N_RULES_SYM; rule++)
		if((rand() % like_a) < like_b)
			if(sym[rule]()){
				printf(". ");
				debug("SHT[%d] SYM[%d] rule [%.2d] executed\n", secnum, entry, rule);
				fprintf(logfp, " | SHT[%d] SYM[%d] rule [%.2d] executed\n", secnum, entry, rule);
			}
}

int sym1(void)
{
	if(entry != STN_UNDEF)
		return 0;

	if(rand() % 2)
		return 0;

#if defined(__i386__)
	orcSYM->st_size = getElf_Word();
#elif defined(__x86_64__)
	if(rand() % 3 < 2)
		orcSYM->st_size = getElf_Xword();
	else
		orcSYM->st_size = getElf_Word();
#endif

	orcSYM->st_value = getElf_Addr();
	orcSYM->st_info  = rand() & 0xff;
	orcSYM->st_other = rand() & 0xff;

	if(rand() % 4 == 0)
		orcSYM->st_shndx = getElf_Section();
	else
		orcSYM->st_shndx = rand() % orcHDR->e_shnum;

	if(rand() % 4 == 0)
		orcSYM->st_name = getElf_Word();
	else
		orcSYM->st_name = rand() & 0xff;

	fprintf(logfp, "(SYM[%d]->st_value = 0x"HEX",", entry, orcSYM->st_value);
	fprintf(logfp, " st_size = 0x"HEX",", orcSYM->st_size);
	fprintf(logfp, " st_info = 0x%x,", orcSYM->st_info);
	fprintf(logfp, " st_other = 0x%x,", orcSYM->st_other);
	fprintf(logfp, " st_shndx = 0x%x,", orcSYM->st_shndx);
	fprintf(logfp, " st_name = 0x%x)", orcSYM->st_name);

	return 1;
}

int sym2(void)
{
	if(rand() % 5 < 4) // 80% chance to return. The symbol name is important.
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	if(rand() % 4 == 0)
		orcSYM->st_name = getElf_Word();
	else
		orcSYM->st_name = rand() & 0xff;

	fprintf(logfp, "(SYM[%d]->st_name = 0x%x)", entry, orcSYM->st_name);

	return 1;
}

int sym3(void)
{
	if(rand() % 5 < 4) // 80% chance to return. st_value is fuzzed in other rules as well.
		return 0;

	if(rand() % 4 < 3)
		orcSYM->st_value = getElf_Addr();
	else
		orcSYM->st_value = getElf_Word();
	
	fprintf(logfp, "(SYM[%d]->st_value = 0x"HEX")", entry, orcSYM->st_value);

	return 1;
}

int sym4(void)
{
#if defined(__i386__)
	orcSYM->st_size = getElf_Word();
#elif defined(__x86_64__)
	if(rand() % 3 < 2)
		orcSYM->st_size = getElf_Xword();
	else
		orcSYM->st_size = getElf_Word();
#endif

	fprintf(logfp, "(SYM[%d]->st_size = 0x"HEX")", entry, orcSYM->st_size);

	return 1;
}

int sym5(void)
{
	if(rand() % 2)
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	if(rand() % 2)
		orcSYM->st_shndx = rand() % orcHDR->e_shnum;
	else {
		if(rand() % 2)
			orcSYM->st_shndx = getElf_Section();
		else
			orcSYM->st_shndx = SHN_UNDEF;
	}

	fprintf(logfp, "(SYM[%d]->st_shndx = 0x%x)", entry, orcSYM->st_shndx);

	return 1;
}

int sym6(void)
{
	if(ELF_ST_TYPE(orcSYM->st_info) != STT_SECTION)
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	unsigned char st_info;

	do
		st_info = ELF_ST_INFO(rand() & 0x0f, STT_SECTION);
	while(ELF_ST_BIND(st_info) == STB_LOCAL);

	orcSYM->st_info = st_info;

	fprintf(logfp, "(SYM[%d]->st_info = 0x%.2x)", entry, orcSYM->st_info);

	return 1;
}

int sym7(void)
{
	if(ELF_ST_TYPE(orcSYM->st_info) != STT_FILE)
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	unsigned char st_info = orcSYM->st_info;
	Elf_Section st_shndx;

	if(rand() % 2)
		do
			st_info = ELF_ST_INFO(rand() & 0x0f, STT_FILE);
		while(ELF_ST_BIND(st_info) == STB_LOCAL);

	if(rand() % 4 < 3){
		while((st_shndx = rand() % orcHDR->e_shnum))
			if(st_shndx != SHN_ABS)
				break;
	} else
		while((st_shndx = getElf_Section()))
			if(st_shndx != SHN_ABS)
				break;

	orcSYM->st_info  = st_info;
	orcSYM->st_shndx = st_shndx;

	fprintf(logfp, "(SYM[%d]->st_info = 0x%.2x,", entry, orcSYM->st_info);
	fprintf(logfp, " st_shndx = 0x%x)", orcSYM->st_shndx);

	return 1;
}

int sym8(void)
{
	if(orcHDR->e_type != ET_REL ||
		orcSYM->st_shndx != SHN_COMMON)
		return 0;

	Elf_Addr st_value;

	while((st_value = getElf_Addr()))
		if(st_value % 4 != 0)
			break;

	orcSYM->st_value = st_value;

	fprintf(logfp, "(SYM[%d]->st_value = 0x"HEX")", entry, orcSYM->st_value);

	return 1;
}

int sym9(void)
{
	if(orcHDR->e_type != ET_REL ||
		orcSYM->st_shndx == SHN_COMMON)
		return 0;

	if(rand() % 2)
		orcSYM->st_value = getElf_Off();
	else
		orcSYM->st_value = getElf_Word();

	fprintf(logfp, "(SYM[%d]->st_value = 0x"HEX")", entry, orcSYM->st_value);

	return 1;
}

int sym10(void)
{
	if(orcHDR->e_type != ET_EXEC &&
		orcHDR->e_type != ET_DYN)
		return 0;

	if(rand() % 5 < 4)
		return 0;

	orcSYM->st_value = getElf_Addr();

	fprintf(logfp, "(SYM[%d]->st_value = 0x"HEX")", entry, orcSYM->st_value);

	return 1;
}

int sym11(void)
{
	if(orcHDR->e_type != ET_EXEC &&
		orcHDR->e_type != ET_DYN)
		return 0;

	if(rand() % 5 < 4)
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	if(rand() % 2)
		orcSYM->st_shndx = 1 + rand() % orcHDR->e_shnum;
	else
		orcSYM->st_shndx = (rand() % 10) + getElf_Section();

	fprintf(logfp, "(SYM[%d]->st_shndx = 0x%x)", entry, orcSYM->st_shndx);

	return 1;
}

int sym12(void)
{
	if(orcSYM->st_shndx != SHN_UNDEF)
		return 0;

	if(!orcSYM->st_value)
		return 0;

	orcSYM->st_value = getElf_Addr();

	fprintf(logfp, "(SYM[%d]->st_value = 0x"HEX")", entry, orcSYM->st_value);

	return 1;
}

int sym13(void)
{
	if(rand() % 4 < 3)
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	orcSYM->st_info = rand() & 0xff;

	fprintf(logfp, "(SYM[%d]->st_info = 0x%.2x)", entry, orcSYM->st_info);

	return 1;
}

int sym14(void)
{
	if(rand() % 4 < 3)
		return 0;

	if(mode & REL)
		if(rand() % 2)
			return 0;

	orcSYM->st_info = ELF_ST_INFO(rand() % 2 ? STB_LOOS : STB_HIOS, rand() % 2 ? STT_LOOS : STT_HIOS);

	fprintf(logfp, "(SYM[%d]->st_info = 0x%.2x)", entry, orcSYM->st_info);

	return 1;
}

int sym15(void)
{
	orcSYM->st_other = rand() & 0xff;

	fprintf(logfp, "(SYM[%d]->st_other = 0x%.2x)", entry, orcSYM->st_other);

	return 1;
}

void initialize_sym_funcs(void)
{
	sym[1]  = &sym1;
	sym[2]  = &sym2;
	sym[3]  = &sym3;
	sym[4]  = &sym4;
	sym[5]  = &sym5;
	sym[6]  = &sym6;
	sym[7]  = &sym7;
	sym[8]  = &sym8;
	sym[9]  = &sym9;
	sym[10] = &sym10;
	sym[11] = &sym11;
	sym[12] = &sym12;
	sym[13] = &sym13;
	sym[14] = &sym14;
	sym[15] = &sym15;
}
