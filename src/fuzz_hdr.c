/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define N_RULES_HDR 19 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr hdr[N_RULES_HDR + 1];

void initialize_hdr_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int mode; // Metadata to fuzz (parameters given in argv[])
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern Elf_Ehdr *elfHDR, *orcHDR;

void fuzz_hdr()
{
	int rule;

	for(rule = 1; rule <= N_RULES_HDR; rule++)
		if((rand() % like_a) < like_b)
			if(hdr[rule]()){
				printf(". ");
				debug("HDR rule [%.2d] executed\n", rule);
				fprintf(logfp, " | HDR rule [%.2d] executed\n", rule);
			}
}

int hdr1(void)
{
	if(mode & PHT)
		return 0;

	if(rand() % 2){ // 50% chance
		orcHDR->e_phoff = 0;
		orcHDR->e_phentsize = 0;
		fprintf(logfp, "(HDR->e_phoff = 0x00, e_phentsize = 0x00)");
	} else {
		orcHDR->e_phnum = 0;
		fprintf(logfp, "(HDR->e_phnum = 0x00)");
	}

	return 1;
}

int hdr2(void)
{
	if(mode & SHT)
		return 0;

	if(rand() % 2){ // 50% chance
		orcHDR->e_shoff = 0;
		orcHDR->e_shentsize = 0;
		fprintf(logfp, "(HDR->e_shoff = 0x00, e_shentsize = 0x00)");
	} else {
		orcHDR->e_shnum = 0;
		fprintf(logfp, "(HDR->e_shnum = 0x00)");
	}

	return 1;
}

int hdr3(void)
{
	Elf_Half e_type;

	if(rand() % 2) // 50% chance
		e_type = getElf_Half() % ET_NUM;
	else {
		if((rand() % 4) < 3){ // .5 * .75 = 37.5% chance
			while((e_type = (getElf_Half() % ET_HIPROC)))
				if(e_type >= 5 && e_type <= ET_HIPROC)
					break;
		} else // .5 * .25 = 12.5% chance
			e_type = 0;
	}

	orcHDR->e_type = e_type;

	fprintf(logfp, "(HDR->e_type = 0x%x)", orcHDR->e_type);

	return 1;
}

int hdr4(void)
{
	if((rand() % 4) < 3){ // 75% chance
		while((orcHDR->e_machine = getElf_Half()))
			if(orcHDR->e_machine > 16)
				break;
	} else
		orcHDR->e_machine = 0;

	fprintf(logfp, "(HDR->e_machine = 0x%x)", orcHDR->e_machine);

	return 1;
}

int hdr5(void)
{
	if((rand() % 4) < 3) // 75% chance
		orcHDR->e_entry = getElf_Addr();
	else
		orcHDR->e_entry = 0;

	fprintf(logfp, "(HDR->e_entry = 0x"HEX")", orcHDR->e_entry);

	return 1;
}

int hdr6(void)
{
	if(mode & PHT)
		return 0;

	orcHDR->e_phoff = getElf_Off();
	fprintf(logfp, "(HDR->e_phoff = 0x"HEX")", orcHDR->e_phoff);

	return 1;
}

int hdr7(void)
{
	orcHDR->e_ehsize = getElf_Half();
	fprintf(logfp, "(HDR->e_ehsize = 0x%x)", orcHDR->e_ehsize);

	return 1;
}

int hdr8(void)
{
	if(mode & PHT)
		return 0;

	if((rand() % 4) < 3){ // 75% chance
		orcHDR->e_phentsize = getElf_Half();
		orcHDR->e_phnum = getElf_Half();
		fprintf(logfp, "(HDR->e_phentsize = 0x%x,", orcHDR->e_phentsize);
		fprintf(logfp, " e_phnum = 0x%x)", orcHDR->e_phnum);
	} else {
		orcHDR->e_phentsize = 0;
		fprintf(logfp, "(HDR->e_phentsize = 0x00)");
	}

	return 1;
}

int hdr9(void)
{
	if((rand() % 4) < 3){ // 75% chance
		if(mode & SHT)
			return 0;

		orcHDR->e_shentsize = getElf_Half();
		orcHDR->e_shnum = getElf_Half();
		fprintf(logfp, "(HDR->e_shentsize = 0x%x,", orcHDR->e_shentsize);
		fprintf(logfp, " e_shnum = 0x%x)", orcHDR->e_shnum);
	} else {
		orcHDR->e_shentsize = 0;
		fprintf(logfp, "(HDR->e_shentsize = 0x00)");
	}

	return 1;
}

int hdr10(void)
{
	if(mode & (STRS | NOTE | DYN | SYM | REL))
		return 0;

	if(mode & SHT)
		if(rand() % 3 < 2)
			return 0;

	if((rand() % 4) < 3) // 75% chance
		orcHDR->e_shstrndx = rand() % elfHDR->e_shnum;
	else {
		if(rand() % 2)
			orcHDR->e_shstrndx = getElf_Half();
		else
			orcHDR->e_shstrndx = 0;
	}

	fprintf(logfp, "(HDR->e_shstrndx = 0x%x)", orcHDR->e_shstrndx);

	return 1;
}

int hdr11(void)
{
	if((rand() % 4) < 3) // 75% chance
		orcHDR->e_ident[EI_CLASS] = (rand() & 0xff) + ELFCLASS64 + 1;
	else
		orcHDR->e_ident[EI_CLASS] = 0;

	fprintf(logfp, "(HDR->e_ident[EI_CLASS] = 0x%.2x)", orcHDR->e_ident[EI_CLASS]);

	return 1;
}

int hdr12(void)
{
	if((rand() % 4) < 3) // 75% chance
		orcHDR->e_ident[EI_DATA] = (rand() & 0xff) + ELFDATA2MSB + 1;
	else
		orcHDR->e_ident[EI_DATA] = 0;

	fprintf(logfp, "(HDR->e_ident[EI_DATA] = 0x%.2x)", orcHDR->e_ident[EI_DATA]);

	return 1;
}

int hdr13(void)
{
	if(rand() % 2){
		orcHDR->e_version = getElf_Word() + EV_CURRENT + 1;
		orcHDR->e_ident[EI_VERSION] = (rand() & 0xff) + EV_CURRENT + 1;
	} else {
		orcHDR->e_version = 0;
		orcHDR->e_ident[EI_VERSION] = 0;
	}

	fprintf(logfp, "(HDR->e_version = 0x%x, e_ident[EI_VERSION] = 0x%.2x)", orcHDR->e_version, orcHDR->e_ident[EI_VERSION]);

	return 1;
}

int hdr14(void)
{
	if(mode & SHT)
		return 0;

	orcHDR->e_shoff     = getElf_Off();
	orcHDR->e_shnum     = getElf_Half();
	orcHDR->e_shentsize = getElf_Half();

	fprintf(logfp, "(HDR->e_shoff = 0x"HEX",", orcHDR->e_shoff);
	fprintf(logfp, " e_shnum = 0x%x,", orcHDR->e_shnum);
	fprintf(logfp, " e_shentsize = 0x%x)", orcHDR->e_shentsize);

	return 1;
}

int hdr15(void)
{
	if(mode & SHT)
		return 0;

	orcHDR->e_shnum = SHN_LORESERVE;
	fprintf(logfp, "(HDR->e_shnum = 0x%x)", orcHDR->e_shnum);

	return 1;
}

int hdr16(void)
{
	orcHDR->e_ident[EI_ABIVERSION] = rand() & 0xff;

	fprintf(logfp, "(HDR->e_ident[EI_ABIVERSION] = 0x%.2x)", orcHDR->e_ident[EI_ABIVERSION]);

	return 1;
}

int hdr17(void)
{
	orcHDR->e_ident[EI_OSABI] = rand() & 0xff;

	fprintf(logfp, "(HDR->e_ident[EI_OSABI] = 0x%.2x)", orcHDR->e_ident[EI_OSABI]);

	return 1;
}

int hdr18(void)
{
	if(rand() % 2)
		orcHDR->e_type = ET_LOOS + 1;
	else
		orcHDR->e_type = ET_HIOS;

	fprintf(logfp, "(HDR->e_type = 0x%x)", orcHDR->e_type);

	return 1;
}

int hdr19(void)
{
	if(mode & PHT)
		return 0;

	orcHDR->e_phnum = 32;

	fprintf(logfp, "(HDR->e_phnum = 0x00)");

	return 1;
}

void initialize_hdr_funcs(void)
{
	hdr[1]  = &hdr1;
	hdr[2]  = &hdr2;
	hdr[3]  = &hdr3;
	hdr[4]  = &hdr4;
	hdr[5]  = &hdr5;
	hdr[6]  = &hdr6;
	hdr[7]  = &hdr7;
	hdr[8]  = &hdr8;
	hdr[9]  = &hdr9;
	hdr[10] = &hdr10;
	hdr[11] = &hdr11;
	hdr[12] = &hdr12;
	hdr[13] = &hdr13;
	hdr[14] = &hdr14;
	hdr[15] = &hdr15;
	hdr[16] = &hdr16;
	hdr[17] = &hdr17;
	hdr[18] = &hdr18;
	hdr[19] = &hdr19;
}
