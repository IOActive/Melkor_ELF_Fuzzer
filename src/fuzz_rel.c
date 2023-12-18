/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define N_RULES_REL 3 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr rel[N_RULES_REL + 1];

void initialize_rel_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern unsigned int secnum;
extern unsigned int entry;
extern Elf_Ehdr *orcHDR;
extern Elf_Shdr *orcSHT;
extern Elf_Rel *orcREL;
extern Elf_Rela *orcRELA;

void fuzz_rel()
{
	int rule;

	for(rule = 1; rule <= N_RULES_REL; rule++)
		if((rand() % like_a) < like_b)
			if(rel[rule]()){
				printf(". ");
				debug("SHT[%d] REL[%d] rule [%.2d] executed\n", secnum, entry, rule);
				fprintf(logfp, " | SHT[%d] REL[%d] rule [%.2d] executed\n", secnum, entry, rule);
			}
}

int rel1(void)
{
	if(rand() % 3 < 2)
		return 0;

	if(orcHDR->e_type == ET_REL){
		if(orcSHT->sh_type == SHT_REL)
			orcREL->r_offset  = getElf_Half();
		else
			orcRELA->r_offset = getElf_Half();
	} else if(orcHDR->e_type == ET_EXEC || orcHDR->e_type == ET_DYN){
		if(orcSHT->sh_type == SHT_REL)
			orcREL->r_offset  = getElf_Addr();
		else
			orcRELA->r_offset = getElf_Addr();
	} else
		return 0;

	fprintf(logfp, "(REL[%d]->r_offset = 0x"HEX")", entry, orcSHT->sh_type == SHT_REL ? orcREL->r_offset : orcRELA->r_offset);

	return 1;
}

int rel2(void)
{
	if(rand() % 3 < 2)
		return 0;

	if(rand() % 4 < 3){ // 75% chance to only change its related Symbol Table index
		Elf_Section sym_ndx;

		if(rand() % 2)
			sym_ndx = rand() % orcHDR->e_shnum; // A random but valid Symbol Table index within the SHT
		else
			sym_ndx = getElf_Section();

		if(orcSHT->sh_type == SHT_REL)
			orcREL->r_info  = ELF_R_INFO(sym_ndx, ELF_R_TYPE(orcREL->r_info));
		else
			orcRELA->r_info = ELF_R_INFO(sym_ndx, ELF_R_TYPE(orcRELA->r_info));
	} else {
		if(orcSHT->sh_type == SHT_REL)
#if defined(__i386__)
			orcREL->r_info = getElf_Word();
#elif defined(__x86_64__) || defined(__aarch64__)
			orcREL->r_info = getElf_Xword();
#endif
		else
#if defined(__i386__)
			orcRELA->r_info = getElf_Word();
#elif defined(__x86_64__) || defined(__aarch64__)
			orcRELA->r_info = getElf_Xword();
#endif
	}

	fprintf(logfp, "(REL[%d]->r_info = 0x"HEX")", entry, orcSHT->sh_type == SHT_REL ? orcREL->r_info : orcRELA->r_info);

	return 1;
}

int rel3(void)
{
	if(orcSHT->sh_type == SHT_REL)
		return 0;

	if(rand() % 3 < 2)
		return 0;

	// r_addend is a Sword (Signed Word)
	if(rand() % 2){ // 75% chance to set r_addend to a negative number > 0x7fffffff
#if defined(__x86_64__) || defined(__aarch64__)
		if(rand() % 2)
			orcRELA->r_addend = 0x8000000000000000 + (rand() % 0x7fffffff);
		else
#endif
			orcRELA->r_addend = 0x80000000 + (rand() % 0x7fffffff);
	} else {
		if(rand() % 2)
			orcRELA->r_addend = getElf_Word();
		else
			orcRELA->r_addend = getElf_Xword();
	}

	fprintf(logfp, "(REL[%d]->r_addend = 0x"HEX")", entry, orcRELA->r_addend);

	return 1;
}

void initialize_rel_funcs(void)
{
	rel[1] = &rel1;
	rel[2] = &rel2;
	rel[3] = &rel3;
}
