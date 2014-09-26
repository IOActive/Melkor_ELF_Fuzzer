/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define N_RULES_PHT 22 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr pht[N_RULES_PHT + 1];
int ph = 0; // Program Header. Used inside the for() loop in fuzz_pht() and will be used in the rules

void initialize_pht_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int mode; // Metadata to fuzz (parameters given in argv[])
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern char *dirname_orcfname;	
extern char *orcptr;
extern Elf_Ehdr *elfHDR;
extern Elf_Ehdr	*orcHDR;
extern Elf_Phdr *elfPHT;
extern Elf_Phdr	*orcPHT;
extern Elf_Phdr *orcOrigPHT;

void fuzz_pht()
{
	int rule;

	for(ph = 0; ph < orcHDR->e_phnum; ph++, orcPHT++)
		for(rule = 1; rule <= 18; rule++) // Rules from 19 will be executed outside the for() loop
			if((rand() % like_a) < like_b)
				if(pht[rule]()){
					printf(". ");
					debug("PHT[%d] rule [%.2d] executed\n", ph, rule);
					fprintf(logfp, " | PHT[%d] rule [%.2d] executed\n", ph, rule);
				}

	for( ; rule <= N_RULES_PHT; rule++)
		if((rand() % like_a) < like_b)
			if(pht[rule]()){
				printf(". ");
				debug("PHT rule [%.2d] executed\n", rule);
				fprintf(logfp, " | PHT rule [%.2d] executed\n", rule);
			}
}

int pht1(void)
{
	if(orcPHT->p_type == PT_INTERP)
		return 0;

	if(orcPHT->p_type == PT_DYNAMIC)
		if(mode & DYN)
			return 0;

	if(orcPHT->p_type == PT_NOTE)
		if(mode & NOTE)
			return 0;

	if(rand() % 2) // p_type is a critical field
		return 0;

	Elf_Word p_type;

	if(rand() % 2){ // 50% chance
		while((p_type = rand() % PT_NUM)){
			switch(p_type){
				case PT_INTERP:
					continue;
					break;
				case PT_DYNAMIC:
					if(mode & DYN)
						continue;
					break;
				case PT_NOTE:
					if(mode & NOTE)
						continue;
					break;
			}

			break;
		}
	} else {
		if(rand() % 2)
			p_type = getElf_Word() + PT_NUM;
		else
			p_type = 0;
	}

	orcPHT->p_type = p_type;

	fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", ph, orcPHT->p_type);

	return 1;
}

int pht2(void)
{
	if(orcPHT->p_type == PT_INTERP)
		if(rand() % 5 < 4) // 80% chance
			return 0;

	if(orcPHT->p_type == PT_DYNAMIC)
		if(mode & DYN)
			return 0;

	if(orcPHT->p_type == PT_NOTE)
		if(mode & NOTE)
			return 0;

	Elf_Off p_offset;

	if(rand() % 3 < 2){ // 66.66% chance
		while((p_offset = getElf_Off()))
			if(p_offset % PAGESIZE == 0)
				break;
	} else {
		while((p_offset = getElf_Off()))
			if(p_offset % PAGESIZE != 0)
				break;
	}

	orcPHT->p_offset = p_offset;

	fprintf(logfp, "(PHT[%d]->p_offset = 0x"HEX")", ph, orcPHT->p_offset);

	return 1;
}

int pht3(void)
{
	if(orcPHT->p_type == PT_INTERP)
		if(rand() % 5 < 4) // 80% chance
			return 0;

	if(orcPHT->p_type == PT_DYNAMIC)
		if(mode & DYN)
			return 0;

	if(orcPHT->p_type == PT_NOTE)
		if(mode & NOTE)
			return 0;

	Elf_Addr v, p;

	if(rand() % 2){
		if(rand() % 3 < 2){ // .5 * .6666 = 33.33% chance
			v = orcPHT->p_vaddr;
			p = getElf_Addr();
		} else { // 16.66% chance
			v = getElf_Addr();
			p = orcPHT->p_paddr;
		}
	} else {
		if(rand() % 2){ // .5 * .5 = 25% chance
			while((v = getElf_Addr()))
				if(v % PAGESIZE == 0){
					if(rand() % 2)
						p = v;
					else
						p = getElf_Addr();
					break;
				}
		} else { // 25% chance
			while((v = getElf_Addr()))
				if(v % PAGESIZE != 0){
					if(rand() % 2)
						p = v;
					else
						p = getElf_Addr();
					break;
				}
		}
	}

	orcPHT->p_vaddr = v;
	orcPHT->p_paddr = p;

	fprintf(logfp, "(PHT[%d]->p_vaddr = 0x"HEX",", ph, orcPHT->p_vaddr);
	fprintf(logfp, " p_paddr = 0x"HEX")", orcPHT->p_paddr);

	return 1;
}

int pht4(void)
{
	if(orcPHT->p_type == PT_INTERP)
		if(rand() % 5 < 4) // 80% chance
			return 0;

	if(orcPHT->p_type == PT_DYNAMIC)
		if(mode & DYN)
			return 0;

	if(orcPHT->p_type == PT_NOTE)
		if(mode & NOTE)
			return 0;

#if defined(__i386__)
	Elf_Word  p_memsz;
#elif defined(__x86_64__)
	Elf_Xword p_memsz;
#endif
	int r = rand();

	if(r % 3 == 0){
		orcPHT->p_filesz = 0;
#if defined(__i386__)
		while((p_memsz = getElf_Word()))
#elif defined(__x86_64__)
		while((p_memsz = getElf_Xword()))
#endif
			if(p_memsz % PAGESIZE == 0){
				orcPHT->p_memsz = p_memsz;
				break;
			}
	} else if(r % 3 == 1){
#if defined(__i386__)
		orcPHT->p_filesz = getElf_Word();
#elif defined(__x86_64__)
		orcPHT->p_filesz = getElf_Xword();
#endif
		orcPHT->p_memsz = 0;
	} else {
		if(rand() % 2){
			orcPHT->p_filesz = 0;
			orcPHT->p_memsz  = 0;
		} else
			orcPHT->p_memsz  = getElf_Word();
	}

	fprintf(logfp, "(PHT[%d]->p_filesz = 0x"HEX",", ph, orcPHT->p_filesz);
	fprintf(logfp, " p_memsz = 0x"HEX")", orcPHT->p_memsz);

	return 1;
}

int pht5(void)
{
	if(rand() % 2){
		if(rand() % 2)
			orcPHT->p_align = PAGESIZE - 1;
		else
			orcPHT->p_align = PAGESIZE + 1;
	} else
#if defined(__i386__)
		orcPHT->p_align = getElf_Word();
#elif defined(__x86_64__)
		orcPHT->p_align = getElf_Xword();
#endif

	fprintf(logfp, "(PHT[%d]->p_align = 0x"HEX")", ph, orcPHT->p_align);

	return 1;
}

int pht6(void)
{
	if(orcPHT->p_type == PT_INTERP)
		return 0;

	if(orcPHT->p_type == PT_DYNAMIC)
		if(mode & DYN)
			return 0;

	if(orcPHT->p_type == PT_NOTE)
		if(mode & NOTE)
			return 0;

	if(rand() % 2) // p_type is a critical field
		return 0;

	Elf_Word p_type;

	while((p_type = (getElf_Word() + PT_LOPROC)))
		if(p_type >= PT_LOPROC && p_type < PT_HIPROC)
			break;

	orcPHT->p_type = p_type;

	fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", ph, orcPHT->p_type);

	return 1;
}

int pht7(void)
{
	if(orcPHT->p_type == PT_INTERP)
		if(rand() % 5 < 4) // 80% chance
			return 0;

	if(orcPHT->p_type == PT_DYNAMIC)
		if(mode & DYN)
			return 0;

	if(orcPHT->p_type == PT_NOTE)
		if(mode & NOTE)
			return 0;

#if defined(__i386__)
	Elf_Word p_filesz;
#elif defined(__x86_64__)
	Elf_Xword p_filesz;
#endif

	if(rand() % 3 < 2){
#if defined(__i386__)
		while((p_filesz = getElf_Word()))
#elif defined(__x86_64__)
		while((p_filesz = getElf_Xword()))
#endif
			if(p_filesz >= orcPHT->p_memsz){
				orcPHT->p_filesz = p_filesz;
				break;
			}
	} else
#if defined(__i386__)
		orcPHT->p_filesz = getElf_Word();
#elif defined(__x86_64__)
		orcPHT->p_filesz = getElf_Xword();
#endif

	fprintf(logfp, "(PHT[%d]->p_filesz = 0x"HEX")", ph, orcPHT->p_filesz);

	return 1;
}

int pht8(void)
{
	if(orcPHT->p_type != PT_NOTE)
		return 0;

	if(mode & NOTE)
		return 0;

#if defined(__i386__)
	Elf_Word p_filesz;
#elif defined(__x86_64__)
	Elf_Xword p_filesz;
#endif

	while((p_filesz = getElf_Half()))
		if(p_filesz % sizeof(Elf_Word) != 0)
			break;

	orcPHT->p_filesz = p_filesz;

	fprintf(logfp, "(PHT[%d]->p_filesz = 0x"HEX")", ph, orcPHT->p_filesz);

	return 1;
}

int pht9(void)
{
	if(orcPHT->p_type != PT_INTERP)
		return 0;

	if(rand() % 3 == 0) // p_type is a critical field
		return 0;

	Elf_Word p_type;
	int r = rand();

	if(r % 4 == 0){ // 25% chance
		while((p_type = getElf_Word())){
			switch(p_type){
				case PT_INTERP:
					continue;
					break;
				case PT_DYNAMIC:
					if(mode & DYN)
						continue;
					break;
				case PT_NOTE:
					if(mode & NOTE)
						continue;
					break;
			}

			break;
		}

		orcPHT->p_type = p_type;

		fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", ph, orcPHT->p_type);
	} else if(r % 4 == 1){ // 25% chance
		int k;
		Elf_Phdr *tmpPHT = elfPHT;

		for(k = 0; k < elfHDR->e_phnum; k++, tmpPHT++)
			if(tmpPHT->p_type == PT_INTERP){
				strncpy(orcptr + tmpPHT->p_offset, dirname_orcfname, strlen(dirname_orcfname));
				*(orcptr + tmpPHT->p_offset + strlen(dirname_orcfname)) = '\0';

				fprintf(logfp, "(PHT[PT_INTERP] = %s)", orcptr + tmpPHT->p_offset);

				return 1;
			}

		return 0; // Not found
	} else if(ph > 0){
		if(rand() % 2){
			if(mode & DYN)
				if(orcOrigPHT[ph - 1].p_type == PT_DYNAMIC)
					return 0;

			if(mode & NOTE)
				if(orcOrigPHT[ph - 1].p_type == PT_NOTE)
					return 0;

			orcOrigPHT[ph - 1].p_type = PT_INTERP;

			fprintf(logfp, "(PHT[%d - 1]->p_type = 0x%x)", ph, orcOrigPHT[ph - 1].p_type);
		} else if(ph < (orcHDR->e_phnum - 1)){
			if(mode & DYN)
				if(orcOrigPHT[ph + 1].p_type == PT_DYNAMIC)
					return 0;

			if(mode & NOTE)
				if(orcOrigPHT[ph + 1].p_type == PT_NOTE)
					return 0;

			orcOrigPHT[ph + 1].p_type = PT_INTERP;

			fprintf(logfp, "(PHT[%d + 1]->p_type = 0x%x)", ph, orcOrigPHT[ph + 1].p_type);
		}
	} else
		return 0;

	return 1;
}

int pht10(void)
{
	if(rand() % 2)
		orcPHT->p_flags = getElf_Half();
	else
		orcPHT->p_flags |= PF_MASKPROC;

	fprintf(logfp, "(PHT[%d]->p_flags = 0x%x)", ph, orcPHT->p_flags);

	return 1;
}

int pht11(void)
{
	if(orcPHT->p_flags & PF_X)
		orcPHT->p_flags |= PF_W;
	else
		return 0;

	fprintf(logfp, "(PHT[%d]->p_flags = 0x%x)", ph, orcPHT->p_flags);

	return 1;
}

int pht12(void)
{
	if(orcPHT->p_type != PT_DYNAMIC)
		return 0;

	if(mode & DYN)
		return 0;

	orcPHT->p_offset = getElf_Off();
	orcPHT->p_vaddr  = getElf_Addr();

	fprintf(logfp, "(PHT[%d]->p_offset = 0x"HEX",", ph, orcPHT->p_offset);
	fprintf(logfp, " p_vaddr = 0x"HEX")", orcPHT->p_vaddr);

	return 1;
}

int pht13(void)
{
	if(rand() % 2) // p_type is a critical field
		return 0;

	if(orcOrigPHT[orcHDR->e_phnum - 1].p_type != PT_NULL && 
		orcOrigPHT[orcHDR->e_phnum - 1].p_type != PT_GNU_RELRO && 
		orcOrigPHT[orcHDR->e_phnum - 1].p_type != PT_GNU_EH_FRAME && 
		orcOrigPHT[orcHDR->e_phnum - 1].p_type != PT_GNU_STACK)
		return 0;

	orcOrigPHT[orcHDR->e_phnum - 1].p_type = PT_SHLIB;

	fprintf(logfp, "(PHT[%d - 1]->p_type = 0x%x)", orcHDR->e_phnum, orcOrigPHT[orcHDR->e_phnum - 1].p_type);

	return 1;
}

int pht14(void)
{
	if(orcPHT->p_type != PT_NULL && 
		orcPHT->p_type != PT_GNU_RELRO && 
		orcPHT->p_type != PT_GNU_EH_FRAME && 
		orcPHT->p_type != PT_GNU_STACK)
		return 0;

	if(rand() % 2) // p_type is a critical field
		return 0;

	if(rand() % 2)
		orcPHT->p_type = PT_LOOS;
	else
		orcPHT->p_type = PT_HIOS;

	fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", ph, orcPHT->p_type);

	return 1;
}

int pht15(void)
{
	orcPHT->p_flags |= PF_MASKOS;

	fprintf(logfp, "(PHT[%d]->p_flags = 0x%x)", ph, orcPHT->p_flags);

	return 1;
}

int pht16(void)
{
	if(orcPHT->p_type != PT_PAX_FLAGS && 
		orcPHT->p_type != PT_GNU_RELRO && 
		orcPHT->p_type != PT_GNU_STACK)
		return 0;

	if(rand() % 3 == 0)
		orcPHT->p_offset = getElf_Off();
	orcPHT->p_vaddr  = getElf_Addr();
#if defined(__i386__)
	orcPHT->p_filesz = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_filesz = getElf_Xword();
#endif
#if defined(__i386__)
	orcPHT->p_memsz = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_memsz = getElf_Xword();
#endif
	orcPHT->p_flags = getElf_Word();
#if defined(__i386__)
	orcPHT->p_align = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_align = getElf_Xword();
#endif

	fprintf(logfp, "(PHT[%d]->p_offset = 0x"HEX",", ph, orcPHT->p_offset);
	fprintf(logfp, " p_vaddr = 0x"HEX",", orcPHT->p_vaddr);
	fprintf(logfp, " p_filesz = 0x"HEX",", orcPHT->p_filesz);
	fprintf(logfp, " p_memsz = 0x"HEX",", orcPHT->p_memsz);
	fprintf(logfp, " p_flags = 0x%x,", orcPHT->p_flags);
	fprintf(logfp, " p_align = 0x"HEX")", orcPHT->p_align);

	return 1;
}

int pht17(void)
{
	if(orcPHT->p_type != PT_TLS)
		return 0;

	if(rand() % 3 == 0)
		orcPHT->p_offset = getElf_Off();
	orcPHT->p_vaddr  = getElf_Addr();
#if defined(__i386__)
	orcPHT->p_filesz = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_filesz = getElf_Xword();
#endif
#if defined(__i386__)
	orcPHT->p_memsz = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_memsz = getElf_Xword();
#endif
	orcPHT->p_flags = getElf_Word();
#if defined(__i386__)
	orcPHT->p_align = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_align = getElf_Xword();
#endif

	fprintf(logfp, "(PHT[%d]->p_offset = 0x"HEX",", ph, orcPHT->p_offset);
	fprintf(logfp, " p_vaddr = 0x"HEX",", orcPHT->p_vaddr);
	fprintf(logfp, " p_filesz = 0x"HEX",", orcPHT->p_filesz);
	fprintf(logfp, " p_memsz = 0x"HEX",", orcPHT->p_memsz);
	fprintf(logfp, " p_flags = 0x%x,", orcPHT->p_flags);
	fprintf(logfp, " p_align = 0x"HEX")", orcPHT->p_align);

	return 1;
}

int pht18(void)
{
	if(orcPHT->p_type != PT_GNU_EH_FRAME)
		return 0;

	if(rand() % 3 == 0)
		orcPHT->p_offset = getElf_Off();
	orcPHT->p_vaddr  = getElf_Addr();
#if defined(__i386__)
	orcPHT->p_filesz = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_filesz = getElf_Xword();
#endif
#if defined(__i386__)
	orcPHT->p_memsz = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_memsz = getElf_Xword();
#endif
	orcPHT->p_flags = getElf_Word();
#if defined(__i386__)
	orcPHT->p_align = getElf_Word();
#elif defined(__x86_64__)
	orcPHT->p_align = getElf_Xword();
#endif

	fprintf(logfp, "(PHT[%d]->p_offset = 0x"HEX",", ph, orcPHT->p_offset);
	fprintf(logfp, " p_vaddr = 0x"HEX",", orcPHT->p_vaddr);
	fprintf(logfp, " p_filesz = 0x"HEX",", orcPHT->p_filesz);
	fprintf(logfp, " p_memsz = 0x"HEX",", orcPHT->p_memsz);
	fprintf(logfp, " p_flags = 0x%x,", orcPHT->p_flags);
	fprintf(logfp, " p_align = 0x"HEX")", orcPHT->p_align);

	return 1;
}

int pht19(void)
{
	int p, last_PT = -1;
	Elf_Phdr *tmpPHT = orcOrigPHT;
	int r = rand();

	if(r % 3 == 0){ // 33.33% chance // Deletes the PT_PHDR from the PHT
		for(p = 0; p < orcHDR->e_phnum; p++, tmpPHT++)
			if(tmpPHT->p_type == PT_PHDR){
				tmpPHT->p_type = getElf_Word();

				fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", p, tmpPHT->p_type);

				break;
			}
	} else if(r % 3 == 1){ // Create an extra PT_PHT right after the first one found in the PHT
		for(p = 0; p < orcHDR->e_phnum; p++, tmpPHT++)
			if(tmpPHT->p_type == PT_PHDR)
				last_PT = p;

		if(last_PT == -1)
			return 0;

		if(last_PT == (orcHDR->e_phnum - 1)){ // No more program headers
			if(mode & DYN)
				if(orcOrigPHT[last_PT].p_type == PT_DYNAMIC)
					return 0;

			if(mode & NOTE)
				if(orcOrigPHT[last_PT].p_type == PT_NOTE)
					return 0;

			orcOrigPHT[last_PT].p_type = PT_PHDR;

			fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", last_PT, orcOrigPHT[last_PT].p_type);
		} else { // Set to PT_PHT right after the latest found
			if(mode & DYN)
				if(orcOrigPHT[last_PT + 1].p_type == PT_DYNAMIC)
					return 0;

			if(mode & NOTE)
				if(orcOrigPHT[last_PT + 1].p_type == PT_NOTE)
					return 0;

			orcOrigPHT[last_PT + 1].p_type = PT_PHDR;

			fprintf(logfp, "(PHT[%d + 1]->p_type = 0x%x)", last_PT, orcOrigPHT[last_PT + 1].p_type);
		}
	} else { // Set to PT_PHDR the latest entry in the PHT (after the PT_LOAD segments)
		if(mode & DYN)
			if(orcOrigPHT[orcHDR->e_phnum - 1].p_type == PT_DYNAMIC)
				return 0;

		if(mode & NOTE)
			if(orcOrigPHT[orcHDR->e_phnum - 1].p_type == PT_NOTE)
				return 0;

		orcOrigPHT[orcHDR->e_phnum - 1].p_type = PT_PHDR;

		fprintf(logfp, "(PHT[%d - 1]->p_type = 0x%x)", orcHDR->e_phnum, orcOrigPHT[orcHDR->e_phnum - 1].p_type);
	}

	return 1;
}

int pht20(void)
{
	int a, b;
	Elf_Phdr swap;

	// Bubble sort algorithm to put the PT_LOAD segments in decreasing order based in their p_vaddr
	for(a = 0; a < orcHDR->e_phnum - 1; a++){
		if(orcOrigPHT[a].p_type != PT_LOAD)
			continue;

		for(b = 0; b < orcHDR->e_phnum - 1 - a; b++){
			if(orcOrigPHT[b].p_type != PT_LOAD)
				continue;

			if(orcOrigPHT[b].p_vaddr < orcOrigPHT[a].p_vaddr){
				memcpy(&swap, &orcOrigPHT[b], sizeof(Elf_Phdr));
				memcpy(&orcOrigPHT[b], &orcOrigPHT[b + 1], sizeof(Elf_Phdr));
				memcpy(&orcOrigPHT[b + 1], &swap, sizeof(Elf_Phdr));
			}
		}
	}

	fprintf(logfp, "(PHT[PT_LOAD].p_vaddr reordered [descending])");

	return 1;
}

int pht21(void)
{
	int p, last_INTERP = -1;
	Elf_Phdr swap, *tmpPHT = orcOrigPHT;

	for(p = 0; p < orcHDR->e_phnum; p++, tmpPHT++)
		if(tmpPHT->p_type == PT_INTERP)
			last_INTERP = p;

	if(last_INTERP == -1)
		return 0;

	memcpy(&swap, &orcOrigPHT[last_INTERP], sizeof(Elf_Phdr));
	memcpy(&orcOrigPHT[last_INTERP], &orcOrigPHT[orcHDR->e_phnum - 1], sizeof(Elf_Phdr));
	memcpy(&orcOrigPHT[orcHDR->e_phnum - 1], &swap, sizeof(Elf_Phdr));

	fprintf(logfp, "(PHT[PT_INTERP] relocated to the end of the PHT. PHT[%d] is now PHT[%d])", orcHDR->e_phnum - 1, last_INTERP);

	return 1;
}

int pht22(void)
{
	int p, found = 0;
	Elf_Phdr *tmpPHT = orcOrigPHT;

	for(p = 0; p < orcHDR->e_phnum; p++, tmpPHT++)
		if(tmpPHT->p_type == PT_DYNAMIC){
			found++;
			break;
		}

	if(found){
		if(mode & DYN)
			return 0;

		if(rand() % 2) // PT_DYNAMIC is important
			return 0;

		if(rand() % 3 == 0)
			tmpPHT->p_offset = getElf_Off();
		tmpPHT->p_vaddr  = getElf_Addr();
#if defined(__i386__)
		tmpPHT->p_filesz = getElf_Word();
#elif defined(__x86_64__)
		tmpPHT->p_filesz = getElf_Xword();
#endif
#if defined(__i386__)
		tmpPHT->p_memsz = getElf_Word();
#elif defined(__x86_64__)
		tmpPHT->p_memsz = getElf_Xword();
#endif
		tmpPHT->p_flags = getElf_Word();
#if defined(__i386__)
		tmpPHT->p_align = getElf_Word();
#elif defined(__x86_64__)
		tmpPHT->p_align = getElf_Xword();
#endif

		fprintf(logfp, "(PHT[%d]->p_offset = 0x"HEX",", p, tmpPHT->p_offset);
		fprintf(logfp, " p_vaddr = 0x"HEX",", tmpPHT->p_vaddr);
		fprintf(logfp, " p_filesz = 0x"HEX",", tmpPHT->p_filesz);
		fprintf(logfp, " p_memsz = 0x"HEX",", tmpPHT->p_memsz);
		fprintf(logfp, " p_flags = 0x%x,", tmpPHT->p_flags);
		fprintf(logfp, " p_align = 0x"HEX")", tmpPHT->p_align);

		return 1;
	} else {
		tmpPHT = orcOrigPHT;

		for(p = 0; p < orcHDR->e_phnum; p++, tmpPHT++)
			if(tmpPHT->p_type == PT_NULL){
				if(mode & DYN)
					return 0;

				tmpPHT->p_type = PT_DYNAMIC;

				fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", p, tmpPHT->p_type);

				return 1;
			}

		tmpPHT = orcOrigPHT;

		// Less priority than overwriting a PT_NULL
		for(p = 0; p < orcHDR->e_phnum; p++, tmpPHT++)
			if(tmpPHT->p_type == PT_GNU_STACK){
				if(mode & DYN)
					return 0;

				tmpPHT->p_type = PT_DYNAMIC;

				fprintf(logfp, "(PHT[%d]->p_type = 0x%x)", p, tmpPHT->p_type);

				return 1;
			}

		return 0;
	}
}

void initialize_pht_funcs(void)
{
	pht[1]  = &pht1;
	pht[2]  = &pht2;
	pht[3]  = &pht3;
	pht[4]  = &pht4;
	pht[5]  = &pht5;
	pht[6]  = &pht6;
	pht[7]  = &pht7;
	pht[8]  = &pht8;
	pht[9]  = &pht9;
	pht[10] = &pht10;
	pht[11] = &pht11;
	pht[12] = &pht12;
	pht[13] = &pht13;
	pht[14] = &pht14;
	pht[15] = &pht15;
	pht[16] = &pht16;
	pht[17] = &pht17;
	pht[18] = &pht18;
	pht[19] = &pht19;
	pht[20] = &pht20;
	pht[21] = &pht21;
	pht[22] = &pht22;
}
