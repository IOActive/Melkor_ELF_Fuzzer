/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#ifdef BSD
#define DT_NUM 34
#define SHT_GNU_HASH 0x6ffffff6
#define DT_GNU_HASH 0x6ffffef5
#endif

#define N_RULES_DYN 18 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr dyn[N_RULES_DYN + 1];

void initialize_dyn_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern unsigned int secnum;
extern unsigned int entry;
extern char *orcptr;
extern Elf_Ehdr	*orcHDR;
extern Elf_Shdr	*elfSHT, *orcSHT;
extern Elf_Dyn *elfDYN, *orcDYN;
extern Elf_Dyn *elfOrigDYN;
extern Elf_Off linkstrtab_offset;

void fuzz_dyn()
{
	int rule;

	for(rule = 1; rule <= N_RULES_DYN; rule++)
		if((rand() % like_a) < like_b)
			if(dyn[rule]()){
				printf(". ");
				debug("SHT[%d] DYN[%d] rule [%.2d] executed\n", secnum, entry, rule);
				fprintf(logfp, " | SHT[%d] DYN[%d] rule [%.2d] executed\n", secnum, entry, rule);
			}
}

int dyn1(void)
{
	if(orcDYN->d_tag != DT_NEEDED &&
		orcDYN->d_tag != DT_SONAME &&
		orcDYN->d_tag != DT_RPATH)
		return 0;

	if(rand() % 3 == 0)
		return 0;

	orcDYN->d_un.d_val = rand() & 0x0fff; // 12-bit random offset

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn2(void)
{
	if(orcDYN->d_tag != DT_PLTRELSZ &&
		orcDYN->d_tag != DT_RELSZ &&
		orcDYN->d_tag != DT_RELASZ &&
		orcDYN->d_tag != DT_STRSZ)
		return 0;

	if(rand() % 2)
		return 0;

	int r = rand();

	if(r % 4 < 2) // 50% chance
		orcDYN->d_un.d_val = rand() & 0xff;
	else if(r % 4 == 2)
		orcDYN->d_un.d_val = getElf_Word();
	else
		orcDYN->d_un.d_val = 0x00;

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn3(void)
{
	if(orcDYN->d_tag != DT_RELENT &&
		orcDYN->d_tag != DT_RELAENT &&
		orcDYN->d_tag != DT_SYMENT)
		return 0;

	if(rand() % 2)
		return 0;

	int r = rand();

	if(r % 4 < 2) // 50% chance
		orcDYN->d_un.d_val = rand() & 0xff;
	else if(r % 4 == 2)
		orcDYN->d_un.d_val = getElf_Word();
	else
		orcDYN->d_un.d_val = 0x00;

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn4(void)
{
	if(orcDYN->d_tag != DT_PLTGOT)
		return 0;

	if(rand() % 2)
		 orcDYN->d_un.d_ptr = getElf_Addr();
	else
		return 0;

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn5(void)
{
	if(orcDYN->d_tag != DT_HASH &&
		orcDYN->d_tag != DT_GNU_HASH &&
		orcDYN->d_tag != DT_SYMTAB)
		return 0;

	if(rand() % 2)
		orcDYN->d_un.d_ptr = getElf_Addr();

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn6(void)
{
	if(orcDYN->d_tag != DT_INIT &&
		orcDYN->d_tag != DT_FINI)
		return 0;

	int r = rand();

	if(r % 3 == 0)
		orcDYN->d_un.d_ptr = getElf_Addr();
	else if(r % 3 == 1)
		orcDYN->d_un.d_ptr = orcHDR->e_entry; // jmp to the original entrypoint
	else {
		if(orcDYN->d_tag == DT_INIT)
			orcDYN->d_un.d_ptr = get_d_ptr_by_d_tag(DT_FINI);
		else 
			orcDYN->d_un.d_ptr = get_d_ptr_by_d_tag(DT_INIT);
	}

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn7(void)
{
	if(orcDYN->d_tag != DT_DEBUG)
		return 0;

	if(rand() % 2)
		return 0;

	if(rand() % 2)
		orcDYN->d_tag = DT_SYMBOLIC;
	else
		orcDYN->d_tag = DT_TEXTREL;

	fprintf(logfp, "(DYN[%d]->d_tag = 0x"HEX")", entry, orcDYN->d_tag);

	return 1;
}

int dyn8(void)
{
	if(orcDYN->d_tag != DT_PLTREL)
		return 0;

	if(rand() % 2)
		return 0;

#if defined(__i386__)
	Elf_Word d_val;
#elif defined(__x86_64__)
	Elf_Xword d_val;
#endif

	while((d_val = rand() % DT_NUM))
		if(d_val != DT_REL && d_val != DT_RELA)
			break;

	orcDYN->d_un.d_val = d_val;

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn9(void)
{
	if(orcDYN->d_tag != DT_DEBUG)
		return 0;

	if(rand() % 2)
		return 0;

	orcDYN->d_tag = DT_BIND_NOW;

	fprintf(logfp, "(DYN[%d]->d_tag = 0x"HEX")", entry, orcDYN->d_tag);

	return 1;
}

int dyn10(void)
{
	if(orcDYN->d_tag != DT_RPATH &&
		orcDYN->d_tag != DT_RUNPATH)
		return 0;

	unsigned int s = strlen(orcptr + linkstrtab_offset + elfDYN->d_un.d_val);
	char *rpath = malloc(s);
	char *fuzzed_path;
	int fuzzed = 0;

	*rpath = '\0';
	while(strlen(rpath) < s){
		fuzzed_path = get_fuzzed_path();

		if(strlen(rpath) + strlen(fuzzed_path) < s){
			strcat(rpath, fuzzed_path);
			fuzzed = 1;
		} else
			break;

		if(strlen(rpath) + 1 < s)
			strcat(rpath, ":");

		if(strlen(rpath) == s - 1)
			break;
	}

	if(!fuzzed)
		return 0;

	strncpy(orcptr + linkstrtab_offset + elfDYN->d_un.d_val, rpath, s);

	fprintf(logfp, "(DYN[%d]->(d_val + 0) = %s)", entry, orcptr + linkstrtab_offset + elfDYN->d_un.d_val);

	free(rpath);

	return 1;
}

int dyn11(void)
{
	if(orcDYN->d_tag != DT_PLTREL)
		return 0;

	if(rand() % 2)
		return 0;

#if defined(__i386__)
	orcDYN->d_un.d_val = DT_RELA;
#elif defined(__x86_64__)
	orcDYN->d_un.d_val = DT_REL;
#endif

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn12(void)
{
	if(orcDYN->d_tag != DT_PLTGOT)
		return 0;

	Elf_Section ndx;

	if(!(ndx = findSectionIndexByName(".got.plt")))
		return 0;

	Elf_Addr *d_ptr = (void *) orcptr + elfSHT[ndx].sh_offset;

	if(rand() % 5 == 0) // 20% chance to modify the first entry, which is the address of _DYNAMIC[]
		*d_ptr++ = getElf_Addr();
	else
		d_ptr++;

	*d_ptr++ = getElf_Addr();
	*d_ptr++ = getElf_Addr();

	d_ptr = (void *) orcptr + elfSHT[ndx].sh_offset; // Points back again to print the results

	fprintf(logfp, "(DYN[%d]->(d_un.d_ptr + 0) = 0x"HEX",", entry, *d_ptr++);
	fprintf(logfp, " (d_un.d_ptr + %d) = 0x"HEX",", (unsigned int) sizeof(Elf_Addr *), *d_ptr++);
	fprintf(logfp, " (d_un.d_ptr + %d) = 0x"HEX")", (unsigned int) sizeof(Elf_Addr *), *d_ptr);

	return 1;
}

int dyn13(void)
{
	if(orcDYN->d_tag != DT_PLTRELSZ)
		return 0;

	if(rand() % 3 < 2)
		return 0;

#if defined(__i386__)
	Elf_Sword d_tag;
#elif defined(__x86_64__)
	Elf_Sxword d_tag;
#endif

	if(rand() % 3 < 2){
		while((d_tag = rand() % 0xff))
			if(d_tag != DT_PLTRELSZ)
				break;
	} else
#if defined(__i386__)
		d_tag = getElf_Word();
#elif defined(__x86_64__)
		d_tag = getElf_Xword();
#endif

	orcDYN->d_tag = d_tag;

	fprintf(logfp, "(DYN[%d]->d_tag = 0x"HEX")", entry, orcDYN->d_tag);

	return 1;
}

int dyn14(void)
{
	if(orcDYN->d_tag != DT_RELASZ &&
		orcDYN->d_tag != DT_RELSZ &&
		orcDYN->d_tag != DT_RELAENT &&
		orcDYN->d_tag != DT_RELENT)
		return 0;

	if(rand() % 4 < 3)
		return 0;

#if defined(__i386__)
	Elf_Sword d_tag;
#elif defined(__x86_64__)
	Elf_Sxword d_tag;
#endif

	if(rand() % 3 < 2){
		while((d_tag = rand() % 0xff))
			if(d_tag != DT_RELASZ &&
				d_tag != DT_RELSZ &&
				d_tag != DT_RELAENT &&
				d_tag != DT_RELENT)
				break;
	} else
#if defined(__i386__)
		d_tag = getElf_Word();
#elif defined(__x86_64__)
		d_tag = getElf_Xword();
#endif

	orcDYN->d_tag = d_tag;

	fprintf(logfp, "(DYN[%d]->d_tag = 0x"HEX")", entry, orcDYN->d_tag);

	return 1;
}

int dyn15(void)
{
	if(orcDYN->d_tag != DT_NULL)
		return 0;

	if(rand() % 5 < 3) // DT_NULL is fucking critical: is the end of _DYNAMIC[]
		return 0;

#if defined(__i386__)
	Elf_Sword d_tag;
#elif defined(__x86_64__)
	Elf_Sxword d_tag;
#endif

	if(rand() % 3 < 2){
		while((d_tag = rand() % 0xff))
			if(d_tag != DT_NULL)
				break;
	} else
#if defined(__i386__)
		d_tag = getElf_Word();
#elif defined(__x86_64__)
		d_tag = getElf_Xword();
#endif

	orcDYN->d_tag = d_tag;

	fprintf(logfp, "(DYN[%d]->d_tag = 0x"HEX")", entry, orcDYN->d_tag);

	return 1;
}

int dyn16(void)
{
	if(orcDYN->d_tag != DT_INIT_ARRAY &&
		orcDYN->d_tag != DT_FINI_ARRAY)
		return 0;

	if(rand() % 2) // Constructors & Destructors are cool
		return 0;

	Elf_Word array_size;
	Elf_Section ndx;

	if(orcDYN->d_tag == DT_INIT_ARRAY)
		array_size = get_d_val_by_d_tag(DT_INIT_ARRAYSZ);
	else 
		array_size = get_d_val_by_d_tag(DT_FINI_ARRAYSZ);

	if(array_size <= sizeof(Elf_Addr *)) // There's more than the default functions
		return 0;

	if(orcDYN->d_tag == DT_INIT_ARRAY){
		if(!(ndx = findSectionIndexByName(".init_array")))
			return 0;
	} else {
		if(!(ndx = findSectionIndexByName(".fini_array")))
			return 0;
	}

	Elf_Addr *d_ptr = (void *) orcptr + elfSHT[ndx].sh_offset;

	d_ptr++;

	*d_ptr = getElf_Addr(); // DT_(INIT|FINI)_ARRAY[1]

	d_ptr = (void *) orcptr + elfSHT[ndx].sh_offset; // Points back again to print the results

	fprintf(logfp, "(DYN[%d]->(d_un.d_ptr + 0) = 0x"HEX",", entry, *d_ptr++);
	fprintf(logfp, " (d_un.d_ptr + %d) = 0x"HEX")", (unsigned int) sizeof(Elf_Addr *), *d_ptr);

	return 1;
}

int dyn17(void)
{
	if(orcDYN->d_tag != DT_INIT_ARRAYSZ &&
		orcDYN->d_tag != DT_FINI_ARRAYSZ)
		return 0;

	if(rand() % 2)
		return 0;

#if defined(__i386__)
	Elf_Word d_val;
#elif defined(__x86_64__)
	Elf_Xword d_val;
#endif

	if(rand() % 2){
		while((d_val = rand() & 0xffff))
			if(d_val % 4 != 0)
				break;
	} else {
		d_val = orcDYN->d_un.d_val;

#if defined(__i386__)
		d_val += 8; // A ptr in 64-bit is 8 bytes. Add 8 to 32-bit ELF
#elif defined(__x86_64__)
		d_val += 4; // Vice versa
#endif
	}

	orcDYN->d_un.d_val = d_val;

	fprintf(logfp, "(DYN[%d]->d_un.d_val = 0x"HEX")", entry, orcDYN->d_un.d_val);

	return 1;
}

int dyn18(void)
{
	if(rand() % 20 < 19) // d_tag is critical
		return 0;

	// d_tag is a Sword (Signed Word)
	if(rand() % 2){ // 50% chance to set d_tag to a negative number > 0x7fffffff
#if defined(__x86_64__)
		if(rand() % 2)
			orcDYN->d_tag = 0x8000000000000000 + (rand() % 0x7fffffff);
		else
#endif
			orcDYN->d_tag = 0x80000000 + (rand() % 0x7fffffff);
	} else {
		if(rand() % 3 < 2){
			if(rand() % 2)
				orcDYN->d_tag = getElf_Word();
			else
				orcDYN->d_tag = getElf_Xword();
		} else {
			int r = rand();

			if(r % 4 == 0)
				 orcDYN->d_tag = DT_LOOS;
			else if(r % 4 == 1)
				 orcDYN->d_tag = DT_HIOS;
			else if(r % 4 == 2)
				 orcDYN->d_tag = DT_LOPROC;
			else
				 orcDYN->d_tag = DT_HIPROC;
		}
	}

	fprintf(logfp, "(DYN[%d]->d_tag = 0x"HEX")", entry, orcDYN->d_tag);

	return 1;
}


Elf_Addr get_d_ptr_by_d_tag(Elf_Sword d_tag)
{
	int k;
	Elf_Dyn *tmpDYN = elfOrigDYN;

	for(k = 0; k < orcSHT->sh_size / orcSHT->sh_entsize; k++, tmpDYN++)
		if(tmpDYN->d_tag == d_tag)
			return tmpDYN->d_un.d_ptr;

	return (Elf_Addr) NULL;
}

Elf_Word get_d_val_by_d_tag(Elf_Sword d_tag)
{
	int k;
	Elf_Dyn *tmpDYN = elfOrigDYN;

	for(k = 0; k < orcSHT->sh_size / orcSHT->sh_entsize; k++, tmpDYN++)
		if(tmpDYN->d_tag == d_tag)
			return tmpDYN->d_un.d_val;

	return 0;
}

void initialize_dyn_funcs(void)
{
	dyn[1]  = &dyn1;
	dyn[2]  = &dyn2;
	dyn[3]  = &dyn3;
	dyn[4]  = &dyn4;
	dyn[5]  = &dyn5;
	dyn[6]  = &dyn6;
	dyn[7]  = &dyn7;
	dyn[8]  = &dyn8;
	dyn[9]  = &dyn9;
	dyn[10] = &dyn10;
	dyn[11] = &dyn11;
	dyn[12] = &dyn12;
	dyn[13] = &dyn13;
	dyn[14] = &dyn14;
	dyn[15] = &dyn15;
	dyn[16] = &dyn16;
	dyn[17] = &dyn17;
	dyn[18] = &dyn18;
}
