/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define N_RULES_STRS 3 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr strs[N_RULES_STRS + 1];

void initialize_strs_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int mode; // Metadata to fuzz (parameters given in argv[])
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern unsigned int secnum;
extern char *orcSTRS;
extern Elf_Shdr	*orcSHT;

void fuzz_strs()
{
	int rule;

	for(rule = 1; rule <= N_RULES_STRS; rule++)
		if((rand() % like_a) < like_b)
			if(strs[rule]()){
				printf(". ");
				debug("STRS[%d] rule [%.2d] executed\n", secnum, rule);
				fprintf(logfp, " | STRS[%d] rule [%.2d] executed\n", secnum, rule);
			}
}

int strs1(void)
{
	if(mode & (SHT | NOTE | DYN | SYM | REL))
		if(rand() % 3 < 2)
			return 0;

	unsigned int ptr_offset = (rand() % 15) + 1; // Avoid the first NULL byte (index 0)

	fprintf(logfp, "(STRS[%d]->sh_offset (0x%x) + ", secnum, (unsigned int) orcSHT->sh_offset);

	while(ptr_offset < orcSHT->sh_size - 1){
		if(*(orcSTRS + ptr_offset) == 0){
			ptr_offset += rand() % 15 + rand() % 15;
			continue;
		}

		*(orcSTRS + ptr_offset) = (rand() & 0x7f) + 0x80; // > 7-bit ASCII chars
		fprintf(logfp, "%d = %c (0x%.2x), ", ptr_offset, *(orcSTRS + ptr_offset), *(orcSTRS + ptr_offset) & 0xff);

		ptr_offset += rand() % 15 + rand() % 15;
	}

	fprintf(logfp, ")");

	return 1;
}

int strs2(void)
{
	if(mode & (SHT | NOTE | DYN | SYM | REL))
		if(rand() % 3 < 2)
			return 0;

	fprintf(logfp, "(STRS[%d]->sh_offset (0x%x) + ", secnum, (unsigned int) orcSHT->sh_offset);

	if(rand() % 2){
		unsigned int ptr_offset = 1;

		while(ptr_offset < orcSHT->sh_size - 1){
			if(*(orcSTRS + ptr_offset) != 0){
				ptr_offset += rand() % 5;
				continue;
			}

			*(orcSTRS + ptr_offset) = (rand() & 0x7f) + 0x80; // > 7-bit ASCII chars
			fprintf(logfp, "%d = %c (0x%.2x), ", ptr_offset, *(orcSTRS + ptr_offset), *(orcSTRS + ptr_offset) & 0xff);

			ptr_offset += rand() % 5;
		}
	} else {
		*(orcSTRS) = (rand() & 0x7f) + 0x80; // > 7-bit ASCII chars
		fprintf(logfp, "0 = %c (0x%.2x), ", *(orcSTRS), *(orcSTRS) & 0xff);

		*(orcSTRS + orcSHT->sh_size - 1) = (rand() & 0x7f) + 0x80;
		fprintf(logfp, "%d = %c (0x%.2x), ", (int) orcSHT->sh_size - 1, *(orcSTRS + orcSHT->sh_size - 1), *(orcSTRS + orcSHT->sh_size - 1) & 0xff);
	}

	fprintf(logfp, ")");

	return 1;
}

int strs3(void)
{
	if(mode & (SHT | NOTE | DYN | SYM | REL))
		if(rand() % 3 < 2)
			return 0;

	unsigned int ptr_offset = rand() % 20;
	char *fmt_ptr;

	fprintf(logfp, "(STRS[%d]->sh_offset (0x%x) + ", secnum, (unsigned int) orcSHT->sh_offset);

	while(ptr_offset < orcSHT->sh_size - 2){
		fmt_ptr = get_fmt_str();

		memcpy(orcSTRS + ptr_offset, fmt_ptr, strlen(fmt_ptr));
		fprintf(logfp, "%d =%s, ", ptr_offset, fmt_ptr);

		ptr_offset += rand() % 20 + rand() % 20;
	}

	fprintf(logfp, ")");

	return 1;
}

void initialize_strs_funcs(void)
{
	strs[1] = &strs1;
	strs[2] = &strs2;
	strs[3] = &strs3;
}
