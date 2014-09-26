/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define N_RULES_NOTE 4 // Total of fuzzing rules defined for this metadata type

// Array of function pointers. Index zero won't be used. The fuzzing rules start from index 1
func_ptr note[N_RULES_NOTE + 1];

void initialize_note_funcs(void) __attribute__((constructor));

/* External vars */
extern FILE *logfp;
extern unsigned int quiet;
extern unsigned int like_a, like_b;
extern unsigned int secnum;
extern unsigned int entry;
extern Elf_Nhdr	*elfNOTE, *orcNOTE;

void fuzz_note()
{
	int rule;

	for(rule = 1; rule <= N_RULES_NOTE; rule++)
		if((rand() % like_a) < like_b)
			if(note[rule]()){
				printf(". ");
				debug("SHT[%d] NOTE[%d] rule [%.2d] executed\n", secnum, entry, rule);
				fprintf(logfp, " | SHT[%d] NOTE[%d] rule [%.2d] executed\n", secnum, entry, rule);
			}
}

int note1(void)
{
	orcNOTE->n_namesz = getElf_Word();

	fprintf(logfp, "(NOTE[%d]->n_namesz = 0x%x)", entry, orcNOTE->n_namesz);

	return 1;
}

int note2(void)
{
	unsigned int ptr_offset = 0;
	char *fmt_ptr;

	fprintf(logfp, "(NOTE[%d] + %d (sizeof(Elf_Nhdr)) + ", entry, (int) sizeof(Elf_Nhdr));

	if(rand() % 3 == 0)
		while(ptr_offset < elfNOTE->n_namesz){ // Trusting in n_namesz from the original ELF. This field in the Orc might be already fuzzed
			fmt_ptr = get_fmt_str();

			memcpy((void *) orcNOTE + sizeof(Elf_Nhdr) + ptr_offset, fmt_ptr, strlen(fmt_ptr));
			fprintf(logfp, "%d =%s, ", ptr_offset, fmt_ptr);

			ptr_offset += 4;
		}
	else
		while(ptr_offset < elfNOTE->n_namesz){
			if(*((char *) orcNOTE + sizeof(Elf_Nhdr) + ptr_offset) != 0){
				ptr_offset++;
				continue;
			}

			*((char *) orcNOTE + sizeof(Elf_Nhdr) + ptr_offset) = (rand() & 0x7f) + 0x80; // > 7-bit ASCII chars
			fprintf(logfp, "%d = %c (0x%.2x), ", ptr_offset, *((char *) orcNOTE + sizeof(Elf_Nhdr) + ptr_offset), *((char *) orcNOTE + sizeof(Elf_Nhdr) + ptr_offset) & 0xff);
			ptr_offset++;
		}

	fprintf(logfp, ")");

	return 1;
}

int note3(void)
{
	unsigned int cnt = 0;
	int *desc = (int *) ((void *) orcNOTE + sizeof(Elf_Nhdr) + elfNOTE->n_namesz);

	fprintf(logfp, "(NOTE[%d] + %d (sizeof(Elf_Nhdr)) + %d (elfNOTE->n_namesz) + ", entry, (int) sizeof(Elf_Nhdr), elfNOTE->n_namesz);

	while(cnt < elfNOTE->n_descsz){ // Trusting in n_descsz from the original ELF. This field in the Orc might be already fuzzed
		*desc = getElf_Word();

		fprintf(logfp, "%d = 0x%x, ", cnt, *desc);

		desc++;
		cnt += sizeof(Elf_Word);
	}

	fprintf(logfp, ")");

	orcNOTE->n_descsz = getElf_Word();

	fprintf(logfp, "(NOTE[%d]->n_descsz = 0x%x)", entry, orcNOTE->n_descsz);

	return 1;
}

int note4(void)
{
	if(rand() % 4 < 3) // Metadata in previous rules is used based upon n_type
		return 0;

	orcNOTE->n_type = 0x80000000 + (rand() % 0x7fffffff);

	fprintf(logfp, "(NOTE[%d]->n_type = 0x%x)", entry, orcNOTE->n_type);

	return 1;
}

void initialize_note_funcs(void)
{
	note[1] = &note1;
	note[2] = &note2;
	note[3] = &note3;
	note[4] = &note4;
}
