/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define BUFF_SIZE 1024

static char *fuzz_paths[] = {
	"orcs_libfoo.so/",
	"../orcs_libfoo.so/",
	"./..../",
	";/;;/",
	"/.so/",
	"~~//",
	"\\",
	"$/",
};

int main(int argc, char *argv[], char *envp[])
{
	unsigned short ndx;
	char orcfname[strlen("orc_") + 16];
	char *env_LD_PRELOAD = malloc(BUFF_SIZE); // Yeah yeah, I prefer to spend time writing this comment than checking the returned value by malloc() :D

	srand(getseed());

	// Overflows and off-by-one's section :D, exploit them !
	*env_LD_PRELOAD = '\0';
	while(strlen(env_LD_PRELOAD) < BUFF_SIZE){
		if(rand() % 2){
			ndx = rand() % 2; // First two entries. Valid paths to ../orcs_libfoo.so/ in case libfoo.so has been already fuzzed
			if(strlen(env_LD_PRELOAD) + strlen(fuzz_paths[ndx]) < BUFF_SIZE)
				strcat(env_LD_PRELOAD, fuzz_paths[ndx]);
			else
				break;
		} else {
			ndx = 2 + (rand() % (sizeof(fuzz_paths) / sizeof(char *)) - 2);
			if(strlen(env_LD_PRELOAD) + strlen(fuzz_paths[ndx]) < BUFF_SIZE)
				strcat(env_LD_PRELOAD, fuzz_paths[ndx]);
			else
				break;
		}

		snprintf(orcfname, sizeof(orcfname), "orc_%.4d.so", 1 + rand() % 100);
		if(strlen(env_LD_PRELOAD) + strlen(orcfname) < BUFF_SIZE)
			strcat(env_LD_PRELOAD, orcfname);
		else
			break;

		if(rand() % 10 < 1) // Double .so extension
			if(strlen(env_LD_PRELOAD) + 3 < BUFF_SIZE)
				strcat(env_LD_PRELOAD, ".so");

		if(strlen(env_LD_PRELOAD) + 1 < BUFF_SIZE)
			strcat(env_LD_PRELOAD, ":");

		if(strlen(env_LD_PRELOAD) == BUFF_SIZE - 1)
			break;
	}

	printf("%s", env_LD_PRELOAD);

	free(env_LD_PRELOAD);

	return 0;
}
