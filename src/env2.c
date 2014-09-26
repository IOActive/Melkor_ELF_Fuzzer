/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

#define BUFF_SIZE 2048

int main(int argc, char *argv[], char *envp[])
{
	unsigned short cnt = 0, ndx;
	char *env_PATH, *path, env_paths[13][37]; // Only 13 paths taken from $PATH with 37 chars each one, enough to play with ...
	char *env_LD_LIBRARY_PATH = malloc(BUFF_SIZE); // Yeah yeah, I prefer to spend time writing this comment than checking the returned value by malloc() :D
	char *fuzzed_path;

	// Split $PATH
	env_PATH = getenv("PATH");

	path = strtok(env_PATH, ":");
	strncpy(env_paths[cnt], path, 37);
	env_paths[cnt++][36] = '\0';

	while((path = strtok(NULL, ":")) != NULL && cnt < 13){
		strncpy(env_paths[cnt], path, 37);
		env_paths[cnt++][36] = '\0';
	}
	// Split

	srand(getseed());

	// Overflows and off-by-one's section :D, exploit them !
	*env_LD_LIBRARY_PATH = '\0';
	while(strlen(env_LD_LIBRARY_PATH) < BUFF_SIZE){
		if(rand() % 4 < 3){ // 75% chance of valid paths
			ndx = rand() % cnt;
			if(strlen(env_LD_LIBRARY_PATH) + strlen(env_paths[ndx]) < BUFF_SIZE)
				strcat(env_LD_LIBRARY_PATH, env_paths[ndx]);
			else
				break;
		} else {
			fuzzed_path = get_fuzzed_path();

			if(strlen(env_LD_LIBRARY_PATH) + strlen(fuzzed_path) < BUFF_SIZE)
				strcat(env_LD_LIBRARY_PATH, fuzzed_path);
			else
				break;
		}

		if(strlen(env_LD_LIBRARY_PATH) + 1 < BUFF_SIZE)
			strcat(env_LD_LIBRARY_PATH, ":");

		if(strlen(env_LD_LIBRARY_PATH) == BUFF_SIZE - 1)
			break;
	}

	printf("%s", env_LD_LIBRARY_PATH);

	free(env_LD_LIBRARY_PATH);

	return 0;
}
