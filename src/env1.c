/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

int main()
{
	char *env_LD_BIND_NOW;

	srand(getseed());

	if(rand() % 2){
		int r = rand();

		if(r % 3 == 0)
			env_LD_BIND_NOW = "1";
		else if(r % 3 == 1)
			env_LD_BIND_NOW = "on";
		else
			env_LD_BIND_NOW = "off";
	} else {
		unsigned short s = 8 + (rand() % 1024);
		unsigned short ndx = 0;

		env_LD_BIND_NOW = malloc(s);

		while(ndx < s)
			*(env_LD_BIND_NOW + ndx++) = 'A' + (rand() % ('Z' - 'A')); // Range of printable chars 'A'-'Z'
	}

	printf("%s", env_LD_BIND_NOW);

	return 0;
}
