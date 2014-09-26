/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[], char *envp[])
{
	int index = 0;

	while(envp[index])
		if(strstr(envp[index], "LD_"))
			printf("$%s\n\n", envp[index++]);
		else
			index++;

	return 0;
}
