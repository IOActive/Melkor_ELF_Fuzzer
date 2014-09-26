#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void help(void);

int main()
{
	char *whoami = (char *) malloc(0xdead);

	strcpy(whoami, "I'm an ELF :-)");

	printf("%s", whoami);
	puts("...\n");

	help();

	fprintf(stdout, "\n");

	return 0;
}
