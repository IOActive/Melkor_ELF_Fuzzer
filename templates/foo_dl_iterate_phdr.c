#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void help(void);

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;

	printf("name = %s (%d segments [phnum])\n", info->dlpi_name, info->dlpi_phnum);

	for (j = 0; j < info->dlpi_phnum; j++)
		printf("\tSegment %2d: address = %10p\n", j, (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));

	return 0;
}

int main()
{
	char *whoami = (char *) malloc(0xdead);

	strcpy(whoami, "I'm an ELF :-)");

	printf("%s", whoami);
	puts("...\n");

	help();

	fprintf(stdout, "\n");

	dl_iterate_phdr(callback, NULL); // Walk through the loaded libraries

	return 0;
}
