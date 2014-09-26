#define _GNU_SOURCE
#include <link.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;

	printf("name = %s (%d segments [phnum])\n", info->dlpi_name, info->dlpi_phnum);

	for (j = 0; j < info->dlpi_phnum; j++)
		printf("\tSegment %2d: address = %10p\n", j, (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));

	return 0;
}

int main(int argc, char **argv)
{
	if(argc != 2){
		fprintf(stderr, "Usage: %s <libfoo.so>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *whoami = (char *) malloc(0xdead);

	strcpy(whoami, "I'm an ELF :-)");

	printf("%s", whoami);
	puts("...\n");

	/* DLOPEN & DLSYM */
	void (*helpsym)();
	void * libfooptr;

	libfooptr = dlopen(argv[1], RTLD_LAZY);

	if(!libfooptr){
		fprintf(stderr, "dlopen(): %s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	dlerror(); /* Clear any existing error */

	helpsym = dlsym(libfooptr, "help");

	if(!helpsym){
		fprintf(stderr, "dlsym(): %s\n", dlerror());
		exit(EXIT_FAILURE);
	} else
		(*helpsym)();

	dl_iterate_phdr(callback, NULL); // Walk through the loaded libraries

	dlclose(libfooptr);
	/* DLOPEN & DLSYM */

	fprintf(stdout, "\n");

	return 0;
}
