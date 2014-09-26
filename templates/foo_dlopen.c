#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

	dlclose(libfooptr);
	/* DLOPEN & DLSYM */

	fprintf(stdout, "\n");

	return 0;
}
