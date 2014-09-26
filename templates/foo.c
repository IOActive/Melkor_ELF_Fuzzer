#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

extern void help(void);

int main()
{
	char *whoami = (char *) malloc(0xdead);

	strcpy(whoami, "I'm an ELF :-)");

	printf("%s", whoami);
	puts("...\n");

	srand(time(NULL));

	if(rand() % 2){
		printf("And I'm happy. I live free ! :-)\n");

		exit(EXIT_SUCCESS);
	} else
		help();

	fprintf(stdout, "\n");

	return 0;
}
