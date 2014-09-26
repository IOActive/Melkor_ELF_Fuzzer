#include <stdio.h>
#include <string.h>

void help()
{
	char msg1[] = "Please, do not take me to Melkor !\n";
	char msg2[] = "He'll corrupt me !\n";
	char msg[strlen(msg1) + strlen(msg2) + 1];

	strncpy(msg, msg1, sizeof(msg) - 1);
	strncat(msg, msg2, sizeof(msg) - 1);

	fprintf(stdout, "%s", msg);
}
