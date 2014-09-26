/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"

FILE *start_logger(char *logfname, char *elfname)
{
	FILE *fp;
	const char *log_line = " ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~\n";

	char log_title[strlen(logfname) + 100];
	snprintf(log_title, sizeof(log_title), "| Log report for fuzzed files based on %-25s                |\n", elfname);

	if(!(fp = fopen(logfname, "w"))){
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	fputs(log_line, fp);
	fputs(log_title, fp);
	fputs(log_line, fp);
	fputs("\nHow to read this report:\n\n", fp);
	fputs("(Fuzzed Metadata) | Corresponding fuzzing rule (docs/Melkor_Fuzzing_Rules.pdf)\n\n", fp);
	fputs("SHT[N] REL[E]  = Section Header N type is SHT_REL or SHT_RELA; Relocation entry E within that section was fuzzed.\n", fp);
	fputs("SHT[N] SYM[E]  = Section Header N type is SHT_SYMTAB or SHT_DYNSYM; Symbol entry E within that section was fuzzed.\n", fp);
	fputs("SHT[N] DYN[E]  = Section Header N type is SHT_DYNAMIC; Dynamic entry E within that section was fuzzed.\n", fp);
	fputs("SHT[N] NOTE[E] = Section Header N type is SHT_NOTE; Note entry E within that section was fuzzed.\n", fp);
	fputs("STRS[N] = Section Header N type is SHT_STRTAB; the String Table within that section was fuzzed.\n", fp);
	fputs("SHT[N]  = Section Header N was fuzzed.\n", fp);
	fputs("PHT[N]  = Program Header N was fuzzed.\n", fp);
	fputs("HDR     = ELF Header was fuzzed.\n", fp);

	return fp;
}

void stop_logger(FILE *fp)
{
	const char *log_footer =
		"\n\n ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~\n"
		"| End of report.                                                                |\n"
		" ~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~\n";

	fputs(log_footer, fp);

	fclose(fp);
}
