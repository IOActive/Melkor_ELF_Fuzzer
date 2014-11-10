/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Mexico
 */

#include "melkor.h"
#include "banner.h"

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* GLOBAL VARS */
FILE		*logfp;
struct stat	elfstatinfo;
unsigned int	mode = 0;   // Metadata to fuzz (parameters)
unsigned int	orcn = 0;   // OrcN inside the for() loop. fuzz_* modules will use it through different loops
unsigned int	n = 5000;   // Default for option -n
unsigned int	quiet = 0;  // For quiet mode (-q). Default is not quiet [debug() output]
unsigned int	likelihood = 10; // Likelihood given in % of the execution of each rule in the main for() loop in fuzz_*.c. Default 10%
unsigned int	like_a = 10, like_b = 1; // Based upon the likelihood, these will be used for: rand() % like_a < like_b. Default values for 10%
unsigned int	secnum = 0; // Used in loops here but refered in fuzz_*.c as the section number
unsigned int	entry  = 0; // Used in loops here but refered in fuzz_*.c as the entry number inside a section (for DYN, SYM, REL)
char		*dirname_orcfname;
char		*elfptr, *orcptr;
char		*elfSTRS, *orcSTRS;
Elf_Ehdr	*elfHDR, *orcHDR;
Elf_Shdr	*elfSHT, *orcSHT;
Elf_Phdr	*elfPHT, *orcPHT;
Elf_Sym		*elfSYM, *orcSYM;
Elf_Dyn		*elfDYN, *orcDYN;
Elf_Rel		*elfREL, *orcREL;
Elf_Rela	*elfRELA, *orcRELA;
Elf_Nhdr	*elfNOTE, *orcNOTE;
Elf_Off		elfshstrtab_offset = 0, orcshstrtab_offset = 0, linkstrtab_offset = 0;
Elf_Shdr	*orcOrigSHT;
Elf_Phdr	*orcOrigPHT;
Elf_Dyn		*elfOrigDYN;

extern int errno;

int main(int argc, char **argv)
{
	int		opt, elffd, orcfd, fuzzed_flag = 0, k = 0;
	char		*elfname;
	Elf_Shdr	elfshstrtab_section, orcshstrtab_section, linkstrtab_section;

	if(argc < 3)
		usage(argv[0]);

	while((opt = getopt(argc, argv, "aHSPsDRNZABqn:l:")) != EOF)
		switch(opt){
			case 'a':
				mode |= AUTO;
				break;
			case 'H':
				mode |= HDR;
				break;
			case 'S':
				mode |= SHT;
				break;
			case 'P':
				mode |= PHT;
				break;
			case 's':
				mode |= SYM;
				break;
			case 'D':
				mode |= DYN;
				break;
			case 'R':
				mode |= REL;
				break;
			case 'N':
				mode |= NOTE;
				break;
			case 'Z':
				mode |= STRS;
				break;
			case 'A':
				mode |= ALL;
				break;
			case 'B':
				mode |= ALLB;
				break;
			case 'n':
				n = atoi(optarg);
				break;
			case 'l':
				likelihood = atoi(optarg);
				if(likelihood < 1 || likelihood > 100){
					fprintf(stderr, "[!] Likelihood (-l) is given in %% and must be between 1 and 100\n");
					exit(EXIT_FAILURE);
				}

				/*
				rand() % 20 < 1 =   5%
				rand() % 10 < 1 =  10%
				rand() % 5 < 1  =  20%
				rand() % 4 < 1  =  25%
				rand() % 3 < 1  =  33.33%
				rand() % 5 < 2  =  40%
				rand() % 2 < 1  =  50%
				rand() % 5 < 3  =  60%
				rand() % 3 < 2  =  66.66%
				rand() % 4 < 3  =  75%
				rand() % 5 < 4  =  80%
				rand() % 10 < 9 =  90%
				rand() % 1 < 1  =  100%
				*/
				if(likelihood <= 5){
					like_a = 20;
					like_b =  1;
				} else if(likelihood <= 10){
					like_a = 10;
					like_b =  1;
				} else if(likelihood <= 20){
					like_a = 5;
					like_b = 1;
				} else if(likelihood <= 25){
					like_a = 4;
					like_b = 1;
				} else if(likelihood <= 34){
					like_a = 3;
					like_b = 1;
				} else if(likelihood <= 40){
					like_a = 5;
					like_b = 2;
				} else if(likelihood <= 50){
					like_a = 2;
					like_b = 1;
				} else if(likelihood <= 60){
					like_a = 5;
					like_b = 3;
				} else if(likelihood <= 67){
					like_a = 3;
					like_b = 2;
				} else if(likelihood <= 75){
					like_a = 4;
					like_b = 3;
				} else if(likelihood <= 80){
					like_a = 5;
					like_b = 4;
				} else if(likelihood <= 90){
					like_a = 10;
					like_b =  9;
				} else if(likelihood <= 100){
					like_a = 1;
					like_b = 1;
				}
				break;
			case 'q':
				quiet = 1;
				break;
			default:
				exit(EXIT_FAILURE);
		}

	if(argv[optind] == NULL){
		fprintf(stderr, "[!] <ELF file template> not supplied !\n");
		exit(EXIT_FAILURE);
	}

	/* Separate the filename from the dirname. The same as basename() */
	elfname  = strrchr(argv[optind], '/');
	if(!elfname)
		elfname = argv[optind];
	else
		elfname = strrchr(argv[optind], '/') + 1;

	if((elffd = open(argv[optind], O_RDONLY)) == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	if(!elf_identification(elffd)){
		fprintf(stderr, "[!] '%s' is not an ELF file. Invalid magic number !\n", elfname);
		close(elffd);
		exit(EXIT_FAILURE);
	}

	if(fstat(elffd, &elfstatinfo) == -1){
		perror("stat");
		close(elffd);
		exit(EXIT_FAILURE);
	}

	if((elfptr = (char *) mmap(NULL, elfstatinfo.st_size, PROT_READ, MAP_SHARED, elffd, 0)) == MAP_FAILED){
		perror("mmap");
		close(elffd);
		exit(EXIT_FAILURE);
	}

	close(elffd);

	elfHDR = (Elf_Ehdr *) (elfptr);
	elfSHT = (Elf_Shdr *) (elfptr + elfHDR->e_shoff);
	elfPHT = (Elf_Phdr *) (elfptr + elfHDR->e_phoff);
	elfshstrtab_section = *(Elf_Shdr *) (elfSHT + elfHDR->e_shstrndx);
	elfshstrtab_offset  = elfshstrtab_section.sh_offset;

	char dirname[strlen("orcs_") + strlen(elfname) + 1];
	char orcfname[strlen("orc_") + 16];
	char logfname[strlen("Report_") + strlen(elfname) + 5];
	char *ext = "";
	if(strcmp(elfname + strlen(elfname) - 2, ".o") == 0)
		ext = ".o";
	if(strcmp(elfname + strlen(elfname) - 3, ".so") == 0)
		ext = ".so";

	dirname_orcfname = malloc(sizeof(dirname) + sizeof(orcfname) + 2);

	snprintf(dirname, sizeof(dirname), "orcs_%s", elfname);
	snprintf(logfname, sizeof(logfname), "Report_%s.txt", elfname);

	if(mkdir(dirname, 0775) == -1)
		if(errno == EEXIST)
			printf("[!] Dir '%s' already exists. Files inside will be overwritten !\n", dirname);

	printf("%s", elf_ascii[0]);
	printf(elf_ascii[1], argv[optind]);
	printf("%s", elf_ascii[2]);
	printf(elf_ascii[3], n);
	printf("%s", elf_ascii[4]);

	if(mode & AUTO){
		printf("[+] Automatic mode\n");
		printf("[+] ELF type detected: ");

		switch(elfHDR->e_type){
			case ET_NONE:
				printf("ET_NONE");
				break;
			case ET_REL:
				printf("ET_REL");
				break;
			case ET_EXEC:
				printf("ET_EXEC");
				break;
			case ET_DYN:
				printf("ET_DYN");
				break;
			case ET_CORE:
				printf("ET_CORE");
				break;
			default:
				printf("Unknown e_type !\n");
				printf("[+] All the metadata (except) the header will be fuzzed\n\n");
		}

		if(elfHDR->e_type > 0 && elfHDR->e_type < 5){
			printf("\n[+] Selecting the metadata to fuzz\n\n");

			int metadata_by_e_type[5][8] = {
						/* HDR  SHT  PHT  SYM  DYN  REL  NOTE  STRS */
				/* ET_NONE */    {  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,   0   }, // Untouched
				/* ET_REL  */    {  0 , SHT,  0 , SYM,  0 , REL,  0 ,  STRS },
				/* ET_EXEC */    {  0 , SHT, PHT, SYM, DYN, REL, NOTE, STRS },
				/* ET_DYN  */    {  0 , SHT, PHT, SYM, DYN, REL, NOTE, STRS },
				/* ET_CORE */    {  0 ,  0 , PHT,  0 ,  0 ,  0 ,  0  ,  0   },
			};

			for(k = 0; k < 8; k++)
				mode |= metadata_by_e_type[elfHDR->e_type][k];
		} else {
			mode = ALLB; // All except the ELF header
		}
	}

	printf("[+] Detailed log for this session: '%s/%s' \n\n", dirname, logfname);

	printf("[+] The Likelihood of execution of each rule is: ");
	printf("Aprox. %d %% (rand() %% %d < %d)\n\n", likelihood, like_a, like_b);

	if ( !quiet )
	{
		printf("[+] Press any key to start the fuzzing process...\n");
		getchar();
	}

	chdir(dirname);

	logfp = start_logger(logfname, elfname);

	srand(getseed());
	PAGESIZE = getpagesize();

	for(orcn = 1; orcn <= n; orcn++){
		snprintf(orcfname, sizeof(orcfname), "orc_%.4d%s", orcn, ext);
		snprintf(dirname_orcfname, sizeof(dirname) + sizeof(orcfname) + 2, "%s/%s", dirname, orcfname);

		if((orcfd = creat(orcfname, elfstatinfo.st_mode)) == -1){
			perror("creat");
			continue;
		}

		if(write(orcfd, elfptr, elfstatinfo.st_size) == -1){
			perror("write");
			continue;
		}

		close(orcfd);

		if((orcfd = open(orcfname, O_RDWR)) == -1){
			perror("open");
			continue;
		}

		if((orcptr = (char *) mmap(NULL, elfstatinfo.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, orcfd, 0)) == MAP_FAILED){
			perror("mmap");
			close(orcfd);
			continue;
		}

		orcHDR = (Elf_Ehdr *) (orcptr);
		orcOrigSHT = (Elf_Shdr *) (orcptr + orcHDR->e_shoff);
		orcOrigPHT = (Elf_Phdr *) (orcptr + orcHDR->e_phoff);
		orcshstrtab_section = *(Elf_Shdr *) (orcOrigSHT + orcHDR->e_shstrndx);
		orcshstrtab_offset  = orcshstrtab_section.sh_offset;

		printf("\n=================================================================================\n");
		printf("[+] Malformed ELF '%s':\n", orcfname);
		fprintf(logfp, "\n=================================================================================\n\n");
		fprintf(logfp, "[+] Malformed ELF: '%s':\n\n", orcfname);

		if(mode & REL){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_REL && orcSHT->sh_type != SHT_RELA)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				if(orcSHT->sh_type == SHT_REL){
					orcREL =  (Elf_Rel *)  (orcptr + orcSHT->sh_offset);
				} else {
					orcRELA = (Elf_Rela *) (orcptr + orcSHT->sh_offset);
				}

				printf("\n[+] Fuzzing the relocations section %s with %d %s entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize),
					orcSHT->sh_type == SHT_REL ? "SHT_REL" : "SHT_RELA");
				fprintf(logfp, "\n[+] Fuzzing the relocations section %s with %d %s entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize),
					orcSHT->sh_type == SHT_REL ? "SHT_REL" : "SHT_RELA");

				for(entry = 0; entry < orcSHT->sh_size / orcSHT->sh_entsize; entry++){
					fuzz_rel();

					fuzzed_flag = 1;

					if(orcSHT->sh_type == SHT_REL)
						orcREL++;
					else
						orcRELA++;
				}
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_REL nor SHT_RELA sections found!\n");
				fprintf(logfp, "\n[!] No SHT_REL nor SHT_RELA sections found!\n");
			}
		}

		if(mode & SYM){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_SYMTAB && orcSHT->sh_type != SHT_DYNSYM)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				linkstrtab_section = *(Elf_Shdr *) (orcptr + orcHDR->e_shoff + (orcSHT->sh_link * sizeof(Elf_Shdr)));
				linkstrtab_offset  = linkstrtab_section.sh_offset;

				elfSYM = (Elf_Sym *) (elfptr + orcSHT->sh_offset);
				orcSYM = (Elf_Sym *) (orcptr + orcSHT->sh_offset);

				printf("\n[+] Fuzzing the Symbol Table %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));
				fprintf(logfp, "\n[+] Fuzzing the Symbol Table %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));

				for(entry = 0; entry < orcSHT->sh_size / orcSHT->sh_entsize; entry++, elfSYM++, orcSYM++){
					fuzz_sym();

					fuzzed_flag = 1;
				}
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_SYMTAB nor SHT_DYNSYM sections found!\n");
				fprintf(logfp, "\n[!] No SHT_SYMTAB nor SHT_DYNSYM sections found!\n");
			}
		}

		if(mode & DYN){
			verifyPHT();
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_DYNAMIC)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				linkstrtab_section = *(Elf_Shdr *) (orcptr + orcHDR->e_shoff + (orcSHT->sh_link * sizeof(Elf_Shdr)));
				linkstrtab_offset  = linkstrtab_section.sh_offset;

				elfOrigDYN = (Elf_Dyn *) (elfptr + orcSHT->sh_offset);
				elfDYN = elfOrigDYN;
				orcDYN = (Elf_Dyn *) (orcptr + orcSHT->sh_offset);

				printf("\n[+] Fuzzing the Dynamic section %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));
				fprintf(logfp, "\n[+] Fuzzing the Dynamic section %s with %d entries\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) (orcSHT->sh_size / orcSHT->sh_entsize));

				for(entry = 0; entry < orcSHT->sh_size / orcSHT->sh_entsize; entry++, elfDYN++, orcDYN++){
					fuzz_dyn();

					fuzzed_flag = 1;

					if(elfDYN->d_tag == DT_NULL)// End of _DYNAMIC[]. Trust in elfDYN, orcDYN->d_tag = NULL might have been changed
						break;
				}
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_DYNAMIC section found!\n");
				fprintf(logfp, "\n[!] No SHT_DYNAMIC section found!\n");
			}
		}

		if(mode & NOTE){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;
			entry = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_NOTE)
					continue;

				if(orcSHT->sh_size == 0)
					continue;

				printf("\n[+] Fuzzing the Note section %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);
				fprintf(logfp, "\n[+] Fuzzing the Note section %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);

				elfNOTE = (Elf_Nhdr *) (elfptr + orcSHT->sh_offset);
				orcNOTE = (Elf_Nhdr *) (orcptr + orcSHT->sh_offset);

				fuzz_note();

				fuzzed_flag = 1;
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_NOTE section found!\n");
				fprintf(logfp, "\n[!] No SHT_NOTE section found!\n");
			}
		}

		if(mode & STRS){
			verifySHT();
			orcSHT = orcOrigSHT;

			fuzzed_flag = 0;

			for(secnum = 0; secnum < orcHDR->e_shnum; secnum++, orcSHT++){
				if(orcSHT->sh_type != SHT_STRTAB)
					continue;

				// Metadata dependencies
				if(secnum == orcHDR->e_shstrndx)
					if(mode & (SHT | NOTE | DYN | SYM | REL))
						if(rand() % 3 < 2)
							continue;

				if(orcSHT->sh_size == 0)
					continue;

				printf("\n[+] Fuzzing the String Table %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);
				fprintf(logfp, "\n[+] Fuzzing the String Table %s with %d bytes\n",
					orcptr + orcshstrtab_offset + orcSHT->sh_name, (unsigned int) orcSHT->sh_size);

				orcSTRS = (char *) (orcptr + orcSHT->sh_offset);

				fuzz_strs();

				fuzzed_flag = 1;
			}

			if(!fuzzed_flag){
				printf("\n[!] No SHT_STRTAB section found!\n");
				fprintf(logfp, "\n[!] No SHT_STRTAB section found!\n");
			}
		}

		if(mode & SHT){
			verifySHT();
			orcSHT = orcOrigSHT;

			printf("\n[+] Fuzzing the Section Header Table with %d entries\n", orcHDR->e_shnum);
			fprintf(logfp, "\n[+] Fuzzing the Section Header Table with %d entries\n", orcHDR->e_shnum);

			fuzz_sht();
		}

		if(mode & PHT){
			verifyPHT();
			orcPHT = orcOrigPHT;

			printf("\n[+] Fuzzing the Program Header Table with %d entries\n", orcHDR->e_phnum);
			fprintf(logfp, "\n[+] Fuzzing the Program Header Table with %d entries\n", orcHDR->e_phnum);

			fuzz_pht();
		}

		if(mode & HDR){
			printf("\n[+] Fuzzing the Elf Header\n");
			fprintf(logfp, "\n[+] Fuzzing the Elf Header\n");

			fuzz_hdr();
		}

		// Reflect the changes in filesystem
		if(msync(orcptr, 0, MS_SYNC) == -1){
			perror("msync");
			munmap(orcptr, elfstatinfo.st_size);
			close(orcfd);
			continue;
		}

		munmap(orcptr, elfstatinfo.st_size);

		close(orcfd);

		usleep(20000);
	}

	stop_logger(logfp);

	printf("\n[+] Fuzzing process finished\n");
	printf("[+] Orcs (malformed ELFs) saved in '%s/'\n", dirname);
	printf("[+] Detailed fuzzing report: '%s/%s'\n", dirname, logfname);

	munmap(elfptr, elfstatinfo.st_size);

	free(dirname_orcfname);

	exit(EXIT_SUCCESS);
}

void usage(const char *self)
{
	banner();

	printf("Usage: %s <ELF metadata to fuzz> <ELF file template> [-n num -l likelihood -q]\n", self);
	printf("\t<ELF metadata to fuzz>:\n");
	printf("\t\t-a  Autodetect (fuzz according to e_type except -H [the header])\n");
	printf("\t\t-H  ELF header\n");
	printf("\t\t-S  Section Header Table\n");
	printf("\t\t-P  Program Header Table\n");
	printf("\t\t-D  Dynamic section\n");
	printf("\t\t-s  Symbols Table(s)\n");
	printf("\t\t-R  Relocations Table(s)\n");
	printf("\t\t-N  Notes section\n");
	printf("\t\t-Z  Strings Tables\n");
	printf("\t\t-A  All of the above (except -a [Autodetect])\n");
	printf("\t\t-B  All of the above (except -a [Autodetect] and -H [ELF Header])\n");
	printf("\t-n  Number of new fuzzed ELF files (orcs) to create (default: %d)\n", n);
	printf("\t-l  Likelihood (given in %% from 1-100) of the execution of each fuzzing rule (default: %d%%)\n", likelihood);
	printf("\t-q  Quiet mode (doesn't print to STDOUT every executed fuzzing rule)\n");

	exit(EXIT_SUCCESS);
}

void banner()
{
	srand(getseed());

	printf("%s", logo);
	printf("%s", banners[rand() % 5]);

	putchar('\n');
}

int elf_identification(int fd)
{
	Elf_Ehdr	header;

	if(read(fd, &header, sizeof(header)) == -1){
		perror("elf_identification: read");
		return 0;
	}

	return memcmp(&header.e_ident[EI_MAG0], ELFMAG, SELFMAG) == 0;
}

void verifySHT()
{
	if(elfHDR->e_shoff == 0 || elfHDR->e_shnum == 0){
		printf("[-] No Section Header Table found (necessary for fuzzing) !\n");
		printf("[-] Quitting...\n");
		munmap(elfptr, elfstatinfo.st_size);
		exit(EXIT_FAILURE);
	}
}

void verifyPHT()
{
	if(elfHDR->e_phoff == 0 || elfHDR->e_phnum == 0){
		printf("[-] No Program Header Table found (necessary for fuzzing) !\n");
		printf("[-] Quitting...\n");
		munmap(elfptr, elfstatinfo.st_size);
		exit(EXIT_FAILURE);
	}
}
