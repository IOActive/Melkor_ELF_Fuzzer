/*
 * Melkor - An ELF File Format Fuzzer
 * Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
 *
 * Mexico
 */

#include "melkor.h"
#include "numbers.h"

#include <unistd.h>
#include <fcntl.h>

unsigned int getseed(void)
{
	int fd;
	unsigned int seed;

	if((fd = open("/dev/urandom", O_RDONLY)) == -1){
		perror("getseed(): open");
		exit(EXIT_FAILURE);
	}

	read(fd, &seed, sizeof(seed));

	close(fd);

	return seed;
}

Elf_Addr getElf_Addr(void)
{
	Elf_Addr a;

	if(rand() % 2)
		// A key base address + 16 bits random offset
		a = (Elf_Addr) (key_Addr[rand() % (sizeof(key_Addr) / sizeof(Elf_Addr))] + (rand() & 0xffff));
	else {
		if(rand() % 2){
			int r = rand();

			if(r % 3 == 0)
				a = (Elf_Addr) int_l33t[rand() % (sizeof(int_l33t) / sizeof(int))];
			else if(r % 3 == 1)
				a = (Elf_Addr) int_b0f[rand() % (sizeof(int_b0f) / sizeof(int))];
			else
				a = (Elf_Addr) common_b0f[rand() % (sizeof(common_b0f) / sizeof(int))];
		} else
			a = (Elf_Addr) rand();
	}

	return a;
}

Elf_Off getElf_Off(void)
{
	Elf_Off o;
	int r = rand();

	if(r % 5 == 0) // 20% chance
		o = (Elf_Off) (key_Addr[rand() % (sizeof(key_Addr) / sizeof(Elf_Addr))] + (rand() % 0xffff));
	else if(r % 5 == 1)
		o = (Elf_Off) int_l33t[rand() % (sizeof(int_l33t) / sizeof(int))];
	else if(r % 5 == 2)
		o = (Elf_Off) int_b0f[rand() % (sizeof(int_b0f) / sizeof(int))];
	else if(r % 5 == 3)
		o = (Elf_Off) common_b0f[rand() % (sizeof(common_b0f) / sizeof(int))];
	else
		o = (Elf_Off) rand();

	return o;
}

Elf_Word getElf_Word(void)
{
	Elf_Word w;
	int r = rand();

	if(r % 3 == 0) // 33.33% chance
		w = (Elf_Word) int_l33t[rand() % (sizeof(int_l33t) / sizeof(int))];
	else if(r % 3 == 1){
		if(rand() % 2)
			w = (Elf_Word) int_b0f[rand() % (sizeof(int_b0f) / sizeof(int))];
		else
			w = (Elf_Word) common_b0f[rand() % (sizeof(common_b0f) / sizeof(int))];
	} else
		w = (Elf_Word) rand();

	return w;
}

Elf_Xword getElf_Xword(void)
{
	Elf_Xword xw;

	xw = getElf_Word();
	xw = xw << 32 | getElf_Word();

	return xw;
}

Elf_Half getElf_Half(void)
{
	Elf_Half h;
	int r = rand();

	if(r % 5 == 0) // 20% chance
		h = (Elf_Half) short_l33t[rand() % (sizeof(short_l33t) / sizeof(int))];
	else if(r % 5 == 1)
		h = (Elf_Half) (int_b0f[rand() % 3] >> 16); // 0x7fff || 0xffff || 0x8000
	else if(r % 5 == 2)
		h = (Elf_Half) (int_b0f[(rand() % (sizeof(int_b0f) / sizeof(int))) + 3] >> 16);
	else if(r % 5 == 3)
		h = (Elf_Half) common_b0f[rand() % (sizeof(common_b0f) / sizeof(int))] >> 16;
	else
		h = (Elf_Half) rand();

	return h;
}

Elf_Section getElf_Section(void)
{
	Elf_Section s;

	if(rand() % 2) // 50% chance to return a small (valid?) value
		s = (Elf_Section) rand() % 0x20;
	else
		s = (Elf_Section) getElf_Half();

	return s;
}

char *get_fmt_str(void)
{
	char *fmt_ptr;

	fmt_ptr = (char *) fmt_strs[rand() % (sizeof(fmt_strs) / sizeof(char *))];

	return fmt_ptr;
}

char *get_fuzzed_path(void)
{
	char *fuzzed_path;

	fuzzed_path = (char *) fuzz_paths[rand() % (sizeof(fuzz_paths) / sizeof(char *))];

	return fuzzed_path;
}
