#
# Melkor - An ELF File Format Fuzzer
# Copyright (C) 2014 Alejandro Hernandez H. (nitr0us)
#
# Mexico
#

CC = gcc
CFLAGS = -ggdb -Wall -DDEBUG
INSTALLPATH = /usr/local/bin/
SRC = src
TEMPL_SRC = templates
OUTPUT = melkor
TEMPLFOO = $(TEMPL_SRC)/foo.c
TEMPLFOOLIBFOO = $(TEMPL_SRC)/foo_libfoo.c
TEMPLFOODL1 = $(TEMPL_SRC)/foo_dlopen.c
TEMPLFOODL2 = $(TEMPL_SRC)/foo_dl_iterate_phdr.c
TEMPLLIBFOO = $(TEMPL_SRC)/libfoo.c
MODULES = $(SRC)/melkor.o $(SRC)/logger.o \
		$(SRC)/fuzz_hdr.o $(SRC)/fuzz_sht.o \
		$(SRC)/fuzz_pht.o $(SRC)/fuzz_sym.o \
		$(SRC)/fuzz_dyn.o $(SRC)/fuzz_rel.o \
		$(SRC)/fuzz_note.o $(SRC)/fuzz_strs.o \
		$(SRC)/generators.o

all: clean templ envtools melkor

melkor: $(MODULES)
	$(CC) $(CFLAGS) $(MODULES) -o $(OUTPUT)

templ:
	$(CC) $(CFLAGS) $(TEMPLFOO) -c -o $(TEMPL_SRC)/foo.o
	$(CC) $(CFLAGS) $(TEMPLFOO) $(TEMPLLIBFOO) -o $(TEMPL_SRC)/foo
	$(CC) $(CFLAGS) $(TEMPLFOO) $(TEMPLLIBFOO) -Wl,-z,relro,-z,now -o $(TEMPL_SRC)/foo_full_relro
	$(CC) $(CFLAGS) $(TEMPLFOO) $(TEMPLLIBFOO) -fstack-protector -z execstack -o $(TEMPL_SRC)/foo_stackprotector_execstack
	$(CC) $(CFLAGS) $(TEMPLFOO) $(TEMPLLIBFOO) -static -o $(TEMPL_SRC)/foo_static
	$(CC) $(CFLAGS) $(TEMPLLIBFOO) -c -fPIC -o $(TEMPL_SRC)/libfoo.o
	$(CC) $(CFLAGS) $(TEMPL_SRC)/libfoo.o -shared -o $(TEMPL_SRC)/libfoo.so
	$(CC) $(CFLAGS) $(TEMPLFOOLIBFOO) -L $(TEMPL_SRC) -lfoo -o $(TEMPL_SRC)/foo_libfoo
	$(CC) $(CFLAGS) $(TEMPLFOODL1) -ldl -o $(TEMPL_SRC)/foo_dlopen
	$(CC) $(CFLAGS) $(TEMPLFOODL2) -L $(TEMPL_SRC) -lfoo -o $(TEMPL_SRC)/foo_dl_iterate_phdr

envtools:
	$(CC) $(CFLAGS) $(SRC)/print_envp_vars.c -o $(SRC)/print_envp_vars
	$(CC) $(CFLAGS) $(SRC)/env1.c $(SRC)/generators.c -o $(SRC)/env1
	$(CC) $(CFLAGS) $(SRC)/env2.c $(SRC)/generators.c -o $(SRC)/env2
	$(CC) $(CFLAGS) $(SRC)/env3.c $(SRC)/generators.c -o $(SRC)/env3

install:
	install $(OUTPUT) $(INSTALLPATH)
clean:
	find  $(SRC) -type f -executable -exec rm {} \;
	find  $(TEMPL_SRC) -type f -executable -exec rm {} \;
	rm -f $(TEMPL_SRC)/*.o
	rm -f $(TEMPL_SRC)/*.so
	rm -f $(SRC)/*.o
	rm -fr orcs_*
	rm -f $(OUTPUT)
