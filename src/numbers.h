int int_l33t[] = {
	0xB16B00B5, // (  *  ) (  *  )
	0x0DEFACED,
	0XDEADFACE,
	0xCAFED00D,
	0xFEE1DEAD,
	0x0D15EA5E,
	0xDEADC0DE,
	0xBAD0C0DE,
	0xDEFECA7E,
	0xDEFEC8ED,
	0x600DCAFE,
	0x00031337,
};

short short_l33t[] = {
	0xDEAD,	0xBABE,
	0xCAFE,	0xF00D,
	0xBEEF,	0xC0DE,
	0xFACE, 0x0BAD,
	0x1337, 0xD00D,
	0x0FA6, 0xB00B,
};

Elf_Addr key_Addr[] = {
	0x00000000, // Zero page
	0x00400000,
	0x08048000,
	0x40000000, // 1GB
	0x80000000, // 2GB
	0x81000000,
	0xc0000000, // 3GB
	0xc1000000,
	0xd0000000,
};

// Could be used as short by shifting 16 bits (E.g. int_b0f[0] >> 16 == 0x7fff)
int int_b0f[] = {
	0x7fffffff, // INT_MAX
	0xffffffff, // UINT_MAX (-1 for signed vars)
	0x80000000, // Negative value for signed vars (MSB = 1)
	0xc0000000,
	0xff00ff00,
	0xffff0000,
};

int common_b0f[] = {
	0x41424344, // INC EAX; INC EBX; INC ECX; INC EDX
	0x41414141, // INC EAX * 4
	0x42424242, // INC EBX * 4
	0x43434343, // INC ECX * 4
	0x44444444, // INC EDX * 4
	0x90909090, // NOP
	0xcccccccc, // INT 3
};

const char *fuzz_paths[] = {
        "orcs_libfoo.so/",
        "././../.././...",
        "/;;/;//..",
        "\\//\\//",
        "~/~~~//",
        "*/!/*",
        "$xX",
        ":::",
        "/#)",
        "$$",
        "//",
        "\\",
        "~",
        "*",
	"/",
};

const char *fmt_strs[] = {
	" %x ",
	" %n ",
	" %p ",
};
