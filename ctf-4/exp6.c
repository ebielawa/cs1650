/*
 * CTF-4 `vcat6' exploit (template)
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

#define	BUF_SZ			sizeof("0x00000000")
#define	FMT_STR			"%1$p%1$p"
#define	BIN_BASE_OFF		0x0
#define	LIBC_BASE_OFF		0x0

unsigned char payload[] =
	/* ------------------------------------	*/
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	"\xef\xbe\xad\xde";
	/* ------------------------------------	*/


int
main(int argc, char **argv)
{
	/* scratch space			*/
	char		buf[BUF_SZ];

	/* base address of `vcat6'		*/
	unsigned long	baddr;

	/* base address of 'libc-2.31.so'	*/
	unsigned long	laddr;

	/* helper				*/
	struct stat	istat;

	/* cleanup				*/
	memset(buf, 0, BUF_SZ);

	/* leak the base address of `vcat6'	*/
	write(STDOUT_FILENO, FMT_STR, strlen(FMT_STR));
	read(STDIN_FILENO, buf, BUF_SZ-1);
	baddr = strtoul(buf, NULL, 16) - BIN_BASE_OFF;

	/* leak the base address of 'libc-2.31.so'	*/
	read(STDIN_FILENO, buf, BUF_SZ-1);
	laddr = strtoul(buf, NULL, 16) - LIBC_BASE_OFF;

	/* sanity check 			*/
	if (!fstat(STDIN_FILENO, &istat) && !S_ISFIFO(istat.st_mode)) {
		if (!baddr || !laddr) {
			fprintf(stderr,
				"[-] baddr = 0x%08lx, laddr = 0x%08lx\n", baddr, laddr);
			fprintf(stderr,
				"[!] If you are debugging your exploit under GDB "
				"you need to type in the leaked addresses\n");
		}
	}

	/*
	 * dump the payload in 'stdout'
	 * sizeof(payload)-1:	ignore the trailing '\0';
	 *			(strings are NULL terminated)
	 */
	write(STDOUT_FILENO, payload, sizeof(payload)-1);

	/* done; success			*/
	return EXIT_SUCCESS;
}
