DBG	= gdb				# debugger
DBG_CMD1= "unset environment"		# debugger commands (initialization)
DBG_CMD2= "set exec-wrapper env 'LD_AUDIT=./magic.so'"
RUNAS	= setarch i686 -3 -R		# x86, 3GB address space, no ASLR
ENV	= env -i LD_AUDIT=./magic.so	# empty environment, LD_AUDIT
CFLAGS	+= -m32 -ggdb3			# x86 (32-bit) code, debug information
TEXT_ADDR= $(shell ./trnd)		# .text starting address
					# x86 (32-bit) code, no {PIC, PIE},
					# executable stack, no RELRO,
					# relocated .text
CFLAGS_INIT0= -m32 -no-pie -fno-pic -z norelro -Wl,-Ttext=$(TEXT_ADDR)
CFLAGS_INIT1= $(CFLAGS_INIT0) -z execstack hlp.o

# phony targets
.PHONY: all clean vcat0_run vcat0_dbg vcat0_exp vcat1_run vcat1_dbg vcat1_exp

# build everything (default target)
all: vcat0 vcat1 exp0 exp1

# run `vcat0'
vcat0_run: vcat0
	$(RUNAS) $(ENV) ./$<
# debug `vcat0'
vcat0_dbg: vcat0 exp0
	$(RUNAS) $(DBG) -iex=$(DBG_CMD1) -iex=$(DBG_CMD2) ./$<
# exploit `vcat0'
vcat0_exp: vcat0 exp0
	./exp0 | $(RUNAS) $(ENV) ./$<
# run `vcat1'
vcat1_run: vcat1
	$(RUNAS) $(ENV) ./$<
# debug `vcat1'
vcat1_dbg: vcat1 exp1
	$(RUNAS) $(DBG) -iex=$(DBG_CMD1) -iex=$(DBG_CMD2) ./$<
# exploit `vcat1'
vcat1_exp: vcat1 exp1
	./exp1 | $(RUNAS) $(ENV) ./$<

# build the apps
vcat0: vcat0.o
	$(CC) $(CFLAGS_INIT0) $< -o $@
vcat1: vcat1.o
	$(CC) $(CFLAGS_INIT1) $< -o $@

# build the exploits
exp0: exp0.c
	$(CC) $(CFLAGS) $< -o $@
exp1: exp1.c
	$(CC) $(CFLAGS) $< -o $@

# clean
clean:
	$(RM) exp0 exp1 vcat0 vcat1
