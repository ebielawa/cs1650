DBG	= gdb				# debugger
DBG_CMD1= "unset environment"		# debugger commands (initialization)
DBG_CMD2= "set exec-wrapper env 'LD_AUDIT=./magic.so'"
RUNAS	= setarch i686 -3 -R		# x86, 3GB address space, no ASLR
ENV	= env -i LD_AUDIT=./magic.so	# empty environment, LD_AUDIT
CFLAGS	+= -m32 -ggdb3			# x86 (32-bit) code, debug information
TEXT_ADDR= $(shell ./trnd)		# .text starting address
					# x86 (32-bit) code, no {PIC, PIE},
					# (non-)executable stack, no RELRO,
					# relocated .text
CFLAGS_INIT2= -m32 -no-pie -fno-pic -z execstack -z norelro -Wl,-Ttext=$(TEXT_ADDR) hlp.o
CFLAGS_INIT3= -m32 -no-pie -fno-pic -z norelro -Wl,-Ttext=$(TEXT_ADDR)

# phony targets
.PHONY: all reset clean
.PHONY: vcat2_run vcat2_dbg vcat2_exp vcat3_run vcat3_dbg vcat3_exp

# build everything (default target)
all: vcat2 vcat3 exp2 exp3

# run `vcat2'
vcat2_run: vcat2
	$(RUNAS) $(ENV) ./$<
# debug `vcat2'
vcat2_dbg: vcat2 exp2
	$(RUNAS) $(DBG) -iex=$(DBG_CMD1) -iex=$(DBG_CMD2) ./$<
# exploit `vcat2'
vcat2_exp: vcat2 exp2 reset
	./exp2 | $(RUNAS) $(ENV) ./$<
# run `vcat3'
vcat3_run: vcat3
	$(RUNAS) $(ENV) ./$<
# debug `vcat3'
vcat3_dbg: vcat3 exp3
	$(RUNAS) $(DBG) -iex=$(DBG_CMD1) -iex=$(DBG_CMD2) ./$<
# exploit `vcat3'
vcat3_exp: vcat3 exp3 reset
	./exp3 | $(RUNAS) $(ENV) ./$<

# build the apps
vcat2: vcat2.o
	$(CC) $(CFLAGS_INIT2) $< -o $@
vcat3: vcat3.o
	$(CC) $(CFLAGS_INIT3) $< -o $@

# build the exploits
exp2: exp2.c
	$(CC) $(CFLAGS) $< -o $@
exp3: exp3.c
	$(CC) $(CFLAGS) $< -o $@

# reset
reset:
	@echo "CSCI 1650 rulez!" > magic.txt

# clean
clean:
	$(RM) exp2 exp3 vcat2 vcat3
