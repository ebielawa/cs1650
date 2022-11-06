DBG	= gdb				# debugger
DBG_CMD	= "unset environment"		# debugger commands (initialization)
RUNAS	= setarch i686 -3		# x86, 3GB address space
ENV	= env -i			# empty environment
CFLAGS	+= -m32 -ggdb3			# x86 (32-bit) code, debug information
MKFIFO	= mkfifo			# mkfifo(1)
FIFO	= fifo				# FIFO (named pipe)
TEXT_ADDR = $(shell ./trnd)		# .text starting address
                                        # x86 (32-bit) code, (no) {PIC, PIE},
                                        # (non-)executable stack, no RELRO,
                                        # relocated .text
CFLAGS_INIT4 = -m32 -no-pie -fno-pic -z norelro -Wl,-Ttext=$(TEXT_ADDR)

# phony targets
.PHONY: all clean $(FIFO)
.PHONY: vcat4_run vcat4_dbg vcat4_exp vcat5_run vcat5_dbg vcat5_exp

# build everything (default target)
all: vcat4 exp4 exp5

# run `vcat4'
vcat4_run: vcat4
	$(RUNAS) $(ENV) ./$<
# debug `vcat4'
vcat4_dbg: vcat4 exp4
	$(RUNAS) $(DBG) -iex=$(DBG_CMD) ./$<
# exploit `vcat4'
vcat4_exp: vcat4 exp4
	./exp4 | $(RUNAS) $(ENV) ./$<
# run `vcat5'
vcat5_run: vcat5
	$(RUNAS) $(ENV) ./$<
# debug `vcat5'
vcat5_dbg: vcat5 exp5
	$(RUNAS) $(DBG) -iex=$(DBG_CMD) ./$<
# exploit `vcat5'
vcat5_exp: vcat5 exp5 $(FIFO)
	(trap '' PIPE; ./exp5 < $(FIFO) | $(RUNAS) $(ENV) ./$< > $(FIFO))

# build the apps
vcat4: vcat4.o
	$(CC) $(CFLAGS_INIT4) $< -o $@

# build the exploits
exp4: exp4.c
	$(CC) $(CFLAGS) $< -o $@
exp5: exp5.c
	$(CC) $(CFLAGS) $< -o $@

# create the FIFO
$(FIFO):
	@if [ ! -p $@ ]; then $(MKFIFO) $@; fi;

# clean
clean:
	$(RM) exp4 exp5 vcat4 $(FIFO)
