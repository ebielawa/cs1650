DBG	= gdb				# debugger
DBG_CMD	= "unset environment"		# debugger commands (initialization)
RUNAS	= setarch i686 -3		# x86, 3GB address space
ENV	= env -i			# empty environment
CFLAGS	+= -m32 -ggdb3			# x86 (32-bit) code, debug information
MKFIFO	= mkfifo			# mkfifo(1)
FIFO	= fifo				# FIFO (named pipe)

# phony targets
.PHONY: all clean $(FIFO)
.PHONY: vcat6_run vcat6_dbg vcat6_exp

# build everything (default target)
all: exp6

# run `vcat6'
vcat6_run: vcat6
	$(RUNAS) $(ENV) ./$<
# debug `vcat6'
vcat6_dbg: vcat6 exp6
	$(RUNAS) $(DBG) -iex=$(DBG_CMD) ./$<
# exploit `vcat6'
vcat6_exp: vcat6 exp6 $(FIFO)
	(trap '' PIPE; ./exp6 < $(FIFO) | $(RUNAS) $(ENV) ./$< > $(FIFO))

# build the exploit
exp6: exp6.c
	$(CC) $(CFLAGS) $< -o $@

# create the FIFO 
$(FIFO):
	@if [ ! -p $@ ]; then $(MKFIFO) $@; fi;

# clean
clean:
	$(RM) exp6 $(FIFO)
