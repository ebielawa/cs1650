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

# Test exploits
# exploit `vcat6' with `flag1'
vcat6_exp1: vcat6 exp6-flag1 $(FIFO)
	(trap '' PIPE; ./exp6-flag1 < $(FIFO) | $(RUNAS) $(ENV) ./$< > $(FIFO))

# exploit `vcat6' with `flag2'
vcat6_exp2: vcat6 exp6-flag2 $(FIFO)
	(trap '' PIPE; ./exp6-flag2 < $(FIFO) | $(RUNAS) $(ENV) ./$< > $(FIFO))

# exploit `vcat6' with `flag3'
vcat6_exp3: vcat6 exp6-flag3 $(FIFO)
	(trap '' PIPE; ./exp6-flag3 < $(FIFO) | $(RUNAS) $(ENV) ./$< > $(FIFO))

# exploit `vcat6' with `flag4'
vcat6_exp4: vcat6 exp6-flag4 $(FIFO)
	(trap '' PIPE; ./exp6-flag4 < $(FIFO) | $(RUNAS) $(ENV) ./$< > $(FIFO))

# Test exploit building
# build the (test) exploit(s)
exp6-flag1: exp6-flag1.c
	$(CC) $(CFLAGS) $< -o $@

exp6-flag2: exp6-flag2.c
	$(CC) $(CFLAGS) $< -o $@

exp6-flag3: exp6-flag3.c
	$(CC) $(CFLAGS) $< -o $@

exp6-flag4: exp6-flag4.c
	$(CC) $(CFLAGS) $< -o $@

# build the exploit
exp6: exp6.c
	$(CC) $(CFLAGS) $< -o $@

# create the FIFO 
$(FIFO):
	@if [ ! -p $@ ]; then $(MKFIFO) $@; fi;

# clean
clean:
	$(RM) exp6 $(FIFO)
