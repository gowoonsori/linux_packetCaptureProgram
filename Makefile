CC = gcc
CFLAGS = 
CLIBS = 
CMDS = captureProgram

all : $(CMDS)

captureProgram : captureProgram.c
	$(CC) $(CFLAGS) $^ -o $@ $(CLIBS) -lpthread -W

clean :
	rm $(CMDS) core