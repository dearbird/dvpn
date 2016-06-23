########

CC=g++
#CC=arm-linux-gnueabihf-gcc

DEBUG?=-g3
OPTIMIZATION?=-O2
WARN?=-Wall -Wshadow -Wpointer-arith -Wmissing-declarations 

APP=dvpn


OBJS =   		\
	fastlz.o 	\
	tap.o   	\
	dvpn.o    	\
	

%.o : %.c
	$(CC) -c $(CFLAGS) -fno-strict-aliasing $(INC) $< -o $@

$(APP) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lrt

debug: CFLAGS=$(WARN) $(DEBUG)
debug: clean $(OBJS) $(APP) 

release: CFLAGS=$(WARN) $(OPTIMIZATION)
release: clean $(OBJS) $(APP)

clean:
	rm -rf *.o $(APP)

