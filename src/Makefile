TARGET = proxy
TARGET_ALL = $(TARGET)
LIBS =  -lm -lsctp -std=gnu99 -lpthread
INCLUDE_DIRS = './include/' 
CC = gcc
CFLAGS = -g
CFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))

.PHONY: default all clean tests

default: $(TARGET)
all: $(TARGET_ALL)
test : $(TARGET_TEST)

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

%.o: %.c 
	$(CC) $(CFLAGS) -c $< -o $@ 

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC)  $(OBJECTS) -Wall  $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
	-rm -f ./include/*.h.gch
	

.PHONY: all clean
