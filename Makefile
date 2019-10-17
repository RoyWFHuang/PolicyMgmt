ifeq ($(UTIL_LIB_NAME),)
	UTIL_LIB_NAME = libmethod.a
endif

LIB_METHOD = src/lib_method.c
UTIL_LIB_FILE = $(LIB_METHOD)


INCLUDE_DIR = \
-I./inc \
-I./h

all:
	$(CC) -c $(UTIL_LIB_FILE) $(CFLAG) $(INCLUDE_DIR)
	ar -r $(UTIL_LIB_NAME) *.o
	rm -rf *.o

debug:
	$(CC) -c $(UTIL_LIB_FILE) $(CFLAG) $(INCLUDE_DIR) $(DEBUG_FLAG)
	ar -r $(UTIL_LIB_NAME) *.o
	rm -rf *.o

clean:
	rm -rf *.o $(UTIL_LIB_NAME)

distclean: clean

