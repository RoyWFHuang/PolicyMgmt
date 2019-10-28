ifneq ("$(wildcard ./config.mk)", "")
include config.mk
endif

ifeq ($(CFLAG),)
  SRC_ROOT = $(pwd)/src
endif

ifeq ($(POLICYMGMT_LIB_NAME),)
	POLICYMGMT_LIB_NAME = libconfigmethod.a
endif

ifeq ($(ERROR_MSG_MODE), yes)
	CFLAG = -DERROR_MSG_MODE
endif

ifeq ($(DEBUG_MODE), yes)
    CFLAG += -DDEBUG_MODE
    ifeq ($(PLM_DEBUG_MODE), yes)
        CFLAG += -DPLM_DEBUG_MODE
    endif
endif

ifeq ($(SYSLOG), yes)
CFLAG += -DSYSLOG
endif

POLICMGMT_FILE = src/policy_mgmt.c

POLICMGMT_LIB_FILE = $(POLICMGMT_FILE)

INCLUDE_DIR = \
-I./inc/ \
-I./h/ \
-I../UtilLib/inc

all:
	$(CC) -c $(POLICMGMT_LIB_FILE) $(CFLAG) $(INCLUDE_DIR)
	ar -r $(POLICYMGMT_LIB_NAME) *.o
	mv $(POLICYMGMT_LIB_NAME) ./lib/
	rm -rf *.o

clean:
	rm -rf *.o ./lib/$(POLICYMGMT_LIB_NAME)

distclean: clean
	rm -rf plmtest

test:
	$(CC) -c $(POLICMGMT_LIB_FILE) plmtest.c $(CFLAG) \
$(INCLUDE_DIR) $(DEBUG_FLAG) -DCONSOLE_DEBUG -DMD_DIR_PATH=\".\"
	$(CC) -g *.o -lmethod -L../UtilLib/lib/ -lcrypto -o plmtest
	rm -rf *.o
