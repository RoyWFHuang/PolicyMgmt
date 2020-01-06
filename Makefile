ifneq ("$(wildcard ./config.mk)", "")
include config.mk
endif

ifeq ($(CFLAG),)
  SRC_ROOT = $(pwd)/src
  UTIL_MODULE = UtilLib
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
-I./$(UTIL_MODULE)/inc

all: utillib
	$(CC) -c $(POLICMGMT_LIB_FILE) $(CFLAG) $(INCLUDE_DIR)
	ar -r $(POLICYMGMT_LIB_NAME) *.o
	mv $(POLICYMGMT_LIB_NAME) ./lib/
	rm -rf *.o

clean:
	rm -rf *.o ./lib/$(POLICYMGMT_LIB_NAME)
	make -C $(UTIL_MODULE) clean

distclean: clean
	rm -rf plmtest
	rm -rf $(UTIL_MODULE)

test: utillib
	$(CC) -c $(POLICMGMT_LIB_FILE) plmtest.c $(CFLAG) \
$(INCLUDE_DIR) $(DEBUG_FLAG) -DCONSOLE_DEBUG -DMD_DIR_PATH=\".\"
	$(CC) -g *.o -lmethod -L../$(UTIL_MODULE)/lib/ -lcrypto -o plmtest
	rm -rf *.o

utillib:
	@git submodule init ; \
	git submodule update
	make -C $(UTIL_MODULE)