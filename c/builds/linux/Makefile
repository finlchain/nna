# refer to : https://greenfishblog.tistory.com/254

###############################################################
# Makefile by finl team
###############################################################

###############################################################
# basic make command
###############################################################

# make                           : debug build   (native)
# make debug                     : debug build   (native)
# make release                   : release build (native)
# make rebuild [debug, release]  : rebuild       (native)
# make clean [debug, release]    : clean

###############################################################
# set default compile options
###############################################################
MAKE_SO = no
MAKE_A = no

CC = gcc
CXX = g++
STRIP      = strip
PLATFORM   = bin
CONFIG     = debug
ifeq ($(MAKE_SO),$(filter $(MAKE_SO), yes))
    LIBNAME    = libnode.so
    LIBCOMPILE = -fPIC
    LIBLINK    = -shared -Wl,-soname,$(LIBNAME),--version-script=ld_conf.lds
else ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
    LIBNAME    = libnode.a
    LIBCOMPILE =
    LIBLINK    =
else
    LIBNAME    = node
    LIBCOMPILE =
    LIBLINK    =
endif #
#TRUNK_DIR  = $(abspath ../..)
TRUNK_DIR  = ../..
SRC_DIR    = $(TRUNK_DIR)/src
OBJ_DIR    = $(TRUNK_DIR)/obj
OBJ_CFG_DIR= $(OBJ_DIR)/$(CONFIG)
LIB_DIR    = $(TRUNK_DIR)/lib
LIB_CFG_DIR= $(LIB_DIR)/$(CONFIG)
INC_DIR    = 
BUILD_DIR  = $(TRUNK_DIR)/builds/linux/$(PLATFORM)/$(CONFIG)
TARGET     = $(BUILD_DIR)/$(LIBNAME)
TARGET_LIB = $(LIB_CFG_DIR)/$(LIBNAME)
PRE_DEFS   =
SYSROOT    =

EXTRA_CFLAGS += -Wall -Werror -fstack-protector-all -std=c++11

###############################################################
# get makefile command line argument
###############################################################

ifneq "$(findstring clean, $(MAKECMDGOALS))" ""
    ARG.CLEAN = 1
endif
ifneq "$(findstring release, $(MAKECMDGOALS))" ""
    ARG.RELEASE = 1
endif
ifneq "$(findstring debug, $(MAKECMDGOALS))" ""
    ARG.DEBUG = 1
endif
ifneq "$(findstring rebuild, $(MAKECMDGOALS))" ""
    ARG.REBUILD = 1
endif

###############################################################
# DEBUG / RELEASE build option branch
###############################################################

ifeq ($(ARG.RELEASE),1)
    # -----------------
    # for release build
    # -----------------
    EXTRA_CFLAGS    += -DNDEBUG -O2
    CONFIG    = release
else
    # ---------------
    # for debug build
    # ---------------
    EXTRA_CFLAGS    += -g -rdynamic -DDEBUG -O0
    CONFIG    = debug
endif

###############################################################
# include config files
###############################################################
include ./../../../../conf/node.cfg
include ./../../../conf/nna.cfg

#
ifeq ($(ARG.RELEASE),1)
RELEASE_MODE_STR = "1"
else
RELEASE_MODE_STR = "0"
endif

#
VER_INFO_MAIN_STR = $(VER_INFO_MAIN)
VER_INFO_SUB_STR = $(VER_INFO_SUB)

#
LIB_DEF_PATH_STR = $(LIB_PATH)
LIB_CRYPTO_PATH_STR = $(LIB_PATH)/libcrypto

#
INC_DEF_PATH_STR = $(INC_PATH)
INC_CRYPTO_PATH_STR = $(INC_PATH)/libcrypto

#
CFG_PATH_STR = $(CFG_PATH)
NODE_CFG_STR = $(NODE_CFG)
RRNET_CFG_STR = $(RRNET_CFG)
#RRSUBNET_CFG_STR = $(RRSUBNET_CFG)
DB_CFG_STR = $(DB_CFG)
CLI_CFG_STR = $(CLI_CFG)
PATH_CFG_STR = $(PATH_CFG)

#
DB_INFO_STR = $(DB_INFO)
REDIS_LIB_INFO_STR = $(REDIS_LIB_INFO)
#MQTT_LIB_INFO_STR = $(MQTT_LIB_INFO)
#HSM_INFO_STR = $(HSM_INFO)
#SSH_INFO_STR = $(SSH_INFO)
JSON_INFO_STR = $(JSON_INFO)

#
LOG_PATH_STR = $(LOG_PATH)
LOG_NAME_STR = $(LOG_NAME)

#
SH_PATH_STR = $(SH_PATH)

#
DB_INFO_STR_U = USE_$(shell echo $(DB_INFO_STR) | tr [a-z] [A-Z])

#
REDIS_LIB_INFO_STR_U = USE_$(shell echo $(REDIS_LIB_INFO_STR) | tr [a-z] [A-Z])

#
#MQTT_LIB_INFO_STR_U = USE_$(shell echo $(MQTT_LIB_INFO_STR) | tr [a-z] [A-Z])

#
#HSM_INFO_STR_U =  USE_$(shell echo $(HSM_INFO_STR) | tr [a-z] [A-Z])

#
#SSH_INFO_STR_U =  USE_$(shell echo $(SSH_INFO_STR) | tr [a-z] [A-Z])

#
JSON_INFO_STR_U =  USE_$(shell echo $(JSON_INFO_STR) | tr [a-z] [A-Z])

##############################
#
PRE_DEFS += -DRELEASE_MODE=\"$(RELEASE_MODE_STR)\"

#
PRE_DEFS += -DVER_INFO_MAIN=\"$(VER_INFO_MAIN_STR)\"
PRE_DEFS += -DVER_INFO_SUB=\"$(VER_INFO_SUB_STR)\"

#
PRE_DEFS += -DCFG_PATH=\"$(CFG_PATH_STR)\"
PRE_DEFS += -DNODE_CFG_PATH=\"$(CFG_PATH_STR)/$(NODE_CFG_STR)\"
PRE_DEFS += -DRRNET_CFG_PATH=\"$(CFG_PATH_STR)/$(RRNET_CFG_STR)\"
#PRE_DEFS += -DRRSUBNET_CFG_PATH=\"$(CFG_PATH_STR)/$(RRSUBNET_CFG_STR)\"
PRE_DEFS += -DDB_CFG_PATH=\"$(CFG_PATH_STR)/$(DB_CFG_STR)\"
PRE_DEFS += -DPATH_CFG_PATH=\"$(CFG_PATH_STR)/$(PATH_CFG_STR)\"
PRE_DEFS += -DSH_PATH=\"$(SH_PATH_STR)\"

#
PRE_DEFS += -DCLI_CFG_PATH=\"$(CFG_PATH_STR)/$(CLI_CFG_STR)\"

#
PRE_DEFS += -DCLI_LOG_PATH=\"$(LOG_PATH_STR)\"
PRE_DEFS += -DCLI_LOG_FILE_PATH=\"$(LOG_PATH_STR)/$(LOG_NAME_STR)\"

#
PRE_DEFS += -D$(DB_INFO_STR_U)
#PRE_DEFS += -D$(HSM_INFO_STR_U)
#PRE_DEFS += -D$(SSH_INFO_STR_U)
PRE_DEFS += -D$(JSON_INFO_STR_U)

ifeq ($(REDIS_LIB_INFO_STR),$(filter $(REDIS_LIB_INFO_STR),LIBAE LIBEV LIBEVENT))
	PRE_DEFS += -D$(REDIS_LIB_INFO_STR_U)
    PRE_DEFS += -DUSE_DB_REDIS
endif #

#ifeq ($(MQTT_LIB_INFO_STR),$(filter $(MQTT_LIB_INFO_STR),LIBMOSQUITTO))
#	PRE_DEFS += -D$(MQTT_LIB_INFO_STR_U)
#    PRE_DEFS += -DUSE_MQTT
#endif #

EXTRA_CFLAGS += $(PRE_DEFS)

###############################################################
# Libraries & Include
###############################################################

LDFLAGS += -pthread -lrt -lm -ldl
LDFLAGS += -L$(LIB_DEF_PATH_STR)
LDFLAGS += -L$(LIB_CRYPTO_PATH_STR)/openssl_111b
LDFLAGS += -L$(LIB_DEF_PATH_STR)/liblua/lua5.2

ifeq ($(REDIS_LIB_INFO_STR),$(filter $(REDIS_LIB_INFO_STR), LIBEVENT))
    LDFLAGS += -levent
    LDFLAGS += -lhiredis
    INC_DIR += -I$(INC_DEF_PATH_STR)/libevent
else
	error
endif #

LDFLAGS += -llua 
LDFLAGS += -lcrypto 
LDFLAGS += -lssl
LDFLAGS += -lz
#LDFLAGS += -lcurl
LDFLAGS += -lsodium
LDFLAGS += -lpgm
LDFLAGS += -lcunit

ifeq ($(DB_INFO_STR),$(filter $(DB_INFO_STR), MYSQL))
    LDFLAGS += -lmysqlclient
else ifeq ($(DB_INFO_STR),$(filter $(DB_INFO_STR), MONGODB))
    LDFLAGS += -lmongoc-1.0 -lbson-1.0
else
	error
endif #

ifeq ($(JSON_INFO_STR),$(filter $(JSON_INFO_STR), JSONC))
    LDFLAGS += -ljson-c
#else ifeq ($(JSON_INFO_STR),$(filter $(JSON_INFO_STR), JSONCPP))
#    LDFLAGS += -ljsoncpp
endif

INC_DIR  += -I$(INC_DEF_PATH_STR) \
			-I$(INC_CRYPTO_PATH_STR)/openssl_111b \
            -I$(INC_DEF_PATH_STR)/liblua/lua5.2 

INC_DIR  += -I../../inc \
            -I../../inc/utils \
            -I../../inc/net \
            -I../../inc/p2p \
            -I../../inc/cons \
            -I../../inc/cli \
            -I../../inc/sec \
            -I../../inc/db

#INC_DIR += -I$(INC_DEF_PATH_STR)/cppunit
INC_DIR += -I$(INC_DEF_PATH_STR)/cunit

ifeq ($(DB_INFO_STR),$(filter $(DB_INFO_STR),MYSQL))
    INC_DIR += -I$(INC_DEF_PATH_STR)/mysql
    INC_DIR += -I../../inc/db/mysql
else ifeq ($(DB_INFO_STR),$(filter $(DB_INFO_STR),MONGODB))
    INC_DIR += -I$(INC_DEF_PATH_STR)/libmongoc-1.0 \
               -I$(INC_DEF_PATH_STR)/libbson-1.0
    INC_DIR += -I../../inc/db/mongo
else
    error
endif #

ifeq ($(REDIS_LIB_INFO_STR),$(filter $(REDIS_LIB_INFO_STR),LIBAE LIBEV LIBEVENT))
    INC_DIR += -I$(INC_DEF_PATH_STR)/hiredis
    INC_DIR += -I../../inc/db/redis
endif #

INC_DIR += -I../../inc/sec/crypto/openssl
#INC_DIR += -I../../inc/sec/ssh/libssh

#ifeq ($(HSM_INFO_STR),$(filter $(HSM_INFO_STR), YUBIHSM))
#    INC_DIR += -I../../inc/sec/hsm/yubihsm
#endif #

ifeq ($(JSON_INFO_STR),$(filter $(JSON_INFO_STR), JSONC))
    INC_DIR += -I$(INC_DEF_PATH_STR)/json-c
else ifeq ($(JSON_INFO_STR),$(filter $(JSON_INFO_STR), JSONCPP))
    INC_DIR += -I$(INC_DEF_PATH_STR)/jsoncpp
else
	error
endif #

#INC_DIR += -I../../inc/utils/que/msgq
#INC_DIR += -I../../inc/utils/que/zmq

#ifeq ($(MQTT_LIB_INFO_STR),$(filter $(MQTT_LIB_INFO_STR), LIBMOSQUITTO))
#    INC_DIR += -I$(INC_DEF_PATH_STR)/mqtt
#    INC_DIR += -I../../inc/utils/que/mqtt
#endif #

EXTRA_CFLAGS += $(INC_DIR)

###############################################################
# Source Directory
###############################################################

ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
    SRCS = 
else
    SRCS += app/run
endif #

SRCS += utils net p2p cons cli sec db

ifeq ($(DB_INFO_STR),$(filter $(DB_INFO_STR), MYSQL))
    SRCS += db/mysql
else ifeq ($(DB_INFO_STR),$(filter $(DB_INFO_STR), MONGODB))
    SRCS += db/mongo
else
    error
endif #

ifeq ($(REDIS_LIB_INFO_STR),$(filter $(REDIS_LIB_INFO_STR), LIBAE LIBEV LIBEVENT))
    SRCS += db/redis
endif #

SRCS += sec/crypto/openssl

#ifeq ($(SSH_INFO_STR),$(filter $(SSH_INFO_STR), LIBSSH))
#    SRCS += sec/ssh/libssh
#endif #

#ifeq ($(HSM_INFO_STR),$(filter $(HSM_INFO_STR), YUBIHSM))
#    SRCS += sec/hsm/yubihsm
#endif #

#SRCS += utils/que/msgq
#SRCS += utils/que/zmq

#ifeq ($(MQTT_LIB_INFO_STR),$(filter $(MQTT_LIB_INFO_STR), LIBMOSQUITTO))
#    SRCS += utils/que/mqtt
#endif #

#
define objs
    $(eval SRC_L := $(shell echo $(1)))
    $(eval SRC_U := $(shell echo $(SRC_L) | tr [a-z] [A-Z]))
    #$(eval SRC_$(SRC_U)_DIR ?= $(SRC_DIR)/$(SRC_L))
    $(eval SRCS_DIR += $(SRC_L))
    #$(eval OBJ_$(SRC_U)_DIR := $(SRC_$(SRC_U)_DIR))
    $(eval SRC_$(SRC_U)_CPP := $(wildcard $(SRC_$(SRC_U)_DIR)/*.cpp))
    $(eval SRCS_CPP += $(SRC_$(SRC_U)_CPP))
    #$(eval OBJS_CXX += $(patsubst $(SRC_$(SRC_U)_DIR)/%.cpp, $(OBJ_$(SRC_U)_DIR)/%.o, $(SRC_$(SRC_U)_CPP)))
    #$(eval DEPS_CXX += $(patsubst $(SRC_$(SRC_U)_DIR)/%.cpp, $(OBJ_$(SRC_U)_DIR)/%.d, $(SRC_$(SRC_U)_CPP)))
endef #

$(foreach src, $(SRCS) , $(eval $(call objs,$(src))))

###############################################################
# compile options
###############################################################

COMPILE_OBJ_NEW = yes

###################
# compile file list
###################

# main source
SRC_MAIN = 

# common library
SRC_LIB = $(SRCS_CPP)

# all compile source file list
LIBMODULE.TARGET = $(SRC_MAIN) $(SRC_LIB)

# compile meta-file to be in intermediate directory
LIBMODULE.INTERMEDIATE_DIR = $(OBJ_CFG_DIR)

# compile meta-file list (.obj, .d)
ifeq ($(COMPILE_OPT_NEW),$(filter $(COMPILE_OPT_NEW),yes))
    LIBMODULE.OBJ = $(subst $(SRC_DIR), $(LIBMODULE.INTERMEDIATE_DIR), $(LIBMODULE.TARGET:.cpp=.o))
    LIBMODULE.DEP = $(subst $(SRC_DIR), $(LIBMODULE.INTERMEDIATE_DIR), $(LIBMODULE.TARGET:.cpp=.d))
else
    LIBMODULE.OBJ = $(LIBMODULE.TARGET:.cpp=.o)
    LIBMODULE.DEP = $(LIBMODULE.TARGET:.cpp=.d)
endif #

###############################################################
# makefile process
###############################################################

.PHONY: debug release build clean rebuild PRE_BUILD POST_BUILD all

# make process scenario
BUILD_STEP = PRE_BUILD $(TARGET) POST_BUILD

# set makefile target and dependency
# to prevent "make: Nothing to be done for 'release'" warning,
# use @true keyword
ifeq ($(ARG.REBUILD),1)
    # under rebuild, do clean before build
    rebuild: | clean $(BUILD_STEP)
    debug: ; @true
    release: ; @true
else ifeq ($(ARG.CLEAN),1)
    # under clean, target has no rule to build
    release: ; @true
    debug: ; @true
else
    # under build release or debug, do build
    build: | $(BUILD_STEP)
    release: build
    debug: build
endif

ifeq ($(COMPILE_OBJ_NEW),$(filter $(COMPILE_OBJ_NEW),yes))
#######
# macro
#######

CONVERT_SRC   = $(subst $(LIBMODULE.INTERMEDIATE_DIR),$(SRC_DIR),$(@:.o=.cpp))
CONVERT_BUILD = $(subst $(SRC_DIR),$(LIBMODULE.INTERMEDIATE_DIR),$(@:.cpp=.o))

###########
# Link Part
###########

$(TARGET): BUILD_OBJD $(LIBMODULE.OBJ)
ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
#
else
	@echo ----------------------------------------
	@echo Link : $(TARGET)
	@echo ----------------------------------------
ifeq ($(MAKE_SO),$(filter $(MAKE_SO), yes))
	@$(CXX) $(LDFLAGS) $(LIBLINK) $(LIBMODULE.OBJ) -o $(TARGET) $(SYSROOT)
else
	@$(CXX) $(LIBLINK) $(LIBMODULE.OBJ) -o $(TARGET) $(SYSROOT) $(LDFLAGS)
endif #

endif #
	$(info)

##############
# Compile Part
##############
$(LIBMODULE.OBJ): %.o:
	@echo ----------------------------------------
	@echo Compile $(notdir $(CONVERT_SRC)) To $(notdir $(CONVERT_BUILD))
	@echo ----------------------------------------
	@mkdir -p $(@D)
	@$(CXX) -MM -MF $(@:.o=.d) -MT"$(@)" $(EXTRA_CFLAGS) $(CONVERT_SRC) $(SYSROOT)
	@$(CXX) $(EXTRA_CFLAGS) $(LIBCOMPILE) -c -o $@ $(CONVERT_SRC) $(SYSROOT)
ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
	@ar -rcus $(TARGET_LIB) $@ $^
endif #
	@$(info)

else #
###########
# Link Part
###########
$(TARGET): BUILD_OBJD $(LIBMODULE.OBJ) BUILD_CP_OBJ
	@echo ----------------------------------------
	@echo Link : $(TARGET)
	@echo ----------------------------------------
	@$(CXX) -o $(TARGET) $(LIBMODULE.OBJ) $(LDFLAGS)
	
##############
# Compile Part
##############
$(LIBMODULE.OBJ):%.o: %.cpp
	@echo ----------------------------------------
	@echo Compile : $(notdir $<)
	@echo ----------------------------------------
	$(CXX) -c $(EXTRA_CFLAGS) -o $@ $<

endif #

###################
# Pre-build process
###################

PRE_BUILD:
	@echo ================================================================
	@echo Make file started. config =\> $(CONFIG), platform =\> $(PLATFORM)
	@echo ================================================================

####################
# Post-build process
####################

# after release build, do strip command
POST_BUILD:
	@echo Post build...
ifeq ($(MAKE_SO),$(filter $(MAKE_SO), yes))
	@if [ "$(CONFIG)" = "release" ]; then \
		echo Start to strip; \
		echo $(STRIP) $(TARGET); \
		$(STRIP) $(TARGET); \
	fi;
endif #

ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
	@echo Compile completed : $(TARGET_LIB)
else
	@echo Compile completed : $(TARGET)
endif #
	@echo ================================================================
	@echo Make file finished. config =\> $(CONFIG), platform =\> $(PLATFORM)
	@echo ================================================================

BUILD_REPO:
	@$(call make-repo)

BUILD_OBJD:
	@$(call make-objd)

BUILD_CP_OBJ:
	@$(call cp-obj)

####################################
#
define make-objd
   mkdir -p $(OBJ_CFG_DIR);
   mkdir -p $(LIB_CFG_DIR);
endef

#
define make-repo
   for dir in $(SRCS_DIR); \
   do \
	mkdir -p $(OBJ_CFG_DIR)/$$dir; \
   done
endef

#
define cp-obj
   for objf in $(LIBMODULE.OBJ); \
   do \
	cp -rf $$objf $(OBJ_CFG_DIR)/; \
   done
endef
#######################################

##################
# Clean up process
##################
clean:
	@rm -f $(LIBMODULE.OBJ)
	@rm -f $(LIBMODULE.DEP)
	@rm -rf $(OBJ_DIR)
	@rm -rf $(LIB_DIR)
	@rm -f $(TARGET)
	@rm -f *~ core
	@echo -----------------------------------------------------------------
	@echo Clean work finished. config =\> $(CONFIG), platform =\> $(PLATFORM)
	@echo -----------------------------------------------------------------

ifeq ($(COMPILE_OBJ_NEW),$(filter $(COMPILE_OBJ_NEW),yes))
##########################
# Include dependency files
##########################
-include $(LIBMODULE.DEP)
endif #

