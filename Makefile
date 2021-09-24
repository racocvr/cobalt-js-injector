################################################################################
# bugficks@samygo
# (c) 2013-2017 
#
# License: GPLv3
#
################################################################################
include ../../samygo.mk
include ../zoe-inc/zoe-inc.mk
################################################################################

SGO_TIZEN=1
LIB=CobaltJsInjector
LOG_LEVEL=eSGO_LOG_DEBUG
LOG_FILE=/tmp/$(LIB).log
#LOG_FILE=/dev/pts/0

LIB_Cxx_FLAGS:=-O2 -I. -std=c++17

TARGETS:=lib$(LIB).so

lib$(LIB)-src += $(LIB).cpp

lib$(LIB)-libs += dl stdc++
lib$(LIB)-libs +=

lib$(LIB)_CFLAGS:=${LIB_Cxx_FLAGS}
lib$(LIB)_CXXFLAGS:=${LIB_Cxx_FLAGS}
lib$(LIB)_CPPFLAGS+=-DSGO_LOG_LEVEL=$(LOG_LEVEL) -DSGO_LOG_TAG=\"$(LIB)\" -DLIB_NAME=\"$(LIB)\" -DSGO_LOG_FILE=\"$(LOG_FILE)\"

lib$(LIB)_LDFLAGS+=-Wl,--unresolved-symbols=ignore-in-shared-libs

################################################################################
include ../../targets.mk
################################################################################ 