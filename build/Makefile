
#Makefile for SharkSSL Amalgamated examples and tools

#General macros
EMPTY :=
SPACE := $(EMPTY) $(EMPTY)

ifndef SHARKPLAT
#export AR
ifndef RANLIB
export RANLIB := ranlib
#export ARFLAGS
export AROFT := $(SPACE)
export CC := gcc
export CXX := g++
endif
export O := .o
export IFT := -I
export MFT := -D
export OFT := -o$(SPACE)
export LNKOFT := -o$(SPACE)
export LIBPFX := lib
export LIBEXT := .a
#CFLAGS+=-DB_LITTLE_ENDIAN
CFLAGS+=-Wall -c -fno-strict-aliasing
ifeq (debug,$(build))
CFLAGS += -g
else
CFLAGS += -Os -O3
endif

SHARKPLAT=Posix
CFLAGS+=$(IFT)../src/arch/Posix
EXTRALIBS += -lrt
ifneq ($(COMSPEC)$(ComSpec),)
EXT=.exe
endif
endif
CFLAGS+=$(IFT)../inc/arch/$(SHARKPLAT)

#SHA1 not included by default, but some examples use it
CFLAGS+=$(MFT)SHARKSSL_USE_SHA1

LIBNAME=$(LIBPFX)SharkSSL$(LIBEXT)
VPATH=../src:../tools:../examples
VPATH+=../src/MinnowServer:../src/SMTP
ifdef XVPATH
VPATH+=$(XVPATH)
endif
CFLAGS+= $(IFT)../inc
CFLAGS+=$(IFT)../examples $(IFT)../src/SMTP # For SMTP example
CFLAGS+=$(IFT)../src/MinnowServer
CFLAGS+=$(XCFLAGS)

ifndef ODIR
ODIR = obj
endif

# Implicit rules for making .o files from .c files
$(ODIR)/%$(O) : %.c
	$(CC) $(CFLAGS) $(OFT)$@ $<

SOURCE = $(filter-out SeCtx.c, $(notdir $(wildcard ../src/*.c)))

OBJS = $(SOURCE:%.c=$(ODIR)/%$(O))


all: obj tools $(LIBNAME) examples

obj:
	mkdir obj
	cd obj


$(LIBNAME): $(OBJS)
	$(AR) $(ARFLAGS) $(AROFT)$@ $(OBJS)
	$(RANLIB) $@


##################  TOOLS
.PHONY : tools clean JSONEX
tools: obj \
	SharkSSLParseCAList$(EXT) \
	SharkSSLParseCert$(EXT) SharkSSLParseKey$(EXT)

SharkSSLParseCAList$(EXT): $(ODIR)/SharkSSLParseCAList$(O)
	$(CC) $(LNKOFT)$@ $^

SharkSSLParseCert$(EXT): $(ODIR)/SharkSSLParseCert$(O)
	$(CC) $(LNKOFT)$@ $^

SharkSSLParseKey$(EXT): $(ODIR)/SharkSSLParseKey$(O)
	$(CC) $(LNKOFT)$@ $^



##################  EXAMPLES

.PHONY : examples
examples: CertCheck$(EXT) \
	  WsEchoClient$(EXT) \
	  LED-SMQ$(EXT) \
	  SharkTrust$(EXT) \
	  Chat-MQTT$(EXT) \
	  AWS-MQTT$(EXT) \
	  JSONEX \
	  smtp$(EXT)


CertCheck$(EXT): $(ODIR)/CertCheck$(O) $(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)

WsEchoClient$(EXT): $(ODIR)/WsEchoClient$(O) $(ODIR)/WsClientLib$(O) \
	$(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)

#smtp$(EXT): $(ODIR)/BufPrint$(O) $(ODIR)/SMTP-example$(O) $(ODIR)/SMTP$(O) \
#	$(ODIR)/selib$(O)
#	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)
smtp$(EXT):
	@echo "SMTP example disabled; see makefile for details"


SharkTrust$(EXT): $(ODIR)/SharkTrust$(O) $(ODIR)/MSLib$(O) \
	$(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)

LED-SMQ$(EXT): $(ODIR)/LED-SMQ$(O) $(ODIR)/SharkMQ$(O) \
	$(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)

Chat-MQTT$(EXT): $(ODIR)/Chat-MQTT$(O) $(ODIR)/SharkMQTT$(O) \
	$(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)

AWS-MQTT$(EXT): $(ODIR)/AWS-MQTT$(O) $(ODIR)/SharkMQTT$(O) \
	$(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)


clean:
	rm -rf obj *.a *.o *.obj


JSONEX:
ifneq ($(wildcard ../../JSON/.*),)
	$(MAKE) XVPATH=../../JSON/src XCFLAGS="-DJSONEXAMPLE -DNO_JVAL_DEPENDENCY -I../../JSON/inc" LED-JSON$(EXT)
else
	@echo "INFO: No JSON directory. Cannot build M2M-LED demo with JSON encoding/decoding."
endif

LED-JSON$(EXT): $(patsubst %.c,$(ODIR)/%$(O), LED-JSON.c BaAtoi.c BufPrint.c JDecoder.c JEncoder.c JParser.c) $(ODIR)/selib$(O)
	$(CC) $(LNKOFT)$@ $^ $(LIBNAME) $(EXTRALIBS)


