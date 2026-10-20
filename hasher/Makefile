# verushash: VerusHash2.2 share validation helper of the VRSC pool. Sources in verus-src/crypto/ are
# vendored+stripped from VerusCoin's own node (see verushash.cpp's header comment and vrsc-project.md).
# Needs AES-NI + PCLMUL (any x86-64 CPU from ~2013 on) -- CVerusHash(V2)::init() aborts with a clear
# message instead of silently hashing wrong if the CPU lacks them (no portable/ARM fallback was ported).
#   make            (STATIC=-static makes a binary that runs on any Linux)
CXX ?= g++
CC ?= gcc
STATIC ?=

VERUS_DIR = verus-src
ISA_FLAGS = -maes -mpclmul -msse4.2 -mssse3

C_OBJS = $(VERUS_DIR)/crypto/haraka.o
CXX_OBJS = $(VERUS_DIR)/crypto/verus_hash.o $(VERUS_DIR)/crypto/verus_clhash.o $(VERUS_DIR)/crypto/verus_clhash_support.o

CFLAGS = -O2 -std=c11 $(ISA_FLAGS) -I$(VERUS_DIR)
CXXFLAGS = -O2 -std=c++17 $(ISA_FLAGS) -I$(VERUS_DIR)

verushash: verushash.o $(C_OBJS) $(CXX_OBJS)
	$(CXX) -O2 $(STATIC) -o $@ verushash.o $(C_OBJS) $(CXX_OBJS) -lpthread

verushash.o: verushash.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f verushash verushash.o $(C_OBJS) $(CXX_OBJS)
