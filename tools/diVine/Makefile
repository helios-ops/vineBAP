include $(VINEBAP_SRC)Makefile.common

MYSRC:=$(VINEBAP_SRC)tools/diVine

LLVM_VER=llvm-3.9

LLVM_LIB_DIR=/usr/lib/$(LLVM_VER)/lib/
LLVM_LIBS=libLLVMSupport.a libLLVMCore.a

LLVM_CFLAGS=-I/usr/include/$(LLVM_VER)

LLVM_COMPONENTS=$(addprefix $(LLVM_LIB_DIR), $(LLVM_LIBS)) 

all: diVine

MY_CFLAGS=-std=c++11 -Wno-error -Wno-gnu-anonymous-struct -Wno-nested-anon-types -Wno-c99-extensions -Wno-extended-offsetof -O2 -g -DNDEBUG   -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -MMD 

MY_LDFLAGS=-lglib-2.0 -lpthread -ldwarf -std=c++11 -lcapstone -lelf -lcurses -lstdc++ -lm -lz

PINDIR:=$(BUILD_ROOT)/pin-2.14-71313-gcc.4.4.7-linux

#BOOST_LD_FLAGS:=-L$(BOOSTDIR)/install/lib -lboost_serialization -lboost_iostreams -lboost_program_options

#CXX=clang-3.9
CXX=g++
COMMON_CFLAGS=-std=c++11 -ftemplate-depth=1024 -g
BOOST_CPP_FLAGS=
BOOST_LD_FLAGS=

diVine: main.o irRecovery.o cfgExtract.o binaryCFG.o $(COMMON_OBJECTS) $(MYSRC)/vmi/libvmi.a $(LLVM_COMPONENTS) 
	#clang-3.9 $^ $(MY_LDFLAGS) -L$(BOOSTDIR)/install/lib -Wl,-rpath $(BOOSTDIR)/install/lib -lboost_serialization -lboost_iostreams -lboost_program_options -I$(FUZZBALL_BASEDIR)/fuzzball/libasmir/src/include  -I$(VEXDIR)/pub -Wall  -g -O2 -L$(VINEDIR)/src -L$(VEXDIR) -lasmir -lvex -lbfd -lopcodes -liberty -lz -ldl -o $@ 
	#clang++-3.9 $^ $(MY_LDFLAGS) -lboost_serialization -lboost_iostreams -lboost_program_options -I$(FUZZBALL_BASEDIR)/fuzzball/libasmir/src/include  -I$(VEXDIR)/pub -Wall  -g -O2 -L$(VINEDIR)/src -L$(VEXDIR) -lasmir -L$(PINDIR)/extras/xed-intel64/lib -lvex -lbfd -lxed -lopcodes -liberty -lz -ldl -o $@ 
	g++ $^ $(MY_LDFLAGS) -lboost_serialization -lboost_iostreams -lboost_program_options -I$(FUZZBALL_BASEDIR)/fuzzball/libasmir/src/include  -I$(VEXDIR)/pub -Wall  -g -O2 -L$(VINEDIR)/src -L$(VEXDIR) -lasmir -L$(PINDIR)/extras/xed-intel64/lib -lvex -lbfd -lxed -lopcodes -liberty -lz -ldl -o $@ 


%.o: $(MYSRC)/%.cpp
	#clang++-3.9 -Wextern-c-compat $(MY_CFLAGS) $^ -I$(MYSRC) $(LLVM_CFLAGS) $(COMMON_CFLAGS) $(VINEBAP_CPPFLAGS) $(VINE_CPPFLAGS) $(VEX_CPPFLAGS) -I$(PINDIR)/extras/xed-intel64/include -c -o $@
	g++ $(MY_CFLAGS) $^ -I$(MYSRC) $(LLVM_CFLAGS) $(COMMON_CFLAGS) $(VINEBAP_CPPFLAGS) $(VINE_CPPFLAGS) $(VEX_CPPFLAGS) -I$(PINDIR)/extras/xed-intel64/include -c -o $@


