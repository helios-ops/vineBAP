COMMON_CFLAGS=-m32 -DH_DISABLE_DEBUG -DNDEBUG

include $(VINEBAP_SRC)Makefile.common

MYSRC:=$(VINEBAP_SRC)tools/ida-static

IDADIR=/home/hhui/softwares/IDA/IDA-6.4
IDAPLUGIN_DIR=$(IDADIR)/plugins
IDASDK_DIR=$(IDADIR)/sdk

IDA_CFLAGS=-m32 -fpermissive -fPIC -D__IDP__ -D__PLUGIN__ -Wno-undef -c -D__LINUX__ -D__EA64__ -I$(IDASDK_DIR)/include 
IDA_LDFLAGS=-m32 -fpermissive -shared -fPIC -L$(IDADIR) -lida64 -Wl,--version-script=$(IDASDK_DIR)/plugins/plugin.script


all: ida-static.plx64

clean:
	rm ./*.o
	rm ida-static.plx64

ida-static.plx64: ida-main.o CFGRecovery.o $(COMMON_OBJECTS) 
	g++ $^ $(IDA_LDFLAGS) -L$(BOOSTDIR)/install/lib -Wl,-rpath $(BOOSTDIR)/install/lib -lboost_serialization -lboost_iostreams -lboost_program_options -I$(FUZZBALL_BASEDIR)/fuzzball/libasmir/src/include  -I$(VEXDIR)/pub -Wall  -g -O2 -L$(VINEDIR)/src -L$(VEXDIR) -lasmir -lvex -lbfd -lopcodes -liberty -lz -ldl -lbfd -lopcodes -lz -lbfd -o $@ 

%.o: $(MYSRC)/%.cpp
	g++ $^ $(COMMON_CFLAGS) $(IDA_CFLAGS) $(VINEBAP_CPPFLAGS) $(VINE_CPPFLAGS) $(VEX_CPPFLAGS) $(BOOST_CPP_FLAGS) -I$(PINDIR)/extras/xed-intel64/include -o $@

install:
	cp ida-static.plx64 $(IDAPLUGIN_DIR)/ida-static.plx64

uninstall:
	rm $(IDAPLUGIN_DIR)/ida-static.plx64
