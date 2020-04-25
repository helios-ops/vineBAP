BOOSTDIR?=$(BUILD_ROOT)/boost_1_48_0-gcc-4.8-fPIC

include $(VINEBAP_SRC)Makefile.common


PINDIR:=$(BUILD_ROOT)/pin-2.14-71313-gcc.4.4.7-linux

PIN_CPP_FLAGS:=-DBIGARRAY_MULTIPLIER=1 -Wall -Werror -Wno-unknown-pragmas -fno-stack-protector -DTARGET_IA32E -DHOST_IA32E -DTARGET_LINUX  -I$(PINDIR)/source/include/pin -I$(PINDIR)/source/include/pin/gen -I$(PINDIR)/extras/components/include -I$(PINDIR)/extras/xed-intel64/include -I$(PINDIR)/source/tools/InstLib -O3 -fomit-frame-pointer -fno-strict-aliasing

PIN_LD_FLAGS:=-shared -Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=$(PINDIR)/source/include/pin/pintool.ver -L$(PINDIR)/intel64/lib -L$(PINDIR)/intel64/lib-ext -L$(PINDIR)/intel64/runtime/cpplibs -lstdc++ -L$(PINDIR)/extras/xed-intel64/lib -lxed -lpin -lpindwarf -ldl


MYSRC:=$(VINEBAP_SRC)tools/flowStitcher
all: flowStitcher.so

clean: 
	rm *.o
	rm flowStitcher.so

flowStitcher.so: pinTracer.o PinDisasm.o $(COMMON_OBJECTS) 
	#g++ -shared -fPIC $^ -Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=$(PINDIR)/source/include/pin/pintool.ver -L$(PINDIR)/intel64/lib -L$(PINDIR)/intel64/lib-ext -Wl,-rpath -L$(PINDIR)/intel64/runtime/cpplibs -lstdc++ -L$(PINDIR)/extras/xed-intel64/lib -lpin -lxed -lpindwarf -ldl -L$(BOOSTDIR)/install/lib -Wl,-rpath $(BOOSTDIR)/install/lib -lboost_serialization -lboost_iostreams -lboost_program_options -I$(FUZZBALL_BASEDIR)/fuzzball/libasmir/src/include  -I$(VEXDIR)/pub -Wall  -g -O2 -L$(VINEDIR)/src -L$(VEXDIR) -lasmir -lvex -lbfd -lopcodes -liberty -lz -ldl -lbfd -lopcodes -lz -lbfd -o flowStitcher.so
	g++ -shared -fPIC $^ -Wl,--hash-style=sysv -Wl,-Bsymbolic -Wl,--version-script=$(PINDIR)/source/include/pin/pintool.ver -L$(PINDIR)/intel64/lib -L$(PINDIR)/intel64/lib-ext -L$(PINDIR)/extras/xed-intel64/lib -lpin -lxed -lpindwarf -ldl -L$(BOOSTDIR)/install/lib -Wl,-rpath $(BOOSTDIR)/install/lib -lboost_serialization -lboost_iostreams -lboost_program_options -I$(FUZZBALL_BASEDIR)/fuzzball/libasmir/src/include  -I$(VEXDIR)/pub -Wall  -g -O2 -L$(VINEDIR)/src -L$(VEXDIR) -lasmir -lvex -lbfd -lopcodes -liberty -lz -ldl -lstdc++ -o flowStitcher.so
	cp $(MYSRC)/run_pinTracer.sh .
	sed -i "s#XXX_MY_BUILD_DIR#$(BUILD_ROOT)#g" ./run_pinTracer.sh
	ln -s $(MYSRC)/tests .

%.o: $(MYSRC)/%.cpp
	g++ $(GENERAL_CPP_FLAGS) $(VINEBAP_CPPFLAGS) $(VEX_CPPFLAGS) $(VINE_CPPFLAGS) $(PIN_CPP_FLAGS) $(BOOST_CPP_FLAGS) $< -c -o $@ 
