VINEBAP_SRC?=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BUILD_ROOT?=$(VINEBAP_SRC)/../build

CURR_DIR=$(abspath $(shell pwd))

all: tools 

.PHONY: tools clean all 

clean:
	rm -rf ./tools

tools:
	mkdir -p $@
	cd $@ && make -f $(VINEBAP_SRC)tools/Makefile VINEBAP_SRC=$(VINEBAP_SRC) BUILD_ROOT=$(BUILD_ROOT) BUILD_DIR=$(BUILD_ROOT)/$@ 
