VINEBAP_SRC?=""
BUILD_ROOT?=""

all: diVine flowStitcher #diVine #ida-static


diVine:
	mkdir -p $@
	cd $@ && make -f $(VINEBAP_SRC)tools/diVine/Makefile VINEBAP_SRC=$(VINEBAP_SRC) BUILD_ROOT=$(BUILD_ROOT)


flowStitcher:
	mkdir -p $@
	cd $@ && make -f $(VINEBAP_SRC)tools/flowStitcher/Makefile VINEBAP_SRC=$(VINEBAP_SRC) BUILD_ROOT=$(BUILD_ROOT)

ida-static:
	mkdir -p $@
	cd $@ && make -f $(VINEBAP_SRC)tools/ida-static/Makefile VINEBAP_SRC=$(VINEBAP_SRC) BUILD_ROOT=$(BUILD_ROOT)

