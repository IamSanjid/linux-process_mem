PKG_CONFIG=pkg-config
NL_LIBNAME=libnl-3.0 libnl-genl-3.0

NL_LIB_FLAGS=$(shell $(PKG_CONFIG) --cflags $(NL_LIBNAME))
NL_LIBS_L=$(shell $(PKG_CONFIG) --libs-only-L $(NL_LIBNAME))
NL_LIBS_l=$(shell $(PKG_CONFIG) --libs-only-l $(NL_LIBNAME))

PROJ_LIBS=$(shell pwd)/libs
KERNEL_DIR = /lib/modules/$(shell uname -r)/build

CC=${CROSS_COMPILE}gcc

.PHONY:all
all: clean lib-gnl lib lib-so test module
# builds the gnl part of the project
lib-gnl: include/process_mem_genl.h process_mem_genl.c
	$(CC) -Wextra -Wall -Werror -Wno-unused-parameter -c -fPIC process_mem_genl.c -Iinclude/ $(NL_LIB_FLAGS) $(NL_LIBS_L) $(NL_LIBS_l) -o $(PROJ_LIBS)/process_mem_genl.o
# builds the api bridge
lib: include/process_mem_types.h include/process_mem.h process_mem.c
	$(CC) -Wextra -Wall -Werror -Wno-unused-parameter -c -fPIC process_mem.c -L$(PROJ_LIBS) -Iinclude/ $(NL_LIB_FLAGS) $(NL_LIBS_L) $(NL_LIBS_l) -lprocess_mem_genl.o -o $(PROJ_LIBS)/process_mem.o
# build shared lib
lib-so: $(PROJ_LIBS)/process_mem_genl.o $(PROJ_LIBS)/process_mem.o
	$(CC) -shared -Iinclude/ -L$(PROJ_LIBS) $(PROJ_LIBS)/process_mem_genl.o $(PROJ_LIBS)/process_mem.o $(NL_LIB_FLAGS) $(NL_LIBS_L) $(NL_LIBS_l) -o $(PROJ_LIBS)/libprocess_mem.so
# builds test program
test: libs/libprocess_mem.so
	$(CC) -Wl,-rpath=$(PROJ_LIBS) -Wall test.c -Iinclude/ -L$(PROJ_LIBS) -lprocess_mem -o test
# builds module
module:
	$(MAKE) -C $(shell pwd)/kernel-module KERNEL_DIR=$(KERNEL_DIR) 

.PHONY: install
install:
	$(MAKE) -C $(shell pwd)/kernel-module install

.PHONY: clean
clean:
	rm -f *.o *.so process_mem
	$(MAKE) -C $(shell pwd)/kernel-module KERNEL_DIR=$(KERNEL_DIR) clean