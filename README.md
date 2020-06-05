# linux-process_mem
Simple library to Read and Write Memory of a Linux Process through custom Kernel Module.

# Things the module can do
* Read/Write specified size of bytes from/to a process-space memory address.
* Can extract specific virtual memory area info (Such as starting address, ending address and flags)

# Requirements
* Linux Kernel Version 5.0+(I am not sure but I guess 4.6+ should also work)
* Make
* GCC
* lib-gnl-3
* Required Kernel Module Headers

# Build
* `make` command in the project folder should do be enough.
* `libs` folder contains lib binary files, you must be interested in `libprocess_mem.so`.

# Test?
* `test` program is generated, you can search a specified integer (the first found address is returned) of a specified PID.

* BTW the module won't going to check if the process which is trying to communicate got root privilege, if you pass `check_root=0` this as an argument while loading the module or using `insmod`.
