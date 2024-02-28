tiny_runtime
============

A tiny & fast container runtime that is statically linked and runs on most Linux kernels (>= 4.18). We only support the x86_64, sorry.

Building
--------

Dependencies:

```bash
sudo apt install libfuse3-dev libcap-dev
```

Compilation:

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make -j9
```
