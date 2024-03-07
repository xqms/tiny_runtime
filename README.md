tiny_runtime
============

tiny_runtime is a fast container runtime that consists of a single file. It is statically linked and has no dependencies other
than a Linux kernel newer than 4.18.

The runtime can be installed into the container image, resulting in a single executable file portable to any Linux system.

At the moment, only the x86_64 architecture is supported.

Other features
--------------

 * NVIDIA support (CUDA + GL)

Usage & examples
----------------

 * Converting a docker image and running it
   ```bash
   docker pull ubuntu:20.04
   tiny_runtime --docker ubuntu:20.04 --docker-out ubuntu.trt

   ./ubuntu.trt
   ```

Installation
------------

... WIP ...

Building from source
--------------------

Dependencies:

```bash
sudo apt install libfuse3-dev libcap-dev libzstd-dev
```

Compilation:

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make -j9
```
