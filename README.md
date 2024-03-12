tiny_runtime
============

tiny_runtime is a fast container runtime that consists of a single file. It is statically linked and has no dependencies other
than a Linux kernel newer than 4.18.

The runtime can be installed into the container image, resulting in a single executable file portable to any Linux system.

At the moment, only the x86_64 architecture is supported.

Other features
--------------

 * NVIDIA support (CUDA + GL)
 * Supported container image formats: Plain SquashFS, Apptainer, Singularity, enroot

Usage & examples
----------------

 * Converting a docker image and running it
   ```bash
   docker pull ubuntu:20.04
   tiny_runtime --docker ubuntu:20.04 --docker-out ubuntu.trt

   ./ubuntu.trt
   ```
 * Directly running a SIF (Singularity/Apptainer) image
   ```bash
   tiny_runtime --image container.sif
   ```
 * Converting a SIF image into an executable file including `tiny_runtime`
   ```bash
   tiny_runtime --install container.sif
   ./container.sif
   ```
 * Setting a fixed command to be run ("entrypoint")
   ```bash
   tiny_runtime --install container.sif nvidia-smi
   ./container.sif
   ```
 * Tweaking options on an image with an entrypoint
   ```bash
   TRT_ARGS="--verbose" ./container.sif
   ```

Installation
------------

You can download the latest binary from the release page (https://github.com/xqms/tiny_runtime/releases/)
or build your own from source.

One-line install in `/usr/local/bin` (requires root):

```bash
wget -O /tmp/tiny_runtime 'https://github.com/xqms/tiny_runtime/releases/latest/download/tiny_runtime' && sudo install /tmp/tiny_runtime /usr/local/bin/tiny_runtime
```

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
