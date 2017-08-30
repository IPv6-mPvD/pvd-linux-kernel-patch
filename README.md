# PvD related kernel patch

## Patch per se

WARNING : the instructions below are used to add pvd support to a ubuntu
4.10 kernel. We will revert to provide a patch for a pristine kernel in
the next commits.

Pre-requisite :

~~~~
git clone git://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git ubuntu-4.10.0
cd ubuntu-4.10.0
git checkout 56389f24b205f2464626d56bc15c5a6ceeeceedf
~~~~

We have decided to provide patches for now in order to reduce the size of the
kernel set stored in git.

The patch is generated with the following command :

~~~~
diff -Naur -X DiffNaurExclude ubuntu-4.10.0-orig ubuntu-4.10.0 >patch-linux-4.10.7
~~~~

## Headers

Some kernel headers must be copied temporarily in the pvdid-daemon repo to bring
kernel definitions to user space applications :

~~~~
mkdir -p ../pvdd/include
cp usr/include/linux/pvd-user.h ../pvdd/include/linux
cp usr/include/linux/rtnetlink.h ../pvdd/include/linux
mkdir -p ../pvdd/include/asm-generic
cp usr/include/asm-generic/socket.h ../pvdd/include/asm-generic
~~~~

Ultimately, this should no longer be needed once PvD support will be officially
part of the kernel. The C library build should copy these files automatically
under /usr/include.

## Activating PvD feature

Activate _CONFIG\_PVD_ in the .config file.

On PvD aware kernels, new entries are created under _/proc_ :

~~~~
file : /proc/net/pvd
directory : /proc/net/pvd.d/<pvd>
~~~~

These entries are created even if no pvd (explicit or implicit) has been
received.
