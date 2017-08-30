# PvD related kernel patch

## Branches

The _master_ branch contains a patch to be applied against a pristine 4.10.7
kernel source tree.

A patch for an ubuntu zesty kernel tree is available in the _ubuntu-zesty_
branch :

~~~~
git clone https://github.com/IPv6-mPvD/pvd-linux-kernel-patch.git
cd pvd-linux-kernel-patch
git checkout ubuntu-zesty
~~~~

## Patch per se

This directory contains a path file to apply to kernel 4.10.7. It brings
support for IpV6 PvD feature as defined in IETF Draft XXX.

We have decided to provide patches for now in order to reduce the size of the
kernel set stored in git.

The patch is generated with the following command :

~~~~
diff -Naur -X DiffNaurExclude linux-4.10.7-orig linux-4.10.7 >patch-linux-4.10.7
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
