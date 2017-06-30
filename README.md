# PvD related kernel patch

## Patch per se

This directory contains a path file to apply to kernel 4.10.7. It brings
support for IpV6 PvD feature as defined in IETF Draft XXX.

We decide to provide patches for now in order to reduce the size of the
kernel set stored in git.

The patch is generated with the following command :

~~~~
diff -Naur -X DiffNaurExclude linux-4.10.7-orig linux-4.10.7 >patch-linux-4.10.7
~~~~

## Headers

Some kernel headers must be copied temporarily in the pvdid-daemon repo to bring
kernel definitions to user space applications :

~~~~
cp usr/include/linux/pvd-user.h ../pvdid-daemon/include/linux
cp usr/include/linux/rtnetlink.h ../pvdid-daemon/include/linux
~~~~

Ultimately, this should no longer be needed once PvD support will be officially
part of the kernel. The C library build should copy these files automatically
under /usr/include.

