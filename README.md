# PvD related kernel patch

This directory contains a path file to apply to kernel 4.10.7. It brings
support for IpV6 PvD feature as defined in IETF Draft XXX.

We decide to provide patches for now in order to reduce the size of the
kernel set stored in git.

The patch is generated with the following command :

~~~~
diff -Naur -X DiffNaurExclude linux-4.10.7-orig linux-4.10.7 >patch-linux-4.10.7
~~~~

