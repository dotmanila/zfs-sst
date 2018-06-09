# ZFS SST Script for PXC

SST script for Percona XtraDB Cluster running on top of ZFS

## Installing

- Tested on Ubuntu Xenial 16.04
- Must have a ZFS dataset named `mysql` that has all MySQL data underneat it.
- Add the following sudoers file into `/etc/sudoers.d/zfs-mysql`

```
Cmnd_Alias MYSQL_ZFS = \
  /sbin/zfs "", /sbin/zfs help *, \
  /sbin/zfs get, /sbin/zfs get *, \
  /sbin/zfs list, /sbin/zfs list *, \
  /sbin/zfs snap, /sbin/zfs snap *, \
  /sbin/zfs send *, /sbin/zfs recv *, \
  /sbin/zfs destroy, /sbin/zfs destroy *, \
  /sbin/zpool list, /sbin/zpool list *, \
  /usr/bin/mysqld_safe

ALL ALL = (root) NOPASSWD: MYSQL_ZFS
Defaults!MYSQL_ZFS !requiretty
```
- Copy the file ``wsrep_sst_zfs.sh`` to ``/usr/bin/wsrep_sst_zfs`` and ``chmod`` it to ``775``.
- Minimum SST and MySQL configuration:

```
[mysqld]
wsrep_sst_method = zfs
wsrep_sst_auth = root:percona

[sst]
tmpdir = /var/lib/mysql-zfs
```

Once the SST process is initiated, the SST script will detach from the ``mysqld`` process to be able to unmount the ZFS datasets. This script is neither alpha, beta nor RC - it is in very early stages and may be subject for full rewrite in the future as ZFS SST requires better communication between the Donor and Joiner that would be too complex with Bash/Shell script.

If you are interested in testing, I've setup the ZFS volumes on each node like below:

```
sudo zpool create -f -o ashift=12 mysql /dev/xvdb
sudo zfs set recordsize=16k mysql
sudo zfs set atime=off mysql
sudo zfs set logbias=latency mysql
sudo zfs set primarycache=metadata mysql
sudo zfs set compression=lz4 mysql

sudo zfs create -o recordsize=128K mysql/logs
sudo zfs create -o recordsize=16K mysql/data

sudo chown -R mysql.mysql /mysql/*
```