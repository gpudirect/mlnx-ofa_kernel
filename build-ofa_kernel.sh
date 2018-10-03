#!/bin/bash

#For others fighting with “error: line 25: Dependency tokens must begin with alpha-numeric, ‘_’ or ‘/’: 
#BuildRequires: %kernel_module_package_buildreqs” on RHEL6, installing the redhat-rpm-config package res
#olves it. I found the answer under “Caveats” in http://downloads.linux.hp.com/SDR/psp/suse/11.2/i386/8.
#50/hp-tg3-3.99p-9.src.txt :

set -x

kver=$(uname -r)
k_src=/lib/modules/${kver}/build
topdir=/var/tmp/dado_topdir
[ -e $topdir ] || mkdir -p $topdir/SOURCES

#OFA=mlnx-ofa_kernel-2.3
#OFA=mlnx-ofa_kernel-3.2
OFA=mlnx-ofa_kernel

sdir=$PWD
cd ..

cp -r ${OFA} $topdir/${OFA}-3.4
cd $topdir
tar czvf $topdir/SOURCES/${OFA}-3.4.tgz ${OFA}-3.4

cd $sdir

rpmbuild -ba \
    --nodeps \
    --define "_topdir $topdir" \
    --define '_dist %{nil}' \
    --define 'configure_options   --with-core-mod --with-user_mad-mod --with-user_access-mod --with-addr_trans-mod --with-mthca-mod --with-mlx4-mod --with-mlx4_en-mod --with-mlx4_vnic-mod --with-mlx5-mod --with-ipoib-mod' \
    --define "KVERSION $kver" \
    --define "K_SRC $k_src" \
    --define 'KMP 1' \
    --define '_prefix /usr' \
    mlnx-ofa_kernel.spec

echo "RPMs are in $topdir/RPMS/x86_64"

# copy RPMs back to a NFS shared fs
cp -v $topdir/RPMS/x86_64/*${OFA}-3.4*.rpm .

