#!/bin/bash

# create repo
cat << __EOT__ > /etc/yum.repos.d/FlexStorage.repo
[FlexStorage]
name=FlexStorage
baseurl=file:///opt/FlexStorage/ceph-packages/
enabled=1
priority=1
gpgcheck=0
__EOT__

if [ -d /opt/FlexStorage/ceph-packages ]; then
    rm -rf /opt/FlexStorage/ceph-packages
fi

# copy files over
mkdir -p /opt/FlexStorage/ceph-packages
mkdir -p /opt/FlexStorage/bin

cd /opt/FlexStorage/ceph-packages; tar xvzf /opt/FlexStorage/build/ceph-rpms.tgz
cd /opt/FlexStorage/bin; cp -f /opt/FlexStorage/build/setup_ceph.py ./ 

# Remove existing python-crypto-2.0.1 rpm.
yum -y --disablerepo=* remove python-crypto-2.0.1

# Install basic packages 
yum -y --disablerepo=* --enablerepo=FlexStorage install fabric

