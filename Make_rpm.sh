#!/bin/bash
rm -rf rpms/repodata
createrepo ./rpms/
tar cvzf build/ceph-rpms.tgz -C rpms/ .
files=("ceph-rpms.tgz" "setup_ceph.py" "setup.sh")
dirs=("calamari" "zabbix")
for file in ${files[@]}
do
    if [ ! -e "build/$file" ];then
        echo "$file is not available!!!"
       exit 1
    fi
done
for dir in ${dirs[@]}
do
    if [ ! -d "build/$dir" ];then
       echo "$dir is not available!!!"
       exit 1
    fi
done
tar cvzf build.tar.gz build utils
make rpm
rm -f build/ceph-rpms.tgz build.tar.gz
