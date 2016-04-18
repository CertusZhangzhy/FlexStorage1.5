#
# Fabric Ceph Spec File
#

%if ! (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}
%endif

#################################################################################
# common
#################################################################################
Name:		FlexStorage
Version: 	%{version}
Release: 	%{?revision}
Summary:        Ceph Deploy with the Fabric 	
License: 	MIT
Group:   	System/Filesystems
URL:     	http://ceph.com/
Source0: 	%{name}_%{version}.tar.gz
%description

%prep
echo "prep"

%install
echo "install"
mkdir -p %{buildroot}
cd %{buildroot}
mkdir -p ./opt/FlexStorage
cd opt/FlexStorage
tar xfz %{tarname}

%clean
echo "clean"
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf "$RPM_BUILD_ROOT"

%files
/opt/FlexStorage/

%changelog
