ARG BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core:3.0

FROM ${BASE_IMAGE}

# Trust Microsoft-signed packages
RUN gpg --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY  \
    && tdnf -y update  \
    && tdnf -y install ca-certificates
    
RUN curl -L https://github.com/microsoft/CCF/releases/download/ccf-6.0.14/ccf_virtual_devel_6.0.14_x86_64.rpm -o ccf-devel.rpm  \
    && tdnf -y install ./ccf-devel.rpm

