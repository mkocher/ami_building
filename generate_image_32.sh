#!/bin/bash -e
# ami-0a59bb63 seems to be a good 64bit 5.4 ami # ec2-run-instances ami-0a59bb63 -k mine2 -t m1.large

#ami-08f41161 # ec2-run-instances ami-08f41161 -k mine2 -t c1.medium

export IMAGE_NAME=refactoredcentos5i386
export IMAGE_VERSION=alpha1
# For vmlinuz-2.6.18-xenU-ec2-v1.0.i386
export KERNEL_ID=aki-9b00e5f2       #32bit
# export KERNEL_ID=aki-9800e5f1       #64bit - doesn't seem to be necessary or work

source auth.sh

updateEc2AmiTools() {
	echo "Updating Local ec2-ami-tools"
    wget http://s3.amazonaws.com/ec2-downloads/ec2-ami-tools.noarch.rpm
	rpm -Uvh ec2-ami-tools.noarch.rpm || true
}

makeImageAndFilesystems() {
    echo "Creating 10GB Image"
    mkdir /mnt/image
    dd if=/dev/zero of=/mnt/image/$IMAGE_NAME bs=1M count=10240
    echo "Creating File System"
    mke2fs -F -j /mnt/image/$IMAGE_NAME
    mkdir /mnt/ec2-fs
    echo "Mounting File System in /mnt/ec2-fs"
    mount -o loop /mnt/image/$IMAGE_NAME /mnt/ec2-fs
    mkdir /mnt/ec2-fs/dev
    /sbin/MAKEDEV -d /mnt/ec2-fs/dev -x console
    /sbin/MAKEDEV -d /mnt/ec2-fs/dev -x null
    /sbin/MAKEDEV -d /mnt/ec2-fs/dev -x zero
    mkdir /mnt/ec2-fs/proc
    mount -t proc none /mnt/ec2-fs/proc
    mkdir /mnt/ec2-fs/etc
    cat <<EOL > /mnt/ec2-fs/etc/fstab
/dev/sda1  /         ext3    defaults        1 1
/dev/sda2  /mnt      ext3    defaults        1 2
/dev/sda3  swap      swap    defaults        0 0
none       /dev/pts  devpts  gid=5,mode=620  0 0
none       /dev/shm  tmpfs   defaults        0 0
none       /proc     proc    defaults        0 0
none       /sys      sysfs   defaults        0 0
rpc_pipefs /var/lib/nfs/rpc_pipefs rpc_pipefs defaults 0 0
EOL
    echo "Created 10Gb disk image and filesystems"
}

doBaseAndSecondaryInstall() {
    echo "Creating Yum Confuration for Base install"
    mkdir -p /mnt/ec2-fs/sys/block
    mkdir -p /mnt/ec2-fs/var/
    mkdir -p /mnt/ec2-fs/var/log/
    mkdir -p /mnt/ec2-fs/var/lib/yum/
    touch /mnt/ec2-fs/var/log/yum.log
    cat <<EOL > /mnt/image/yum.conf
[main]
cachedir=/var/cache/yum
keepcache=0
debuglevel=2
logfile=/var/log/yum.log
distroverpkg=redhat-release
tolerant=1
exactarch=1
obsoletes=1
reposdir=/dev/null
gpgcheck=1
plugins=1

# Note: yum-RHN-plugin doesn't honor this.
metadata_expire=300

# Default.
# installonly_limit = 3

# CentOS-Base.repo
#
# This file uses a new mirrorlist system developed by Lance Davis for CentOS.
# The mirror system uses the connecting IP address of the client and the
# update status of each mirror to pick mirrors that are updated to and
# geographically close to the client.  You should use this for CentOS updates
# unless you are manually picking other mirrors.
#
# If the mirrorlist= does not work for you, as a fall back you can try the 
# remarked out baseurl= line instead.
#
#

[base]
name=CentOS-5 - Base
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=i386&repo=os
#baseurl=http://mirror.centos.org/centos/5/os/i386/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#released updates 
[updates]
name=CentOS-5 - Updates
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=i386&repo=updates
#baseurl=http://mirror.centos.org/centos/5/updates/i386/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#packages used/produced in the build but not released
[addons]
name=CentOS-5 - Addons
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=i386&repo=addons
#baseurl=http://mirror.centos.org/centos/5/addons/i386/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#additional packages that may be useful
[extras]
name=CentOS-5 - Extras
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=i386&repo=extras
#baseurl=http://mirror.centos.org/centos/5/extras/i386/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-5 - Plus
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=i386&repo=centosplus
#baseurl=http://mirror.centos.org/centos/5/centosplus/i386/
gpgcheck=1
enabled=0
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

# Name: RPMforge RPM Repository for Red Hat Enterprise 5 - dag
# URL: http://rpmforge.net/
[rpmforge]
name = Red Hat Enterprise 5 - RPMforge.net - dag
#baseurl = http://apt.sw.be/redhat/el5/en/$basearch/dag
mirrorlist = http://apt.sw.be/redhat/el5/en/mirrors-rpmforge
#mirrorlist = file:///etc/yum.repos.d/mirrors-rpmforge
enabled = 1
protect = 0
gpgkey = http://dag.wieers.com/packages/RPM-GPG-KEY.dag.txt
#gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmforge-dag
gpgcheck = 1
EOL
    echo "Running Yum"
    yum -c /mnt/image/yum.conf --installroot=/mnt/ec2-fs -y groupinstall Base
    echo "Finished Base install"
    echo "Starting Secondary install"
    yum -c /mnt/image/yum.conf --installroot=/mnt/ec2-fs -y install postfix openssh openssh-askpass openssh-clients openssh-server gcc* bison flex compat-libstdc++-296 subversion autoconf automake libtool compat-gcc-34-g77 sysstat rpm-build fping vim-common vim-enhanced pkgconfig elinks screen yum-utils rsyslog rpmforge-release dstat monit ifstat net-snmp
    yum -c /mnt/image/yum.conf --installroot=/mnt/ec2-fs -y erase sendmail
    yum -c /mnt/image/yum.conf --installroot=/mnt/ec2-fs -y clean packages
    cat <<EOL > /mnt/ec2-fs/etc/sysconfig/network
NETWORKING=yes
HOSTNAME=localhost.localdomain
EOL

    cat <<EOL > /mnt/ec2-fs/etc/sysconfig/network-scripts/ifcfg-eth0
ONBOOT=yes
DEVICE=eth0
BOOTPROTO=dhcp
EOL

    cat <<EOL >> /mnt/ec2-fs/etc/ssh/sshd_config
UseDNS  no
PermitRootLogin without-password
EOL

    echo "Finished Secondary install"
}

installKernelModules() {
	echo "Fetch Amazon EC2 kernel modules"
	curl -o /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz http://ec2-downloads.s3.amazonaws.com/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz
	echo "Installing EC2 kernel modules"
	tar -xzf /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz -C /mnt/ec2-fs/
	rm -fr /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz
}

doPostInstall() {
    echo "Performing (chrooted) Post install"
    mkdir -p /mnt/ec2-fs/tmp/
    touch /mnt/ec2-fs/etc/mtab
    cat <<'EOL' > /mnt/ec2-fs/tmp/post-install-script


echo "Starting Post install"
echo "127.0.0.1     localhost   localhost.localdomain" > /etc/hosts
authconfig --enableshadow --useshadow --enablemd5 --updateall

#fix '4gb seg fixup' Xen errors
cat <<'LDCONF' > /etc/ld.so.conf.d/libc6-xen.conf
# This directive teaches ldconfig to search in nosegneg subdirectories
# and cache the DSOs there with extra bit 0 set in their hwcap match
# fields.  In Xen guest kernels, the vDSO tells the dynamic linker to
# search in nosegneg subdirectories and to match this extra hwcap bit
# in the ld.so.cache file.
hwcap 0 nosegneg

LDCONF
/sbin/ldconfig -v

echo "Disabling TTYs"
perl -p -i -e 's/(.*tty2)/#\1/' /etc/inittab
perl -p -i -e 's/(.*tty3)/#\1/' /etc/inittab
perl -p -i -e 's/(.*tty4)/#\1/' /etc/inittab
perl -p -i -e 's/(.*tty5)/#\1/' /etc/inittab
perl -p -i -e 's/(.*tty6)/#\1/' /etc/inittab
perl -p -i -e 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config 
perl -p -i -e 's/#ClientAliveInterval 0/ClientAliveInterval 60/' /etc/ssh/sshd_config
perl -p -i -e 's/#ClientAliveCountMax 3/ClientAliveCountMax 240/' /etc/ssh/sshd_config

echo "Installing getsshkey"
cat <<'SSH' >/etc/init.d/getsshkey
#!/bin/bash
# chkconfig: 4 11 11
# description: This script fetches the ssh key early. \
#

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
[ -r /etc/sysconfig/network ] && . /etc/sysconfig/network

# Check that networking is up.
[ "${NETWORKING}" = "no" ] && exit 1

start() {
  if [ ! -d /root/.ssh ] ; then
          mkdir -p /root/.ssh
          chmod 700 /root/.ssh
  fi
  # Fetch public key using HTTP
  curl -f http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key > /tmp/my-key
  if [ $? -eq 0 ] ; then
          cat /tmp/my-key >> /root/.ssh/authorized_keys
          chmod 600 /root/.ssh/authorized_keys
          rm /tmp/my-key
  fi
  # or fetch public key using the file in the ephemeral store:
  if [ -e /mnt/openssh_id.pub ] ; then
          cat /mnt/openssh_id.pub >> /root/.ssh/authorized_keys
          chmod 600 /root/.ssh/authorized_keys
  fi
}

stop() {
  echo "Nothing to do here"
}

restart() {
  stop
  start
}

# See how we were called.
case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    restart
    ;;
  *)
    echo $"Usage: $0 {start|stop}"
    exit 1
esac

exit $?

SSH
chmod +x /etc/init.d/getsshkey

echo "Modifying Services"
chkconfig --add postfix
chkconfig --add getsshkey
chkconfig --level 4 rsyslog on
chkconfig --level 4 getsshkey on
chkconfig --level 4 postfix on 
chkconfig --level 4 psacct on
chkconfig --level 4 smartd off
chkconfig --level 4 anacron off
chkconfig --level 4 apmd off
chkconfig --level 4 acpid off
chkconfig --level 4 auditd off
chkconfig --level 4 irqbalance off
chkconfig --level 4 mdmpd off
chkconfig --level 4 portmap off
chkconfig --level 4 nfslock off
chkconfig --level 4 cpuspeed off
chkconfig --level 4 cups off
chkconfig --level 4 autofs off
chkconfig --level 4 bluetooth off
chkconfig --level 4 rpcidmapd off
chkconfig --level 4 rpcsvcgssd off
chkconfig --level 4 rpcgssd off
chkconfig --level 4 pcscd off
chkconfig --level 4 gpm off
chkconfig --level 4 hidd off
chkconfig --level 4 yum-updatesd off
chkconfig --del acpid
chkconfig --del auditd
chkconfig --del irqbalance
chkconfig --del mdmpd
chkconfig --del NetworkManager
chkconfig --del NetworkManagerDispatcher
chkconfig --del dhcdbd
chkconfig --del dund
chkconfig --del firstboot
chkconfig --del irda
chkconfig --del apmd
chkconfig --del smartd
chkconfig --del kudzu
chkconfig --del hidd
chkconfig --del gpm
chkconfig --del pcscd
chkconfig --del bluetooth
chkconfig --del cpuspeed
chkconfig --del cups
chkconfig --del rdisc
chkconfig --del readahead_later
chkconfig --del wpa_supplicant
chkconfig --del pand
chkconfig --del netplugd

echo "Setting up Bash environment for root"
cat <<'EOF'> /root/.bashrc
# .bashrc

# User specific aliases and functions

alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias vi='vim'

# Source global definitions
if [ -f /etc/bashrc ]; then
        . /etc/bashrc
fi

EOF

cat <<'EOF'> /root/.bash_profile
# .bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
        . ~/.bashrc
fi

# User specific environment and startup programs

PATH=$PATH:$HOME/bin

export PATH
unset USERNAME

EOF

cat <<'EOF'> /root/.bash_logout
# ~/.bash_logout

clear

EOF

touch /root/.bash_logout

cat <<'EOF'> /usr/local/sbin/update-modules.sh
#!/bin/bash

# Update EC2 kernel modules autmatically.
modules_file="ec2-modules-`uname -r`-`uname -m`.tgz"
[ -f $modules_file ] && rm -f $modules_file
echo "Attempting kernel modules update from S3"
(wget http://s3.amazonaws.com/ec2-downloads/$modules_file && echo "Retreived $modules_file from S3" || echo "Unable to retreive $modules_file from S3")|logger -s -t "ec2"
(tar xzf $modules_file -C / && depmod -a && echo "Updated kernel modules from S3")|logger -s -t "ec2"

EOF

chmod +x /usr/local/sbin/update-modules.sh

cat <<'EOF'> /usr/local/sbin/update-tools.sh
#!/bin/bash

# Requires ruby package to be installed -install will fail but instance will boot without
# Update ec2-ami-tools autmatically.
[ -f ec2-ami-tools.noarch.rpm ] && rm -f ec2-ami-tools.noarch.rpm
echo "Attempting ami-utils update from S3"
(wget http://s3.amazonaws.com/ec2-downloads/ec2-ami-tools.noarch.rpm && echo "Retreived ec2-ami-tools from S3" || echo "Unable to retreive ec2-ami-tools from S3")|logger -s -t "ec2"
(rpm -Uvh ec2-ami-tools.noarch.rpm && echo "Updated ec2-ami-tools from S3" || echo "ec2-ami-tools already up to date")|logger -s -t "ec2"

EOF

chmod +x /usr/local/sbin/update-tools.sh

cat <<'EOF'> /etc/rc.local
#!/bin/sh
#
# This script will be executed *after* all the other init scripts.
# You can put your own initialization stuff in here if you don't
# want to do the full Sys V style init stuff.

# Stuff we want to do once at launch and never again:
if [ -f "/root/firstrun" ]; then
    # Randomise root password to avoid common password across instances:
    dd if=/dev/urandom count=50|md5sum|passwd --stdin root

    # Update AMI tools to the latest version:
    [ -x "/usr/local/sbin/update-tools.sh" ] && /usr/local/sbin/update-tools.sh

    # Try to find kernel modules matching current kernel:
    [ -x "/usr/local/sbin/update-modules.sh" ] && /usr/local/sbin/update-modules.sh

    # Some kernels use xvc0 as their serial console device:
    if [ -c /dev/xvc0 ]; then
        if ! grep 'co:2345:respawn:/sbin/agetty xvc0 9600' /etc/inittab; then
                echo 'co:2345:respawn:/sbin/agetty xvc0 9600 vt100' >> /etc/inittab
                echo 'xvc0' >> /etc/securetty
                kill -1 1
        fi
    fi

    # Ensure devpts is mounted to prevent ssh hang-ups
    mount | grep devpts > /dev/null
    if [ $? -ne 0 ] ; then
        devpts="none   /dev/pts   devpts  gid=5,mode=620 0 0"
        ( grep -v "\#" /etc/fstab | grep devpts > /dev/null ) || echo $devpts >> /etc/fstab
        mount -a
    fi
    rm -f /root/firstrun
fi

touch /var/lock/subsys/local
# Update the ec2-ami-tools
/usr/local/sbin/update-tools.sh

# =*Output ssh host keys to console*=
[ -f /etc/ssh/ssh_host_key ] || (ssh-keygen -f /etc/ssh/ssh_host_key -t rsa1 -C 'host' -N '' | logger -s -t "ec2")
[ -f /etc/ssh/ssh_host_rsa_key ] || (ssh-keygen -f /etc/ssh/ssh_host_rsa_key -t rsa  -C 'host' -N '' | logger -s -t "ec2")
[ -f /etc/ssh/ssh_host_dsa_key ] || (ssh-keygen -f /etc/ssh/ssh_host_dsa_key -t dsa  -C 'host' -N '' | logger -s -t "ec2")

echo "-----BEGIN SSH HOST KEY FINGERPRINTS-----" |logger -s -t "ec2"
ssh-keygen -l -f /etc/ssh/ssh_host_key.pub |logger -s -t "ec2"
ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub |logger -s -t "ec2"
ssh-keygen -l -f /etc/ssh/ssh_host_dsa_key.pub |logger -s -t "ec2"
echo "-----END SSH HOST KEY FINGERPRINTS-----"   |logger -s -t "ec2"

EOF

exit 

EOL

    chmod +x /mnt/ec2-fs/tmp/post-install-script
    chroot /mnt/ec2-fs/ /tmp/post-install-script
    echo "Cleaning up Image"
    echo "$IMAGE_NAME version $IMAGE_VERSION" > /mnt/ec2-fs/etc/t3-ami-release
    echo "Finished Post Install"
}

bundleVolume() {
    sync
    echo "Bundling Volume"
    mkdir -p /mnt/tmp
    if [ -z "$KERNEL_ID" ]; then
      ec2-bundle-vol -v /mnt/ec2-fs -d /mnt/tmp -p $IMAGE_NAME -k $EC2_PRIVATE_KEY -c $EC2_CERT -u $AWS_ACCOUNT_NUMBER --fstab /mnt/ec2-fs/etc/fstab -r i386
    else 
      ec2-bundle-vol -v /mnt/ec2-fs -d /mnt/tmp -p $IMAGE_NAME -k $EC2_PRIVATE_KEY -c $EC2_CERT -u $AWS_ACCOUNT_NUMBER --fstab /mnt/ec2-fs/etc/fstab -r i386 --kernel $KERNEL_ID
    fi
    echo "Finished Bundling Volume"

}

uploadBundle() {
    echo "Uploading Bundle"
    ec2-upload-bundle -b $AWS_BUCKET -m /mnt/tmp/$IMAGE_NAME.manifest.xml -a $AWS_ACCESS_KEY_ID -s $AWS_SECRET_ACCESS_KEY --retry 5
    echo "Finished Uploading Bundle"
}

cleanup() {
    echo "Starting Cleanup"
    echo "Unmounting /mnt/ec2-fs"
    umount /mnt/ec2-fs/proc
    umount -d /mnt/ec2-fs
    rm -fr /mnt/image/
    rm -fr /mnt/ec2-fs
    rm -fr /mnt/tmp
    echo "File System Cleaned"
    echo "Done! Put a fork in it!"
}

makeImageAndFilesystems
doBaseAndSecondaryInstall
installKernelModules
doPostInstall
bundleVolume
uploadBundle
cleanup

