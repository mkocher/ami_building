#!/bin/bash -e

# ami-0a59bb63 seems to be a good 64bit 5.4 ami     # ec2-run-instances ami-0a59bb63 -k mine2 -t m1.large
# ami-08f41161  seems to be a good 32bit centos ami # ec2-run-instances ami-08f41161 -k mine2 -t c1.medium

# export architecture="i386"
export architecture="x86_64"
export IMAGE_NAME=centos5-$architecture-2
export IMAGE_VERSION=alpha1
# For vmlinuz-2.6.18-xenU-ec2-v1.0.i386
# export KERNEL_ID=aki-9b00e5f2       #32bit - doesn't seem to be neccessary, does work.
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
  mkdir /mnt/ec2-fs/dev/pts
  mkdir /mnt/ec2-fs/proc
  mount -t proc none /mnt/ec2-fs/proc
  mkdir /mnt/ec2-fs/etc
  
  echo "Created 10Gb disk image and filesystems"
}

create32Fstab() {
  cat <<'EOL' > /mnt/ec2-fs/etc/fstab
/dev/sda1  /         ext3    defaults        1 1
/dev/sda2  /mnt      ext3    defaults        1 2
/dev/sda3  swap      swap    defaults        0 0
none       /dev/pts  devpts  gid=5,mode=620  0 0
none       /dev/shm  tmpfs   defaults        0 0
none       /proc     proc    defaults        0 0
none       /sys      sysfs   defaults        0 0
rpc_pipefs /var/lib/nfs/rpc_pipefs rpc_pipefs defaults 0 0
EOL
}

create64Fstab() {
  cat <<'EOL' > /mnt/ec2-fs/etc/fstab
/dev/sda1  /         ext3 defaults 1 1
/dev/sdb   /mnt      ext3 defaults 1 2
none       /dev/pts  devpts  gid=5,mode=620  0 0
none       /dev/shm  tmpfs   defaults        0 0
none       /proc     proc    defaults        0 0
none       /sys      sysfs   defaults        0 0
EOL
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
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=$architecture&repo=os
#baseurl=http://mirror.centos.org/centos/5/os/$architecture/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#released updates 
[updates]
name=CentOS-5 - Updates
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=$architecture&repo=updates
#baseurl=http://mirror.centos.org/centos/5/updates/$architecture/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#packages used/produced in the build but not released
[addons]
name=CentOS-5 - Addons
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=$architecture&repo=addons
#baseurl=http://mirror.centos.org/centos/5/addons/$architecture/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#additional packages that may be useful
[extras]
name=CentOS-5 - Extras
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=$architecture&repo=extras
#baseurl=http://mirror.centos.org/centos/5/extras/$architecture/
gpgcheck=1
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

#additional packages that extend functionality of existing packages
[centosplus]
name=CentOS-5 - Plus
mirrorlist=http://mirrorlist.centos.org/?release=5&arch=$architecture&repo=centosplus
#baseurl=http://mirror.centos.org/centos/5/centosplus/$architecture/
gpgcheck=1
enabled=0
gpgkey=http://mirror.centos.org/centos/RPM-GPG-KEY-CentOS-5

EOL
  echo "Running Yum"
  yum -c /mnt/image/yum.conf --installroot=/mnt/ec2-fs -y groupinstall Base
  echo "Finished Base install"
  echo "Starting Secondary install"
  yum -c /mnt/image/yum.conf --installroot=/mnt/ec2-fs -y install openssh openssh-clients openssh-server
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

install32KernelModules() {
  echo "Fetch Amazon EC2 kernel modules"
  curl -o /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz http://ec2-downloads.s3.amazonaws.com/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz
  echo "Installing EC2 kernel modules"
  tar -xzf /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz -C /mnt/ec2-fs/
  rm -fr /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-i686.tgz
}

install64KernelModules() {
  echo "Fetch Amazon EC2 kernel modules"
  curl -o /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-x86_64.tgz http://ec2-downloads.s3.amazonaws.com/ec2-modules-2.6.18-xenU-ec2-v1.0-x86_64.tgz
  echo "Installing EC2 kernel modules"
  tar -xzf /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-x86_64.tgz -C /mnt/ec2-fs/
  rm -fr /tmp/ec2-modules-2.6.18-xenU-ec2-v1.0-x86_64.tgz
}

setLdConfPatchStringFor32bit() {
  cat <<'LDCONF_PATCH' >> /mnt/ld_conf_patch
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
LDCONF_PATCH
}

doPostInstall() {
  echo "Performing (chrooted) Post install"
  mkdir -p /mnt/ec2-fs/tmp/
  touch /mnt/ec2-fs/etc/mtab
  cat <<'EOL' > /mnt/ec2-fs/tmp/post-install-script

echo "Starting Post install"
echo "127.0.0.1     localhost   localhost.localdomain" > /etc/hosts
authconfig --enableshadow --useshadow --enablemd5 --updateall

EOL
  test -f /mnt/ld_conf_patch && cat /mnt/ld_conf_patch >> /mnt/ec2-fs/tmp/post-install-script

  cat <<'EOL' >> /mnt/ec2-fs/tmp/post-install-script
echo "/sbin/MAKEDEV /dev/urandom" >> /etc/rc.sysinit
echo "/sbin/MAKEDEV /dev/random" >> /etc/rc.sysinit
echo "/sbin/MAKEDEV /dev/sdc" >> /etc/rc.sysinit
echo "/sbin/MAKEDEV /dev/sdc1" >> /etc/rc.sysinit
echo "/sbin/MAKEDEV /dev/sdc2" >> /etc/rc.sysinit
echo "/sbin/MAKEDEV /dev/ptmx" >> /etc/rc.sysinit


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
chkconfig --add getsshkey
chkconfig --level 4 getsshkey on
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
    ec2-bundle-vol -v /mnt/ec2-fs -d /mnt/tmp -p $IMAGE_NAME -k $EC2_PRIVATE_KEY -c $EC2_CERT -u $AWS_ACCOUNT_NUMBER --fstab /mnt/ec2-fs/etc/fstab -r $architecture
  else 
    ec2-bundle-vol -v /mnt/ec2-fs -d /mnt/tmp -p $IMAGE_NAME -k $EC2_PRIVATE_KEY -c $EC2_CERT -u $AWS_ACCOUNT_NUMBER --fstab /mnt/ec2-fs/etc/fstab -r $architecture --kernel $KERNEL_ID
  fi
  echo "Finished Bundling Volume"

}

uploadBundle() {
  echo "Uploading Bundle"
  ec2-upload-bundle -b $AWS_BUCKET -m /mnt/tmp/$IMAGE_NAME.manifest.xml -a $AWS_ACCESS_KEY_ID -s $AWS_SECRET_ACCESS_KEY --retry 5
  echo "Finished Uploading Bundle"
  echo "to register, run: ec2-register $AWS_BUCKET/$IMAGE_NAME.manifest.xml"
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

if [ "$architecture" == "i386" ]; then
  echo "Building i386 AMI"
  updateEc2AmiTools
  makeImageAndFilesystems
  create32Fstab
  doBaseAndSecondaryInstall
  install32KernelModules
  setLdConfPatchStringFor32bit
  doPostInstall
  bundleVolume
  uploadBundle
  # cleanup
elif [ "$architecture" == "x86_64" ]; then
  echo "Building x86_64 AMI"
  updateEc2AmiTools
  makeImageAndFilesystems
  create64Fstab
  doBaseAndSecondaryInstall
  install64KernelModules
  doPostInstall
  bundleVolume
  uploadBundle
  # cleanup
else
  echo "Please set your architecture to i386 or x86_64"
  exit 1
fi