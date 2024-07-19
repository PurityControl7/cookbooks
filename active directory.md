# Active Directory example

Imagine we've successfully obtained some useful information using Responder. Key elements we've acquired include:

- The target’s Windows account.
- The domain name.
- The target machine’s name.
- Most importantly, the NTLM challenge-response.

For now, our primary focus is the NTLM response, as it contains a hash derived from the password. We will use John The Ripper to crack this hash with a wordlist of previously cracked passwords:

```
root@AttackServer:~# john -w wordlists.txt pass.txt
```

-w wordlists.txt specifies the wordlist file containing possible passwords, and pass.txt is the file containing the NTLM response hashes to be cracked.

As stated in my materials, <em>in a corporate environment Windows machines are typically interconnected to share resources and settings. This interconnection is managed using Windows Active Directory.</em>

<em>The root node of Windows Active Directory is called a Forest. Its primary purpose is to contain domains (groups of machines and users) that share similar configurations.</em>

<em>Each domain can be further divided into Organizational Units (OUs). The first domain in a forest is known as the primary domain.</em>

<em>Each domain follows its own policies regarding password strength, update schedules, user accounts, machines, etc.</em>

<em>A domain controller is a Windows machine that controls and manages a specific domain. It acts as the central hub that resources rely on to make decisions or poll new settings from. The larger the network, the more domain controllers are required to scale up performance.</em>

<em>Windows machines connected to a domain can have two types of users:</em>

- <em>Local users whose password hashes are stored locally on the server.</em>
- <em>Domain users whose password hashes are stored on the domain controller.</em>

<em>A domain user is not restricted to a single workstation and can connect to all workstations within the domain unless explicitly prohibited from doing so.</em>

(note: this brief introduction has been borrowed from <em>How to Hack Like a GOD: Master the secrets of Hacking through real life scenarios</em>, which serves as framework and inspiration for some of these cookbooks).

And now just a quick digression for the sake of completeness:

While NTLM (NT LAN Manager) was widely used in earlier versions of Windows for authentication purposes, it has largely been replaced by the more secure Kerberos protocol in later versions. NTLM uses a challenge-response mechanism for authentication, which, while effective, is less secure compared to modern standards.

Kerberos, on the other hand, employs a ticket-based system, which enhances security by reducing the risk of replay attacks and improving the overall efficiency of the authentication process. Kerberos relies on a trusted third party, the Key Distribution Center (KDC), to issue tickets that grant access to services without repeatedly transmitting passwords over the network.

Despite the shift to Kerberos, NTLM is still supported for backward compatibility and is often encountered in various scenarios, making it essential to understand both protocols.

So, we have cracked the hash and gained some credentials. What's next?

To remotely execute commands on a Windows machine, we need at least one of these three network conditions:

1. Remote Desktop Protocol (RDP) – Port 3389:

RDP allows for a graphical interactive session on the target machine using programs like mstsc on Windows or rdesktop/remmina on Linux. This is the go-to option for easy remote connection. However, it's worth noting that RDP connections generate detailed logs, making it easier for investigators to pinpoint the exact time and nature of a breach.

2. Remote Procedure Calls (RPC) – Ports 135 and 49152-65535 (or 5000-6000 on Windows 2003):

RPC services allow administrators to remotely execute functions and procedures on machines. This includes several services that enable code execution. RPC is often preferred for command execution due to its versatility and the fact that it generally leaves fewer traces compared to RDP sessions. This makes it a less conspicuous method for remote command execution.

3. Remote PowerShell (WinRM) – Ports 5985-5986:

The WinRM service accepts remote PowerShell commands from admin users. This method is particularly powerful for automation and scripting purposes, allowing for efficient management and control over remote systems. Like RDP, WinRM also logs activities, but it provides a robust way to manage and configure Windows systems remotely.

Each of these methods has its use cases and security implications. Understanding the logging and traceability of each method is crucial for both attackers and defenders.

The scenario described in the aforementioned book focuses on command line execution via RPC. I will re-iterate the key points, add some extra comments as needed, and reflect upon what I have learned from it.

We are attempting to use wmiexec.py to execute commands remotely on a Windows machine with the following command:

```
root@backdoor:# wmiexec.py username:Password123\@192.168.1.25
```

However, we encounter an access denial error:

```
Impact v0.9.15 – Copyright 2002-2016 Core Security Technologies
[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

This suggests that the compromised user does not have sufficient privileges on the target machine to perform remote command execution.

Some key points about wmiexec.py:

This is a tool used for executing commands remotely on Windows machines via the Windows Management Instrumentation (WMI) service.

Usage: It requires specifying the username and password (username:Password123) of an account that has permissions to execute commands on the remote system.

Errors: When wmiexec encounters an access denial (rpc_s_access_denied), it typically means that the user account used lacks the necessary permissions. This could be due to restrictions on the remote system's security settings or the user account's privileges.

Considerations: To resolve access issues, ensure that the specified user account has sufficient permissions, such as being a member of the Administrators group or having appropriate WMI access rights on the target machine.
	
The next logical step would be looking for possible network shares on the workstation:

```
root@backdoor:# smbclient -L 192.168.1.25 -U DOMAIN\\username%Password123
```

Here's what each part of the command does:

-L 192.168.1.25: This option tells smbclient to list (or enumerate) shares on the specified IP address (192.168.1.25), which is typically a Windows file share or print share server.

-U DOMAIN\\username%Password123: This specifies the username (username) and password (Password123) for authentication. The DOMAIN\\ prefix indicates the domain to which the user belongs.

Some key points about smbclient:

Purpose: smbclient is a command-line tool used to interact with SMB/CIFS (Server Message Block / Common Internet File System) shares on Windows and Samba servers.

Usage: The -L option is specifically used to list available shares on a remote server. It requires valid credentials (-U DOMAIN\\username%Password123) to authenticate and access the server.

Authentication: The format DOMAIN\\username%Password123 provides the necessary credentials for authentication. It's important to ensure that the specified user account (username) has sufficient permissions to access the shares on the target machine (192.168.1.25).

Security Considerations: When using smbclient, ensure that credentials are handled securely. Avoid transmitting sensitive information over unsecured networks and configure SMB/CIFS settings securely to prevent unauthorized access.

Output: Upon successful authentication, smbclient will list available shares on the target machine (192.168.1.25). If authentication fails, it may display an error indicating access denied or authentication failure.

After an unsuccessful attempt to find useful shares on the initial target, we proceed to another target identified earlier:

```
root@backdoor:# nmblookup SV0078
10.10.20.78 SV0078<00>
```

nmblookup is used to query NetBIOS names and map them to IP addresses. In this case, it resolves SV0078 to the IP address 10.10.20.78.

After that we are performing an nmap scan for additional targets on the network:

```
root@backdoor:# nmap 10.10.20.0/24 -p 445 -oA 445_servers
```

-p 445: Specifies that the scan will target TCP port 445, which is used by the SMB (Server Message Block) protocol on Windows machines.

-oA 445_servers: Outputs the scan results in three formats (nmap, gnmap, and xml) to files prefixed with 445_servers.

Scan results:

```
Nmap scan report for 10.10.20.78
PORT     STATE    SERVICE
445/tcp  open     microsoft-ds

Nmap scan report for 10.10.20.199
PORT     STATE    SERVICE
445/tcp  open     microsoft-ds
```

The scan identifies two machines (10.10.20.78 and 10.10.20.199) with port 445/tcp (Microsoft Directory Service) open. This indicates they are running SMB, which could potentially host file shares and provide avenues for further exploration or exploitation.

Some notes about network discovery with nmap:

By scanning the /24 subnet (10.10.20.0/24) specifically targeting port 445/tcp, we quickly identify machines that have SMB (microsoft-ds) services running and accessible. Port 445 being open indicates potential Windows systems that could be targeted for further investigation or exploitation.

Target Identification: The results of the nmap scan (10.10.20.78 and 10.10.20.199 with open 445/tcp) provide a narrowed-down list of machines that are likely candidates for further penetration testing or reconnaissance activities.

There is one small caveat in this approach, though: what if we encounter a larger number of potential targets? This is where a little bit of scripting comes in handy. The script here is designed to automate the process of listing shares (smbclient -L) on multiple target machines specified in an array.

```
#!/bin/bash
## Array containing all viable targets
declare -a arr=("10.10.20.78" "10.10.20.199" "10.10.20.56"
"10.10.20.41" "10.10.20.25" "10.10.20.90" "10.10.20.71"
"10.10.20.22" "10.10.20.38" "10.10.20.15")
## now loop through the above array
for i in "${arr[@]}"
do
    echo $i
    ## List shares
    smbclient -L $i -U DOMAIN\\user%Password123!
    echo "--"
done
```

Quick breakdown:

Array Declaration ```(declare -a arr=("10.10.20.78" ... "10.10.20.15")```: Defines an array named arr containing IP addresses of target machines.

For Loop ```(for i in "${arr[@]}")```: Iterates over each element ```$i``` in the arr array. In Bash scripting, the @ character in the context of an array ```(like "${arr[@]}")``` is used to expand all elements of the array.

```"${arr[@]}"```: Expands to all elements of the array arr. Each element is treated as a separate word in the iteration, regardless of spaces or other delimiters within the elements.

For example, if your array arr contains elements "10.10.20.78", "10.10.20.199", etc., ```"${arr[@]}"``` will expand to "10.10.20.78" "10.10.20.199" ... and so on, allowing the for loop to iterate over each IP address individually.

So, in the script:

```
for i in "${arr[@]}"
do
    echo $i
    ## List shares
    smbclient -L $i -U DOMAIN\\user%Password123
    echo "--"
done
```

The for i in ```"${arr[@]}"``` line ensures that ```$i``` iterates over each element (IP address) in the arr array, executing the subsequent commands (echo, smbclient, echo "--") for each IP address in turn.

Echo ```(echo $i)```: Prints the current IP address being processed.

SMB Client Command ```(smbclient -L $i -U GBSHOP\\dvoxon%Bird123!)```:

```-L $i```: Lists shares on the target machine specified by the current value of ```$i```.

```-U DOMAIN\\user%Password123```: Specifies the username and password for authentication against the SMB server on the target machine ```($i)```.

Echo Separator (echo "--"): Prints a separator line after listing shares for each target.

Also, don't forget to do this simple step before executing the script:

```
root@backdoor:# chmod +x loop.sh && ./loop.sh
```

We've discovered some potentially interesting shares on a machine (10.10.20.78), but our current low-privileged account prevents you from accessing them:

```
root@backdoor:# smbclient -c "ls" //10.10.20.78/CORP$ -U DOMAIN\\user%Password123
WARNING: The “syslog” option is deprecated
Domain[DOMAIN] OS=[Windows Server 2012 R2 Datacenter Evaluation]
NT_STATUS_ACCESS_DENIED listing \*
```

Notes:

-c "ls": Executes the ls command within the smbclient session, which lists files and directories.

//10.10.20.78/CORP$: Specifies the UNC path to the share you're attempting to access (CORP$) on the machine with IP 10.10.20.78.

This means we need to somehow achieve higher privileges. Our first target from the loop is the SV0199 (10.10.20.199) machine hosting the SYSVOL share. SYSVOL is a critical folder on domain controllers in Windows environments, containing policies, scripts, and other important domain-related information.

Next step would look like this:

```
root@backdoor:# smbclient -U DOMAIN\\user%Password //10.10.20.199/SYSVOL -c "recurse; ls"
```

DOMAIN\\user: The username with domain prefix (double backslash is used to escape the backslash).

//10.10.20.199/SYSVOL: Specifies the UNC path to the share you want to access. SYSVOL is the name of the share on the target machine.

recurse: Enables recursive directory listing, meaning it will list directories and their contents recursively.

ls: Lists files and directories in the specified share.

After this command smbclient returns several XML files hosted in the SYSVOL folder on a domain controller. These XML files, such as groups.xml and ScheduledTasks.xml, are critical for the domain's configuration and management.

Importance of XML Files:

groups.xml: This file is used by domain controllers to define and manage group memberships and configurations. It specifies which users are members of which groups and can include settings for administrative privileges. For example, groups.xml may contain configurations to set up local administrator accounts on new workstations across the domain. This makes it a valuable target for extracting credentials, as it may store sensitive information related to account creation and management.

ScheduledTasks.xml: This file contains configurations for scheduled tasks that are deployed across domain machines. It automates various administrative tasks and ensures that certain scripts or programs are executed on a predefined schedule.

Password Storage and Security:

Domain controllers use these XML files to enforce configurations and deploy settings to all domain-connected machines. As part of this deployment process, critical information, including passwords for newly created accounts, might be stored in these XML files. Since these files are read by all workstations, any domain user with access to them could potentially retrieve this sensitive information. This practice, while convenient for centralized management, poses a significant security risk if the XML files are not adequately protected.

By understanding the role of these XML files and their contents, attackers can target them to gain access to credentials and configurations that are pivotal for domain management. Proper security measures should be in place to protect these files from unauthorized access to prevent such risks.

Let's try getting the groups.xml file:


```
smbclient //10.10.20.199/SYSVOL -U DOMAIN\\user%Password123 -c "get \DOMAIN.CORP\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\USER\Preferences\Groups\groups.xml"
```

-c "get \DOMAIN.CORP\...\groups.xml": Executes the get command to download the groups.xml file from the specified path in the SYSVOL share.

The groups.xml file contains an obfuscated password for a local admin account, e.g., wk_admin. Using gpp-decrypt, we reverse the encryption (AES-256) to obtain the clear-text password (Microsoft unintentionally published the key on its website a few years ago). In this case, the tool reveals 7stringsRockHell* as the decrypted password for the wk_admin account.

```
root@AttackServer:# gpp-decrypt
6gKTm/tvgxptRmOTeB4L1L6KcfLrPMwW8w6uvbqEvhyGbFtp6sSBueVYpTS+ZcIU
```

Now that we’ve obtained a valid local administrator account, we can proceed to remotely execute commands on the workstation. We will use the wmiexec.py tool to do this. A simple command like whoami can verify our control over the system.

```
root@backdoor:# wmiexec.py DOMAIN\\wk_admin:7stringsRockHell*@10.10.20.199
```

Note: if you encounter issues with special characters or authentication, ensure that the password is correctly formatted and try enclosing it in single quotes (') if necessary:

```
root@backdoor:# wmiexec.py DOMAIN\\wk_admin:'7stringsRockHell*'@10.10.20.199
```

By running the whoami command via wmiexec.py, we can confirm that we have administrative control over the workstation. The command will display the user account currently running the command, verifying that this account has the necessary privileges.

Note: UAC is a security feature in Windows designed to prevent unauthorized changes to the system. It prompts for confirmation when actions that could affect system settings are performed. However, the main local administrator account is usually exempt from UAC prompts by default. This means commands executed using this account typically do not trigger UAC.
