# Citrix example

*Note: This chapter is based on demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios", starting from page 64.*

Citrix is a powerful virtualization solution that many companies use to address a significant challenge: “How do I provide a secure, uniform, and controlled environment for 40,000 users without creating 40,000 network holes?” Citrix allows users to access applications running on remote servers while making them appear as if they're running locally on the user’s workstation.

At its core, Citrix functions like a specialized version of Remote Desktop Protocol (RDP) that is confined to a single application rather than a full desktop. This restricted access model opens up various possibilities for exploitation.

For instance, if you can run something other than just the intended application on the remote server—like a command-line interface (cmd.exe) or File Explorer (explorer.exe)—you might gain access to other users’ files and potentially sensitive information. This can lead to discovering valuable data or further vulnerabilities.

*Additional Insights on Citrix in Penetration Testing:*

- Session Hijacking: If you can obtain a session token or credentials, you might hijack an active Citrix session, gaining access to whatever the user has access to.

- Application Enumeration: Use tools to enumerate available applications and services within the Citrix environment. This could reveal additional attack vectors or poorly secured applications.

- Privilege Escalation: Look for ways to escalate your privileges within the Citrix environment. Misconfigurations or vulnerabilities might allow you to execute commands or access files with higher privileges.

- Network Traffic Analysis: Citrix sessions are often encrypted, but analyzing network traffic might still reveal useful information, such as session tokens or patterns that could be exploited.

- Configuration Weaknesses: Often, Citrix deployments have configuration issues or outdated software versions that can be exploited. Identifying these weaknesses can provide entry points for further attacks.

*Note: some useful Citrix keyboard shortcuts:*

    Ctrl + F1: Opens the Citrix Task Manager on the remote server.
    Ctrl + F2: Opens the Citrix Connection Center.
    Ctrl + F3: Opens the Citrix Session Preferences.
    Ctrl + Alt + Break: Switches between full-screen and windowed mode.
    Ctrl + Alt + Del: Opens the Windows Security screen (e.g., to change password, access Task Manager).
    Ctrl + Alt + Insert: Equivalent to Ctrl + Alt + Del but within the remote session.
    Alt + Tab: Switches between open applications within the Citrix session.
    Ctrl + Alt + Home: Opens the Citrix toolbar (useful for accessing session controls).
    Ctrl + Alt + End: Opens the Task Manager on the remote session.
    Ctrl + Alt + Left/Right Arrow: Switches between virtual desktops in Citrix sessions.

And now back to our hypothetical scenario:

After compromising a local user account and escalating privileges as described in the chapter on "Active Directory," we log into Citrix Receiver and connect to the sales application. Initially, we can only access limited sales data from a single store—hardly what we aim for. Our goal is to access sales data from every store in the country.

Enter the hidden gem: the calculator app. Since this app runs on the remote server, any commands or hotkeys we use are executed on the server itself. For example, Citrix allows the use of the Ctrl+F1 hotkey to launch the Task Manager. Unfortunately, this attempt is blocked due to security hardening that restricts the spawning of unauthorized applications.

Not to worry—there are alternative methods to explore. One useful trick is to locate a URL in a hidden menu. Clicking this URL will open a browser session on the server, often Internet Explorer. The help menu in any application is a good place to look for such URLs.

When Internet Explorer launches, we discover that while Task Manager is restricted, Internet Explorer is accessible. This presents an opportunity: we can use it to browse system files. By issuing the “CTRL+O” command and entering ‘C:’ in the address bar, we attempt to navigate to the server’s file system. However, this direct method is blocked.

Instead, we use the shared folder path ‘\127.0.0.1\C$’ to access the ‘C:’ drive. This allows us to browse the server’s files and dig deeper into the system. We search for files with common extensions such as .vba, .vbs, .bat, and .ps1, which might contain credentials. However, we find no relevant files in directories like ‘C:\temp’ or other accessible locations.

We also check for deployment files like ‘unattend.xml’ and ‘sysprep.xml,’ which sometimes contain local admin credentials. Despite our efforts, the system appears well-secured. Our attempt to open a command-line interface (cmd.exe) results in an error message stating, “your system administrator has blocked this program,” indicating further restrictions in place.

The error encountered when trying to launch cmd.exe mirrors the issue we faced with Task Manager. A quick search reveals that this restriction is likely due to AppLocker, a Windows feature that controls which applications users can run. AppLocker enforces application whitelisting and can restrict executables based on several criteria:

- Executable’s Location: AppLocker can restrict applications based on their directory. For instance, executables located in common directories like C:\Windows\System32 are often whitelisted by default. Since cmd.exe resides in this directory, location-based restrictions are not the issue here.

- Executable’s Publishing Certificate: AppLocker can also restrict applications based on their digital signature. cmd.exe, being a Microsoft-signed utility, is typically allowed by default. Therefore, it's unlikely that AppLocker is blocking cmd.exe based on its certificate.

- Executable’s Fingerprint or Hash: This is the most probable cause. AppLocker can block applications based on their hash values. Every executable file has a unique hash that AppLocker can use to determine whether it’s allowed to run. If cmd.exe’s hash has been blacklisted or if specific policies are configured to disallow certain hashes, this could explain why we’re unable to launch the application.

If cmd.exe is restricted due to AppLocker policies or other security measures, there are several alternative tools and methods that might not be subject to the same restrictions. Here are some potential alternatives, along with explanations:

- 32-bit Version of cmd.exe: If the standard 64-bit version of cmd.exe is blocked, you might still have access to the 32-bit version (C:\Windows\SysWow64\cmd.exe). It’s worth checking if this version is allowed.

- PowerShell (powershell.exe): PowerShell is a powerful scripting environment that can be used for a wide range of tasks, from simple command execution to complex scripts. The powershell.exe executable might be allowed even if cmd.exe is not. Note that PowerShell can often bypass certain restrictions due to its extensive capabilities.

- PowerShell ISE (powershell_ise.exe): The Integrated Scripting Environment (ISE) for PowerShell provides an interface for writing and debugging scripts. It might be permitted where PowerShell itself is allowed, offering an alternative means to execute commands and scripts.

- 32-bit PowerShell (powershell.exe (32-bit)): Similar to the 32-bit version of cmd.exe, there is a 32-bit version of PowerShell available at C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe. This version might bypass restrictions applied to the 64-bit version.

- Batch Files (.BAT): Batch files are scripts that contain a series of commands executed sequentially. They might not be restricted in the same way as cmd.exe and can be used to automate tasks and execute commands.

- VBScript Files (.VBS): VBScript is a scripting language that can be used to perform various tasks. .VBS files can be executed through Windows Script Host and might not be subject to the same restrictions as command-line tools.

- HTML Applications (HTA): HTA files are essentially HTML files that can be executed as standalone applications. They can include JavaScript and can interact with the Windows environment, potentially allowing for command execution or system interaction.

- JavaScript Files (.JS): JavaScript files can be executed within environments that support scripting, such as HTA applications or browsers. They can perform various operations and might bypass some restrictions on command-line tools.

- ActiveX Objects: ActiveX controls are small programs that run within applications like Internet Explorer. They can be used to perform tasks or access system resources. ActiveX objects might be allowed when other scripting methods are restricted.

After attempting various alternatives to cmd.exe, we encounter repeated failures. It’s clear that administrators have thoroughly locked down this system and blocked these executables. However, we still have more options to explore.

Do you recall the RPC commands we executed using wmiexec.py? Windows provides a built-in tool that performs similar functions: wmic.exe. This executable is located at C:\Windows\System32\wbem\wmic.exe for 64-bit systems and C:\Windows\SysWOW64\wbem\wmic.exe for 32-bit systems. Let’s give it a shot.

WMIC commands might have unconventional structures, but they offer the same information and capabilities as traditional commands. This tool can be particularly useful for gathering system information or performing administrative tasks, even when other methods are restricted.

*Note: some useful WMIC queries:*

Retrieves the operating system’s name, version, and build number:

```
wmic os get caption, version, buildnumber
```

Lists all installed software with their names and versions:

```
wmic product get name, version
```

Displays the last boot time of the system, indicating how long the system has been running:

```
wmic os get lastbootuptime
```

Shows a list of user accounts along with their Security Identifiers (SIDs):

```
wmic useraccount get name, sid
```

Provides a summary of currently running processes, including their Process IDs (PIDs) and names:

```
wmic process list brief
```

Gathers details about the CPU, including its name, device ID, core count, and maximum clock speed:

```
wmic cpu get caption, deviceid, name, numberofcores, maxclockspeed
```

Lists network adapters along with their descriptions and IP addresses:

```
wmic nicconfig get description, ipaddress
```

Displays information about disk space usage for all logical disks:

```
wmic logicaldisk get caption, description, freespace, size
```

*Note: use ```wmic /?``` for help with command syntax and options.*

To gather information about the machine’s name and patching level, you can use the following WMIC commands:

```
wmic:root\cli>computersystem get name
Name
SV0056
```

Checking installed updates:

```
wmic:root\cli>qfe get HotfixID, Description, InstalledOn
Description         HotFixID   InstalledOn
Update              KB2883200  9/30/2013
Update              KB2894029  9/30/2013
Update              KB2894179  9/30/2013
```

From the output, it’s apparent that the server has not been updated for over three years. This indicates a potential vulnerability that we might exploit.

With the server’s outdated state, we can consider using a publicly available exploit for privilege escalation, such as the MS16-032 exploit. For example, you might use the Invoke-MS16-032.ps1 script to gain administrative privileges.

*Note: MS16-032 is a Microsoft security bulletin addressing a vulnerability in the Windows operating system. This vulnerability could allow an attacker to escalate privileges by exploiting flaws in the Win32k.sys kernel driver. Due to its potential for significant impact, it has been widely patched in many systems, making it increasingly difficult to exploit successfully. Despite this, if the target system has not been updated, this exploit could still be effective.*

Unfortunately, AppLocker has restricted the default PowerShell executable (powershell.exe). This presents a challenge, but we can explore alternative methods. Instead of the standard executable, you might find PowerShell functionalities packaged as a DLL file. DLL files are valid PE files but need to be loaded by an executable to run.

To bypass the restrictions on PowerShell, we can utilize a DLL-based implementation of PowerShell like a DLL implementation on p3nt4’s GitHub. You can transfer this file to the Citrix server in a couple of ways:

- Direct Download: Use Internet Explorer on Citrix to download the DLL file directly.


- Intermediate Transfer: Alternatively, use a backdoor like PI to first upload the DLL to a server you control. Then, access the server from Citrix and download the DLL using a simple HTTP server. For instance, you could use Python’s SimpleHTTPServer to serve the file:

```
python -m SimpleHTTPServer 8080
```

This will make the file accessible via HTTP, allowing you to download it from the Citrix environment.

To run the DLL, you can use RunDLL32.exe, a utility that can execute functions within DLL files. Use the following command to invoke the DLL:

```
rundll32.exe PowerShdll.dll,main
```

Here, PowerShdll.dll is the name of your DLL, and main is the entry point function within the DLL.

*Note: The main function in this context is the entry point defined in the DLL. When a DLL is executed with rundll32.exe, it calls the specified function (main in this case) within the DLL. This function typically sets up the environment or performs the actions required by the DLL. In the case of a PowerShell DLL, the main function would initialize the PowerShell interpreter, allowing you to execute PowerShell commands.*

*The book shows executing commands directly from the address bar in Internet Explorer or Windows Explorer. While you can run certain commands directly from the address bar, this method is generally more suited for simple executable paths rather than complex operations like running DLLs. It's more reliable to use the command line for such tasks.*

Once you have the PowerShell interpreter running, you can execute the MS16-032 exploit. This exploit leverages a vulnerability in Windows to gain elevated privileges. Specifically, MS16-032 takes advantage of a race condition between threads running on different CPUs.

*Note: the exploit targets a race condition where two threads attempt to perform operations concurrently. This condition can lead to a situation where the system's privilege checks are bypassed. By carefully timing the execution, the exploit allows an attacker to escalate privileges and open a command prompt with SYSTEM-level access (NT AUTHORITY). In other words, this race condition exploited by MS16-032 involves manipulating thread handles. When threads are created or managed incorrectly, it can result in a condition where an attacker can gain control over these threads, leading to privilege escalation. The exploit uses this flaw to execute arbitrary code with elevated privileges.*

*A thread handle is a reference or pointer used by an operating system to manage and control threads. Threads are the smallest unit of execution within a process, and each thread handle allows the operating system or applications to perform operations on a specific thread. This includes actions like starting, stopping, or querying the status of a thread.*

And now back to the task at hand:

When attempting to execute the Invoke-MS16-032.ps1 exploit, we encounter the following error:

```
PS C:\Users\user\AppData\Local> import-module .\Invoke-MS16-032.ps1
PS C:\Users\user\AppData\Local> Invoke-MS16-032.ps1
(...some output has been omitted...)
no valid thread handle was captured, exiting!
```

This error suggests that the exploit is failing because it cannot capture a valid thread handle. Upon closer inspection of the script, we find the following snippet:

```
# LOGON_NETCREDENTIALS_ONLY / CREATE_SUSPENDED
$CallResult = [Advapi32]::CreateProcessWithLogonW(
    "user", "domain", "pass",
    0x00000002, "C:\Windows\System32\cmd.exe", "",
    0x00000004, $null, $GetCurrentPath,
    [ref]$StartupInfo, [ref]$ProcessInfo)
```

The issue arises because the exploit for MS16-032 spawns cmd.exe threads to leverage a race condition, but this is hindered by the AppLocker policy in place.

To address this, we modify the script to use a valid executable that is not blocked by AppLocker. We replace C:\Windows\System32\cmd.exe with C:\Windows\System32\wbem\wmic.exe, and make the same change on line 333 of the script.

After updating the script, we execute it again, and this time, a new wmic window opens with admin credentials. The benefit here is twofold: we gain admin privileges and bypass AppLocker’s restrictive policy.

We can now spawn any process on the machine using the command ```process call create "cmd"```. Running ```whoami``` confirms that we have NT AUTHORITY privileges.

After some effort, we finally have an interactive admin console on the Citrix server. This achievement provides us with full control over the machine and access to any user connected to it from any shop across the country. This centralized control is a significant advantage of Citrix.

With all users gathered in one location, we can avoid the hassle of hunting for them across different machines. To make the most of this opportunity, we will exploit a notable design flaw in Windows environments: reversible passwords in memory. Details on this will be covered in the next cookbook.
