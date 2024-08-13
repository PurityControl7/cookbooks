# LDAP and Printer Exploitation

Note: *This short cookbook summarizes demonstrations from The Hacker Playbook 2 (THP 2) and the focus here is on exploiting Lightweight Directory Access Protocol (LDAP) and printer services, two often-overlooked but potentially vulnerable aspects of enterprise networks.*

In the world of penetration testing, it’s easy to overlook low-level findings, but sometimes these can lead to significant network compromises. One of the more intriguing examples involves multi-function printers (MFPs). These devices, often taken for granted, can potentially open doors to deeper network access.

Imagine you’re on a network without any credentials. A prudent approach would be to scan only your current subnet to avoid alerting any Intrusion Detection Systems (IDS). During your scan, you discover a multi-function printer.

Note: *To scan an entire subnet for devices that might be using LDAP, you can use the following nmap command:*

```
nmap -Pn -sS -p 389 --script ldap-search 192.168.1.0/24

```

*This command will scan all IP addresses within the 192.168.1.0/24 subnet for open port 389 (LDAP). The ldap-search script will further interrogate any detected LDAP services to gather more detailed information, which could be useful for identifying potential MFPs or other devices utilizing LDAP.*

Upon accessing the printer, you might encounter default credentials, or you could guess the password based on common documentation. Once inside the administrative console, you may not initially find anything of value. However, enterprise MFPs often have the capability to query the domain for email addresses via LDAP. This feature enables the printer to find the sender’s email address when scanning a document.

Now, consider the potential to capture the password for the user account that the printer uses to bind to the LDAP server and perform these queries.

For example, you log into your Xerox MFP using the default credentials over HTTP. In many penetration tests, it’s common to see such default passwords; for example, a quick Google search may reveal that the admin password is 1111. Navigating to the “Properties” tab, you can see that the printer is configured to use LDAP for domain queries.

At this point, you need to modify the LDAP server settings so that it points to your Kali attack VM. By doing this, any LDAP lookups conducted by the printer will be directed to your setup instead of the corporate LDAP server.

While reviewing the configuration, you notice the username field contains a domain account. Although the password field is blank, you can still make changes without re-entering password information. After saving your configuration changes, the next step is to wait for the MFP to conduct an LDAP lookup so you can capture the credentials.

Fortunately, many printers, including Xerox models, come equipped with a feature that allows you to test LDAP queries. You can click on the "User Mappings" tab to test a user lookup. However, before you proceed with testing an account, you need to set up a netcat listener on the specified server you configured in the previous steps.

To start a quick listener on port 444 (or whichever port you configured), run the following command in your terminal:

```
root@kali:~ nc -l -vv -p 444
```

Notes about the command:

- ```nc```: This is the command to run netcat, a versatile networking utility often referred to as the "Swiss Army Knife" of networking tools.

- ```-l```: This option tells netcat to listen for incoming connections.

- ```-vv```: This flag enables verbose output, providing detailed information about the connections and data being transmitted.

- ```-p 444```: This specifies the port number on which netcat will listen for incoming connections (in this case, port 444).

Notes about Netcat:

*Netcat (often abbreviated as nc) is a powerful networking tool that can read and write data across network connections using TCP or UDP. It's commonly used for various purposes, including:*

- *Port Scanning: Identify open ports on a target machine.*

- *Banner Grabbing: Capture service banners to gather information about running services on open ports.*

- *File Transfers: Transfer files between machines over the network.*

- *Creating Reverse Shells: Establish a command shell on a target machine.*

- *Network Debugging: Analyze network connections and troubleshoot connectivity issues.*

After setting up the Netcat listener and testing the LDAP query from the printer, we can observe the output in our terminal. The Multi-Function Printer (MFP), now connected to our Kali machine instead of the legitimate LDAP server, attempts to authenticate using a domain account. In this case, the captured credentials reveal a username of Domain_Admin_Account and a password of $uper$ecretPass!.

While you may not always be lucky enough to capture a domain admin account, obtaining any set of valid credentials provides a strong foothold for further lateral movement within the network. From here, you can begin exploring other attack vectors and privileges to escalate your access, potentially leading to a full compromise of the network.

Note: *using Netcat in the way described for capturing LDAP credentials won't work against LDAPS (LDAP over SSL).*
