**Note:** This is the second installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

## Attacking Authentication

Authentication may seem like one of the simplest security mechanisms in web applications: users provide a username and password, and the application verifies their validity. However, authentication is the critical first line of defense against unauthorized access, forming the foundation for other security measures like session management and access control. If authentication is compromised, attackers can gain full control over the application and its data. Despite its apparent simplicity, creating secure authentication is complex, and real-world implementations often contain flaws that make them a common weak point in web application security.

Here are some general guidelines:

1. If you already know a valid username (for example, an account you control), submit one login attempt using this username with an incorrect password, and another attempt using a random username.

2. Record every detail of the server's responses to each login attempt, including the status code, redirects, on-screen messages, and any differences hidden in the HTML page source. Use your intercepting proxy to maintain a full history of all traffic to and from the server.

3. Attempt to identify any obvious or subtle differences in the server's responses to the two login attempts.

4. If this fails, repeat the exercise across every part of the application where a username can be submitted (e.g., self-registration, password change, and forgotten password flows).

5. If a difference is detected in the server's responses based on valid and invalid usernames, obtain a list of common usernames. Use a custom script or automated tool to quickly submit each username, filtering responses that indicate the username is valid.

6. Before starting your enumeration, check whether the application implements account lockout after a certain number of failed login attempts. If so, design your enumeration attack accordingly. For example, if the application allows only three failed login attempts per account, you risk wasting one attempt for every username discovered through automated enumeration. To avoid this, do not submit random passwords with each login attempt. Instead, use a single common password or set the password to be the same as the username. If password quality rules are weak, it's likely that some logins will succeed, revealing both the username and password in a single attempt. In Burp Intruder, you can use the "battering ram" attack mode to insert the same payload at multiple positions in your login request. Even if the application’s responses to login attempts with valid and invalid usernames appear identical in every aspect, it may still be possible to enumerate usernames based on response timing. Applications often perform different back-end processes depending on whether the submitted username is valid. For instance, when a valid username is provided, the application may fetch user details from a back-end database, perform processing (e.g., checking account expiry), and validate the password (which might involve a resource-intensive hash algorithm) before returning a generic error message if the password is incorrect. The timing difference between responses may be too subtle to detect manually through a browser, but an automated tool could discriminate between them. Even if the results contain a large proportion of false positives, it is still better to have a list of 100 usernames—roughly 50% of which are valid—than a list of 10,000 usernames with only 0.5% validity. In addition to the login functionality, there may be other sources for valid usernames. Review all source code comments uncovered during application mapping to identify possible usernames. Any email addresses associated with developers or personnel in the organization may also serve as valid usernames, either in full or just the user-specific prefix. Accessible log files may also reveal usernames.

Even if login occurs over HTTPS, credentials can still be exposed to unauthorized parties if the application handles them insecurely:

- **Query String Parameters:** If credentials are transmitted as query string parameters instead of within the body of a POST request, they are vulnerable to being logged in several places, such as the user's browser history, web server logs, and reverse proxy logs. If an attacker compromises any of these resources, they could potentially escalate privileges by capturing the stored credentials.

- **Redirects:** While most web applications submit login credentials in the body of a POST request, it's surprisingly common to handle login via a redirect to a different URL with the credentials passed as query string parameters. Although it's unclear why developers opt for this, it’s often easier to implement redirects as 302 redirects rather than submitting a second HTML form with JavaScript.

- **Cookies:** Some web applications store user credentials in cookies, typically for features like login persistence, password changes, or "remember me" functionality. These credentials are vulnerable to attacks that compromise user cookies, and persistent cookies can be accessed if an attacker gains access to the client's local filesystem. Even if credentials are encrypted, attackers can replay the cookie to log in without needing to know the user's password.

If no insecure transmission of credentials is found, closely examine any encoded or obfuscated data. If this data is sensitive, it's possible that the obfuscation algorithm can be reverse-engineered.

### Forgotten Password Functionality and Design Weaknesses:

In addition to the issues discussed with login functionality, password recovery mechanisms often introduce vulnerabilities, such as username enumeration. These weaknesses can make the forgotten password flow the weakest link in the application's authentication logic. Some common design issues include:

- **Secondary Challenges:** Forgotten password functionality typically presents a secondary challenge in place of the main login. These challenges are often easier for attackers to bypass than trying to guess a password. Security questions like mother's maiden name, memorable dates, or favorite colors usually have a limited set of answers, which are often publicly available or easy to discover with minimal effort.

- **Insecure User-Set Challenges:** In many cases, users are allowed to set their own password recovery challenge during registration. Users often choose insecure questions, assuming only they will be asked them.

- **Brute-Forcing Recovery Challenges:** Similar to password change functionality, developers frequently overlook the possibility of brute-forcing password recovery answers. If the application allows unlimited attempts for answering recovery questions, it becomes highly vulnerable to a determined attacker.

Even if the application does not explicitly provide a visible field for entering an email address to receive the recovery URL, it's possible that the application transmits this information through hidden form fields or cookies. This creates two opportunities for an attacker:

1. **Discovering the User’s Email:** You may be able to extract the email address of the compromised user from these hidden fields or cookies. This information is often not visible on the page but can still be intercepted or viewed in the response body or through the browser's developer tools.

2. **Modifying the Email Address:** If the application transmits the email address in a hidden form field or cookie, you can manipulate this value to receive the recovery URL at an email address of your choice. By changing the value of the email field to your own address, you can capture the recovery link intended for the user you are targeting, potentially allowing you to reset their password without their knowledge.

For example, imagine a login recovery page where the application doesn't explicitly ask for the email but includes it as a hidden parameter in the HTML form. You could intercept the form submission, identify the hidden field containing the email, and modify the value to an email address you control. After submitting the form, the application would send the recovery URL to your email, bypassing the user's control over the recovery process.

If the application generates an email containing a recovery URL in response to a forgotten password request, try to capture several of these URLs and analyze them for patterns. It's possible that the URL contains predictable components such as tokens, user IDs, or other parameters that can help you predict future recovery URLs. This process is similar to analyzing session tokens for predictability—look for common structures or sequences that may allow you to generate or guess recovery URLs for other users.

### "Remember me" function:

1. Check if "Remember Me" fully remembers the user or just the username. Many applications store only the username and require the password for subsequent logins. However, if the "remember me" feature is storing session tokens or other credentials, it could still expose a vulnerability. In fact, many systems now use persistent cookies with session tokens or JWTs (JSON Web Tokens) to fully authenticate users, which could be a significant security risk if these tokens are not securely stored (e.g., in HttpOnly, Secure cookies).

Check whether the token is tied to specific user sessions (IP address, user agent) or whether it's easily copied or stolen across devices. This is important because such session persistence mechanisms can be abused by attackers.

2. Inspect all persistent cookies and local storage mechanisms. Nowadays, many applications use ```localStorage```, ```sessionStorage```, and cookies to store user data or session identifiers. Although cookies are the most common method, ```localStorage``` and ```sessionStorage``` are becoming increasingly popular as they allow for persistent data storage even across sessions without relying on cookies.

Remember to also inspect the IndexedDB and WebSQL storage in addition to the old options (Internet Explorer's userData, Silverlight isolated storage, and Flash Local Shared Objects). These modern storage mechanisms can hold sensitive data that may not be immediately obvious. Ensure you're also checking for unencrypted data, such as credentials, session tokens, or user IDs that might be stored in any of these mechanisms.

3. Review encoded or obfuscated data. Applications may obfuscate data to make it more difficult to reverse-engineer. However, weak encoding or encoding that uses predictable patterns could still be exploited. Modern techniques like Base64 encoding or custom obfuscation algorithms may be used, and while these are not secure on their own, they may create a false sense of security. Pay attention to modern encoding practices like Base64, Hex encoding, or even JWT. It's important to consider the possibility of reversible obfuscation that could expose sensitive data when decoded.

4. Modify persistent cookies to impersonate another user. If session tokens or JWTs are used in the "remember me" functionality, modifying the cookie may allow an attacker to hijack the session. However, many applications have implemented token-based authentication where the token is signed (JWT, for example), making it more difficult to tamper with the data directly. If the application uses tokens (JWT, OAuth tokens), check if they are signed and whether their integrity can be violated by simply modifying the cookie. A common defense is HMAC (Hash-based Message Authentication Code), where tampering with the token will invalidate its signature. Look for any session fixation or session hijacking vulnerabilities in token-based systems. Even with secure token storage, other flaws could lead to attackers impersonating a user by forcing them to use a specific session.

- **Note: What is a JWT?**

A JWT is a compact, URL-safe token format used to represent claims (or statements) between two parties, often for authentication and information exchange. It’s commonly used for stateless authentication in modern web applications, where the server doesn't need to maintain session data. A JWT consists of three parts:

1. **Header:** Contains information about the token, like the signing algorithm (e.g., HS256 or RS256).

2. **Payload:** Contains the claims (statements about the user or system). These can be registered, public, or private claims.

- Registered claims: Predefined claims like ```iat``` (issued at), ```exp``` (expiration), etc.

- Public claims: Custom claims that can be used across different systems.

- Private claims: Custom claims agreed upon by the sender and receiver (e.g., user ID).

3. **Signature:** This part ensures the integrity of the token. It’s created by signing the header and payload with a secret key (HMAC) or a private key (RSA or ECDSA).

The structure looks like this:

```
header.payload.signature
```

**How does JWT work?**

1. **Authentication:** A user logs in with their credentials. The server generates a JWT with the user's claims (e.g., user ID, roles, etc.), signs it with a secret key (or private key), and sends it back to the client.

2. **Storage:** The client stores the JWT (usually in ```localStorage``` or a cookie).

3. **Subsequent Requests:** For any subsequent requests, the client includes the JWT in the ```Authorization``` header (usually with the ```Bearer``` prefix).

4. **Validation:** The server validates the JWT by verifying the signature using the secret key (or public key if it's asymmetric encryption). If valid, the server processes the request, otherwise, it returns an error.

**Key Features:**

- **Stateless:** No need for server-side sessions because the token itself contains all the necessary information (authentication data).

- **Compact:** It’s a compact token that can be easily passed around in URLs, HTTP headers, or cookies.

- **Secure:** The integrity of the JWT can be verified with the signature, and claims can be encrypted (though typically JWTs are just signed, not encrypted).

**Security Caveats:**

- **Expiration:** Always set an expiration (```exp```) to limit the lifespan of the JWT.

- **Secure Storage:** If stored in cookies, ensure they’re set with ```HttpOnly``` and ```Secure``` flags to prevent XSS and CSRF attacks.

- **Algorithm Weaknesses:** Be cautious of weak signing algorithms (e.g., ```none``` algorithm, or weak symmetric encryption).

### Weak Password Validation:

1. **Password Truncation:** It's wild how some applications still chop off passwords beyond a certain length! This makes brute-forcing a breeze. If you can figure out the max length (say, 8 characters), you can refine attacks massively.

2. **Case Insensitivity:** Case-insensitive checks are another relic that reduces complexity. Essentially, it turns a-z into A and halves your permutations.

3. **Stripping Characters:** This one can be sneakier, as developers might claim they’re “sanitizing inputs.” But stripping special characters reduces entropy. And you’re left with alphanumerics—basically baby mode for brute-force attempts.

4. **Hack Steps:** Manual testing is your friend here—login with variations of your own password, understand the rules, and refine your attack.

### Fail-Open Login Mechanisms:

Even well-designed authentication mechanisms can become insecure due to implementation flaws. These mistakes—often subtle and difficult to detect—can lead to information leakage, login bypasses, or a weakened security posture overall. These flaws are particularly critical in high-security applications, such as those used by banks, where simpler vulnerabilities have likely been resolved.

One severe example of an implementation flaw is **fail-open logic**, where authentication mechanisms inadvertently allow access when an error occurs, rather than failing securely. This issue is particularly dangerous because it can expose sensitive data or grant unauthorized access without requiring valid credentials. Below is an example of a flawed login mechanism that exhibits fail-open behavior:

```
public Response checkLogin(Session session) { 
    try {
        String uname = session.getParameter("username");
        String passwd = session.getParameter("password");
        User user = db.getUser(uname, passwd);

        if (user == null) { // Invalid credentials
            session.setMessage("Login failed.");
            return doLogin(session); // Redirect back to login
        }
    } catch (Exception e) {
        // Error handling is empty! No action is taken.
    }
    // If an exception occurs, this block executes, granting login success.
    session.setMessage("Login successful.");
    return doMainMenu(session); // User is redirected to the main menu
}
```

**What's Happening Here?**

1. **Valid Logic:** The first part attempts to retrieve the username and password from the request (```session.getParameter()```) and checks them against the database (```db.getUser()```). If ```db.getUser()``` returns ```null```, it means the credentials are invalid, and the method appropriately redirects back to the login page.

2. **Fail-Open Logic:** If any exception occurs (e.g., a ```NullPointerException``` if the ```username``` or ```password``` parameter is missing), the catch block silently absorbs the exception and continues execution. As a result, **the code reaches the final block**, where it sets the session to "Login successful" and proceeds as if the user is authenticated.

3. **Why This is Dangerous:** Even though the session may not be tied to a valid user, an attacker could exploit this logic flaw to gain partial access to sensitive functionality or data. In more complex systems, these fail-open flaws might allow attackers to bypass authentication entirely.

In practice, this flaw is more likely to occur in systems with:

- **Layered method calls:** Where the authentication logic spans multiple functions, increasing the chance of inconsistent error handling.

- **Complex validation workflows:** Where partial progress or state is maintained across several steps, making it harder to ensure secure behavior in all scenarios.

- **Poor error handling policies:** For example, general try-catch blocks with no specific handling for different exception types can mask critical issues.

**Probing and Exploiting Fail-Open or Improper Logic Flaws in Login Mechanisms:**

1. **Perform a Baseline Login:** Start by performing a complete, valid login using an account you control. Record every piece of data submitted to the application and the responses received using an intercepting proxy, such as Burp Suite. This establishes a baseline for normal behavior.

2. **Experiment with Modifications:** Repeat the login process multiple times, introducing unexpected modifications to the submitted data. Focus on every request parameter, cookie, or header sent by the client. For each one:

- Replace the value with an empty string.

- Completely remove the name/value pair.

- Submit extremely long or extremely short values.

- Replace numbers with strings and vice versa.

- Include the same item multiple times with identical or conflicting values.

3. **Analyze Application Responses:** Review the application's responses to each malformed request closely. Look for any divergence in behavior compared to the base case. Note any unexpected results, error messages, or partial logins.

4. **Iterate and Combine:** Use your observations to refine your test cases. For example, if one specific modification causes a change in the application's behavior, try combining it with other changes to further probe the logic. The goal is to uncover edge cases where the application behaves inconsistently, which may reveal exploitable weaknesses.

### Multi-Stage Login Pitfalls:

Many believe that multi-stage authentication mechanisms inherently offer greater security than simple username/password logins. While adding additional authentication checks can enhance security, it also increases complexity—and with complexity comes a greater chance of implementation flaws. In some cases, multiple vulnerabilities can combine in ways that actually make a multi-stage login less secure than a traditional single-step authentication.

Several common flaws can be exploited in multi-stage login mechanisms:

- **Skipping Intermediate Stages:** Some applications assume that reaching a later authentication stage (e.g., stage three) proves the user has successfully completed earlier stages. If the application does not properly enforce sequential validation, an attacker may be able to jump from an initial stage directly to a later one. This could allow authentication with only a partial set of credentials.

- **Trusting Previously Validated Data:** At different stages, applications may assume that certain user attributes (such as account status or access level) have already been validated earlier. However, if an attacker can manipulate these attributes in later stages—such as flipping an "isAdmin" flag or bypassing account expiration checks—then they may gain unauthorized access. For example, if an account lockout status is checked in stage one but not enforced in stage two, an attacker might brute-force login attempts during the second stage while bypassing protections.

- **Mismatched Identity Across Stages:** Some multi-stage logins rely on the user resubmitting identity information at different points, often via hidden form fields or session variables. If the application does not enforce that the same user identity is consistently used throughout the process, an attacker could mix and match credentials. For instance, they might submit their own valid credentials in the first stage and then use another user's details in the second stage (e.g., their token-based authentication). This could enable unauthorized access while technically passing all required checks.

**Modern Relevance and Additional Considerations:**

- **Session Fixation Attacks:** If the system doesn't properly reset or bind a session to a single identity, attackers may hijack a partially authenticated session and complete later authentication stages using their own credentials.

- **OAuth / SSO Weaknesses:** Many web applications today rely on third-party authentication (OAuth, SAML, etc.), and similar logic flaws can occur when transitioning between the identity provider and the service being accessed. Attackers might tamper with token exchanges to manipulate authentication flows.

- **Race Conditions:** In some cases, attackers can manipulate multi-step logins by triggering multiple requests in rapid succession, potentially bypassing security checks or submitting conflicting authentication data.

To identify weaknesses in a multi-stage authentication process, follow these structured steps:

1. Perform a Baseline Login and Capture Data:

- Log in to the application using an account you control.

- Use an intercepting proxy (e.g., Burp Suite, OWASP ZAP) to capture every request and response.

- Document all data submitted at each stage, including hidden form fields, cookies, and URL parameters.

2. Analyze the Authentication Flow:

- Identify each distinct authentication step and note what data is collected at each stage.

- Check if any information is collected more than once or is transmitted back to the client for resubmission.

- Pay attention to hidden fields, cookies, or URL parameters that persist login state information.

3. Attempt Authentication Sequence Manipulation:

Perform multiple login attempts while modifying request sequences:

- Out-of-Order Execution – Attempt the login steps in a different sequence.

- Direct Access – Skip earlier steps and try jumping to later authentication stages.

- Stage Skipping – Bypass one or more steps and proceed to the next stage.

- Unexpected Input – Think creatively about unintended paths, like injecting unexpected parameters or values.

4. Test for Inconsistent Data Handling:

- If the same data is submitted more than once, try changing it at different stages.

- Check if earlier validations are ignored in later stages (e.g., if a username is verified in stage one but trusted in stage three without revalidation).

- Test mixed-identity authentication: Use one user’s credentials in one stage and another’s in the next.

- Examine whether different validation methods exist at separate stages, such as requiring a username and password in one step but a username and PIN in another.

5. Exploit Trust in Client-Side Data:

- Look for parameters that indicate login progression (e.g., ```stage2complete=true```).

- Modify values and check if unauthorized access to later authentication stages is possible.

- Observe if the application improperly trusts user-supplied session tokens or state-tracking variables.

Some multi-stage authentication mechanisms introduce secondary challenges, such as:

- Randomly chosen security questions (e.g., mother's maiden name, birthplace).

- Requests for randomly selected characters from a secret passphrase.

Common Implementation Flaws:

- Predictable Randomization – The application may generate a different challenge with each login attempt but fail to track which question was previously asked. Attackers can cycle through login attempts until they receive a question they know the answer to.

- Repeated Challenge Reauthentication – If the application allows an attacker to pass earlier authentication stages repeatedly until they receive a security challenge they can answer, it defeats the purpose of multi-step authentication. For example, a passphrase challenge requiring two random letters allows an attacker to keep retrying login attempts until the system requests letters they know.

**Key Takeaways:**

- Multi-stage authentication adds complexity but does not inherently increase security.

- Improper enforcement of authentication sequences can allow attackers to skip stages or manipulate authentication flow.

- Trust in client-side data is a major security flaw; applications should enforce server-side validation at every stage.

- Randomized security questions or secondary authentication mechanisms must be designed to prevent brute-force exploitation or predictable reauthentication attacks.

## Attacking Session Management

Session management is a crucial security component in web applications, allowing them to track and maintain a user's identity across multiple requests. It ensures that authenticated users remain recognized beyond the initial login request and helps manage their interaction with the application.

Due to its pivotal role, session management is a prime target for attackers. If an attacker can exploit weaknesses in this mechanism, they can bypass authentication and impersonate other users without needing their credentials. In the worst-case scenario, compromising an administrative session could grant full control over the application.

Common vulnerabilities range from trivial to highly complex. In the most severe cases, an attacker might simply increment a session token to switch to another user's account. More robust implementations may use obfuscation and security layers, requiring attackers to employ sophisticated automation and analysis to uncover weaknesses. Regardless of complexity, any flaw in session management can have devastating security implications.

No matter how robust authentication is, every request after login depends on the integrity of session management. If this mechanism is broken, attackers can sidestep authentication entirely, making session security just as critical as login security itself.

Session management vulnerabilities generally fall into two main categories:

- Weaknesses in the generation of session tokens, making them predictable or easily guessable.

- Weaknesses in the handling of session tokens, leading to leakage, theft, or improper invalidation.

### Identifying Session Tokens in Web Applications:

In applications using standard cookies for session management, identifying the session token is often straightforward. However, in some cases, it requires closer inspection:

1. **Multiple Tracking Mechanisms** – Some applications use multiple data points, such as cookies, URL parameters, and hidden form fields, to track sessions. Always verify which parameter is the actual session token.

2. **False Identifiers** – Some seemingly relevant values, like default session cookies generated by the web server, may not be used for session tracking.

3. **Observing Authentication Behavior** – Many applications issue new session tokens after login. Monitoring the data passed to the browser can help pinpoint the correct token.

4. **Systematic Testing** – To confirm which parameter is the session token, remove suspected values one by one while accessing a session-dependent page (e.g., a "My Account" section). If removing a value breaks access, it’s likely the session token. Tools like Burp Repeater are useful for this process.

Not all web applications use traditional session-based mechanisms. Some security-critical applications with authentication and complex functionality opt for alternative methods to manage user state. Two common alternatives are:

**1. HTTP Authentication:**

Some applications rely on HTTP-based authentication methods like Basic, Digest, or NTLM authentication instead of session tokens. These work as follows:

- The browser handles authentication using HTTP headers rather than relying on session-specific code in web pages.

- Once a user enters credentials in a browser pop-up, the browser automatically resends them with each request to the server, maintaining authentication without session tracking.

- This approach is similar to forms-based authentication where every page includes a login prompt, requiring constant reauthentication.

Although HTTP authentication can identify users across multiple requests without using session tokens, it is rarely used in modern web applications. The main reasons are:

- Poor usability – Browser pop-ups for authentication are intrusive.

- Limited control – The application has less flexibility in managing logins, logouts, and session timeouts.

- Lack of scalability – HTTP authentication doesn’t integrate well with complex web applications that require fine-grained access control and user session management.

For these reasons, most web applications today use session-based authentication instead.

**2. Sessionless State Mechanisms:**

Instead of issuing session tokens, some applications store all state-related information on the client-side rather than on the server. Common implementations include:

- Cookies – The application sends state-related data to the client inside cookies.

- Hidden form fields – Data about user interactions is stored within HTML forms and submitted with each request.

This method functions similarly to ASP.NET ```ViewState```, where the entire application state is serialized, stored on the client, and then returned to the server with each request. However, to prevent security risks, the following safeguards are necessary:

- Encryption & Signing – The state data must be encrypted or digitally signed to prevent tampering.

- Context Awareness – The application must validate where the state object originated to prevent attacks where a user copies a valid state object and reuses it in a different context to gain unintended access.

- Expiration Handling – Since there’s no server-side session, the application must include a timestamp or expiration mechanism to prevent replay attacks.

While sessionless state mechanisms reduce server load (since no session tracking is needed), they introduce risks if client-side data is not properly protected. If an attacker can modify or forge state data, they may manipulate their access level or impersonate another user.

**Additional Notes:**

- HTTP authentication is mostly seen in internal enterprise applications where usability isn't a major concern.

- Sessionless state mechanisms are used in stateless architectures, such as RESTful APIs or applications that must scale efficiently without storing per-user sessions on the server.

However, for most modern web applications, session-based authentication remains the preferred approach due to its flexibility, security, and ease of use.

### Guidelines for Analyzing Session Management:

1. If HTTP authentication is in use, the application may not implement a separate session management mechanism. Analyze any token-like data items carefully to determine their role in maintaining state.

2. If the application relies on a sessionless state mechanism, where all state data is transmitted via the client, look for these strong indicators:

- Token-like data items issued to the client are unusually long (typically 200 or more bytes).

- A new token-like item is generated in response to every request.

- The token appears encrypted (random-looking, no discernible structure) or signed (structured with an additional segment of binary data).

- The application rejects repeated submissions of the same token, indicating it enforces strict one-time use.

3. If it becomes evident that the application does not use session tokens for state management, then the attacks targeting session vulnerabilities may not be effective. In this case, shift focus to other critical weaknesses, such as broken access controls or code injection vulnerabilities—which often yield more impactful exploits.

### Weaknesses in Token Generation:

Many session management mechanisms are vulnerable due to predictable token generation, allowing attackers to determine valid tokens issued to other users. Tokens serve critical security functions, and their predictability can lead to serious compromises.

Tokens are often used in various security contexts, including:

- Password recovery tokens sent via email.

- Anti-CSRF tokens placed in hidden form fields.

- One-time access tokens for temporary protected resource access.

- "Remember me" tokens for persistent login functionality.

- Order tracking tokens in shopping applications without authentication.

Some applications generate session tokens by transforming user-related information (e.g., username, email, or timestamps) into a structured format. These tokens may be encoded or obfuscated, but not truly random. For example, this may look like a long, random string:

```
757365723d6461663b6170703d61646d696e3b646174653d30312f31322f3131
```

However, decoding it as hexadecimal reveals:

```
user=daf;app=admin;date=10/09/11
```

Attackers can exploit such structured tokens by enumerating usernames and generating possible valid tokens to hijack user sessions.

Tokens containing meaningful data often have a recognizable structure with distinct delimiters separating key components. These may include:

- Username or email address

- Numeric user ID

- User’s group/role (e.g., admin, guest, premium)

- Timestamp or expiration date

- Incrementing or predictable sequence numbers

- Client IP address

Each component may be encoded in different ways, often to obfuscate content or facilitate safe transmission. Common encoding methods include:

- Hex encoding (e.g., ```48656c6c6f``` → ```Hello```)

- Base64 encoding (e.g., ```SGVsbG8=``` → ```Hello```)

- XOR encoding (a simple but weak encryption method)

Attackers often analyze token structures using decoding techniques to uncover patterns, predict valid session tokens, and perform session hijacking.

When an application processes a structured token, it may only validate certain components while ignoring the rest. For example, if a token is Base64-encoded, the server might only extract and verify the "user" and "date" fields, leaving other data unused.

In cases where a token contains binary data, much of it may be padding, with only a small portion actually relevant for validation. Identifying which parts of a token are essential can significantly reduce its effective entropy, making it easier for attackers to analyze and predict valid tokens.

### Predictable Tokens:

In the most blatantly vulnerable cases, an application may use a simple sequential number as the session token. With just two or three samples, an attacker can predict future tokens and hijack 100% of active sessions almost instantly.

Other applications may use more complex sequences, but these can still be analyzed and exploited with some effort. Based on real-world experience, predictable session tokens often stem from three key weaknesses:

- Concealed sequences

- Time dependency

- Weak random number generation

Each of these vulnerabilities can be leveraged to compromise session security, which we’ll explore next.

#### Concealed Sequences:

At first glance, some session tokens appear unpredictable in their raw form. However, when they are decoded or unpacked, hidden patterns may emerge, allowing attackers to reverse-engineer the sequence and predict valid tokens.

Let’s examine a scenario where an attacker is attempting to uncover a predictable session token:

```
GET /auth/340/Home.ashx HTTP/1.1  
Host: mdsec.net  
User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:1.9.2.10) Gecko/20100914 Firefox/3.6.10  
Accept: text/html, application/xhtml+xml, application/xml; q=0.9, */*; q=0.8  
Referer: https://mdsec.net/auth/340/Default.ashx  
Cookie: SessionId=5160£2E93E9FB22  
```

Consider the following extracted session tokens:

```
lwjVJA  
Ls3Ajg  
xpKr+A  
XleXYg  
9hyCzA  
jeFuNg  
JaZZoA  
```

At first glance, these values appear random, but a closer inspection reveals that they share characteristics of Base64-encoded data: mixed-case alphabetic characters, numbers, and special symbols like ```+```, which is a valid Base64 character.

Decoding these tokens from Base64 reveals binary-like data, which suggests that the token values represent raw 32-bit numbers rather than human-readable ASCII text. Converting the decoded binary data into hexadecimal format yields:

```
9708D524  
2ECDC08E  
C692ABF8  
5E579762  
F61C82CC  
8DE16E36  
25A659A0  
```

At first, no obvious pattern emerges from these hexadecimal values. To investigate further, we compute the differences between consecutive values by subtracting each number from the previous one. Let's denote:

- ```V1 = 9708D524```

- ```V2 = 2ECDC08E```

- ```V3 = C692ABF8```

- ```V4 = 5E579762```

- ```V5 = F61C82CC```

- ```V6 = 8DE16E36```

- ```V7 = 25A659A0```

Now, calculating the differences:

```
V2 - V1 = 2ECDC08E - 9708D524  = 97C4EB6A  
V3 - V2 = C692ABF8 - 2ECDC08E  = FF97C4EB6A  
V4 - V3 = 5E579762 - C692ABF8  = 97C4EB6A  
V5 - V4 = F61C82CC - 5E579762  = FF97C4EB6A  
V6 - V5 = 8DE16E36 - F61C82CC  = FF97C4EB6A  
V7 - V6 = 25A659A0 - 8DE16E36  = 97C4EB6A  
```

Now we see that two alternating values appear in the difference calculations:

- ```97C4EB6A```

- ```FF97C4EB6A```

So, what’s happening?

- It looks like the token generator is applying a fixed step size (```0x97C4EB6A```) to the previous value.

- The alternating presence of ```FF``` at the beginning of some differences suggests a possible integer overflow, meaning that when the value exceeds 32 bits, it wraps around (truncating extra bits).

- The very first token (```V1 = 9708D524```) could have been chosen arbitrarily by the application.

- Once the sequence starts, it follows the predictable pattern by adding/subtracting ```0x97C4EB6A```.

- If we had only one value, we wouldn't be able to tell the pattern. But after seeing multiple values, we can recognize the repeated step size.

In short, this reveals a repeating sequence. The token generation algorithm adds ```0x97C4EB6A``` to the previous value, then truncates the result to fit a 32-bit number, before encoding it in Base64 for transport over HTTP. With this knowledge, an attacker can predict future session tokens by applying the discovered pattern:

- Starting with a known token, they can repeatedly add ```0x97C4EB6A``` to generate the next sequence.

- Since the application truncates the value to 32 bits before encoding, an attacker can replicate this behavior in a script.

- The same process can also be used in reverse, reconstructing previous session tokens issued by the server.

#### Time Dependency:

Some web servers and applications generate session tokens using the time of generation as an input. If the algorithm does not incorporate sufficient additional entropy, it may be possible to predict other users' session tokens. While any given sequence of tokens may initially appear random, analyzing the timestamps at which each token was generated can reveal a discernible pattern. In a high-traffic application where numerous sessions are created per second, an automated attack can potentially identify large numbers of valid session tokens.

During a security assessment of an online retailer's web application, the following sequence of session tokens was observed:

```
3124538-1172764258718
3124539-1172764259062
3124540-1172764259281
3124541-1172764259734
3124542-1172764260046
3124543-1172764260156
3124544-1172764260296
3124545-1172764260421
3124546-1172764260812
3124547-1172764260890
```

Each token consists of two numeric components:

- The first number increases incrementally by 1.

- The second number increases by varying amounts, suggesting it may be time-dependent.

By calculating the differences between successive values in the second component:

```
344
219
453
312
110
140
125
391
78
```

No immediately obvious pattern emerges. However, it remains feasible to brute-force the relevant number range to discover valid session tokens.

A second sequence of tokens was collected after a few minutes:

```
3124553-1172764800468
3124554-1172764800609
3124555-1172764801109
3124556-1172764801406
3124557-1172764801703
3124558-1172764802125
3124559-1172764802500
3124560-1172764802656
3124561-1172764803125
3124562-1172764803562
```

Comparing the two sequences reveals two key observations:

1. The first numeric sequence continues incrementing normally, but five values are missing—likely assigned to other users logging in during the interval.

2. The second numeric sequence shows a sudden jump of 539,578, strongly suggesting a time-based dependency.

The sudden increase in the second component indicates that it likely represents a millisecond timestamp. A subsequent code review confirmed this assumption:

```
String sessId = Integer.toString(s_SessionIndex++) + "-" + System.currentTimeMillis();
```

The session ID consists of:

- ```s_SessionIndex++```: A sequential counter for sessions.

- ```System.currentTimeMillis()```: The current system time in milliseconds.

Using this knowledge, an attacker can construct a scripted attack to capture other users' session tokens:

1. **Continuous Polling:**

- Repeatedly request new session tokens from the server.

- Observe the incremental changes in the first numeric component.

2. **Observe the incremental changes in the first numeric component.**

- If the first number increases by more than 1, a token has been issued to another user.

3. **Estimating the Second Component:**

- The second number is time-based, meaning its value falls within a predictable range between known token timestamps.

- Given frequent polling, this range will typically be narrow (only a few hundred possible values).

4. **Brute-Force Attack:**

- Iterate through all possible values in the estimated range.

- Append each value to the missing session index.

- Attempt to access a protected page using the generated session token.

- When successful, the attack compromises the user's session.

5. **Compromising the Application:**

- Running the attack continuously allows an attacker to capture every user session.

- If an administrator logs in, the attacker gains full control over the application.

#### Weak Number Generation:

Computers are fundamentally deterministic machines, meaning very little of what they do is truly random. When applications require randomness—such as for generating session tokens—they rely on pseudorandom number generators (PRNGs). These algorithms produce sequences of numbers that appear random but are actually generated through a predictable mathematical process.

Some PRNGs distribute numbers evenly across a range, making them seem stochastic (i.e. conjectural). However, given a small sample of generated values, an attacker can often reverse-engineer the algorithm and predict future (or past) values with perfect accuracy.

Jetty, a widely used Java-based web server, includes a session management mechanism that was found to be vulnerable to a token prediction attack. In 2006, security researcher Chris Anley from NGSSoftware discovered that Jetty’s session tokens were generated using Java's ```java.util.Random``` class. This class implements a *linear congruential generator (LCG)*, a type of PRNG that follows this formula to produce new numbers:

```
synchronized protected int next(int bits) {
    seed = (seed * 0x5DEECE66DL + 0xBL) & ((1L << 48) - 1);
    return (int) (seed >>> (48 - bits));
}
```

Breaking it down:

1. **Seed Update:**

- The previous ```seed``` value is multiplied by a constant (```0x5DEECE66DL``` in hex).

- Another constant (```0xBL```) is added.

- The result is bitwise-ANDed with ```((1L << 48) - 1)```, which effectively keeps the value within a 48-bit range.

2. **Bit Shifting and Extraction:**

- The expression ```seed >>> (48 - bits)``` uses the *unsigned right shift operator* (```>>>```), which moves the bits of ```seed``` to the right by ```(48 - bits)```.

- This operation extracts the required number of bits from the seed and ensures that the final number is within the desired range.

Since the LCG formula always generates the next number based on a fixed mathematical relationship, an attacker who obtains a few token values can work out the initial seed. Once the seed is known, all future (and past) session tokens can be predicted, allowing the attacker to hijack other users' sessions.

The key issue here is that ```java.util.Random``` was never designed for cryptographic security. It is meant for general-purpose randomness in applications like games and simulations, not for security-sensitive operations like session management. Secure applications should instead use a cryptographically secure PRNG (CSPRNG), such as ```java.security.SecureRandom```, which is designed to resist prediction.

**Note: What Does ```((1L << 48) - 1)``` Do?**

The expression ```((1L << 48) - 1)``` is a bitmask that ensures the result remains within 48 bits. Here's how it works:

**Step 1: ```1L << 48``` (Left Shift)**

- ```1L``` is the number ```1``` as a **long** type (denoted by ```L```), meaning it's a 64-bit integer.

- The ```<< 48``` operator shifts this ```1``` **48 places to the left**, turning it into a large binary number:

```
1L      = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
1L << 48 = 00000000 00000000 00000000 00000001 00000000 00000000 00000000 00000000
```

This results in a number with a single ```1``` at bit position 48, with all bits below it as ```0```.

**Step 2: Subtracting 1**

Now, we subtract 1:

```
(1L << 48) - 1 =
00000000 00000000 00000000 00000001 00000000 00000000 00000000 00000000
- 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
-----------------------------------------------------------------------
00000000 00000000 00000000 00000000 11111111 11111111 11111111 11111111
```

This results in a bitmask where the lower 48 bits are all 1s, and the higher bits are 0s.

**Step 3: Applying Bitwise-AND (```&```)**

When the calculated seed value is bitwise-ANDed (```&```) with this mask, it effectively clears out any bits beyond 48 while keeping the lower 48 bits unchanged. For example, if ```seed``` had bits set beyond 48:

```
11010101 00101010 11001010 10011010 10101010 10101010 10101010 10101010  (64-bit seed)
&
00000000 00000000 00000000 00000000 11111111 11111111 11111111 11111111  (48-bit mask)
-----------------------------------------------------------------------
00000000 00000000 00000000 00000000 10101010 10101010 10101010 10101010  (Result: 48-bit value)
```

This guarantees that the seed never grows beyond 48 bits, maintaining a predictable number space.

**Additional Clarification:** 

In previous example, we ended up with four groups (32 bits)—truncated for readability. So, let's correct that and show a true 48-bit number.

**The Correct Representation:**

Let’s assume a random 48-bit number before the masking:

```
11010101 00101010 11001010 10011010 11110000 11001100  (full 48-bit value)
```

Then, our 48-bit mask:

```
11111111 11111111 11111111 11111111 11111111 11111111  (48-bit mask)
```

Now, applying the bitwise-AND (```&```):

```
11010101 00101010 11001010 10011010 11110000 11001100  
&
11111111 11111111 11111111 11111111 11111111 11111111  
---------------------------------------------------
11010101 00101010 11001010 10011010 11110000 11001100  (unchanged 48-bit result)
```

If the original seed had extra bits beyond 48 (since Java ```long``` is 64-bit), then those would get chopped off:

```
11010101 00101010 11001010 10011010 11110000 11001100 01010101 10101010  (original 64-bit seed)
&
00000000 00000000 11111111 11111111 11111111 11111111 11111111 11111111  (48-bit mask)
---------------------------------------------------
00000000 00000000 11010101 00101010 11001010 10011010 11110000 11001100  (48-bit result)
```

The highest 16 bits (00000000 00000000) are wiped out, leaving only 48 bits.

**And now, let’s break down ```seed >>> (48 - bits)``` and why it’s needed!**

1. ```seed``` contains a 48-bit number

- After applying the linear congruential formula and the ```& ((1L << 48) - 1)```, we know seed is always a 48-bit value.

2. ```>>> (48 - bits)``` shifts it right

- ```bits``` represents how many bits the caller wants (e.g., if they request 32 bits, then ```bits = 32```).

- ```(48 - bits)``` calculates how much we need to shift to the right to extract the desired portion.

3. Logical shift (```>>>```) instead of arithmetic shift (```>>```)

- The **logical right shift** (```>>>```) ensures that zeroes are filled in from the left, preventing sign extension (which could happen if it were a negative number and we used ```>>```).

- Since ```seed``` is always positive in this case (due to bitwise ```&``` limiting it to 48 bits), this detail isn’t super important, but it's a good habit in Java.

**Why is this needed?**

Imagine ```seed``` is a full 48-bit number, but the caller only wants 32 bits (as is common when generating random numbers). Without shifting, you’d get all 48 bits, which might not fit where you need it. So we:

- Shift right by ```(48 - 32) = 16``` bits.

- This effectively extracts the upper 32 bits of ```seed```, which are considered more “random” than the lower bits (since lower bits can sometimes have weaker randomness in LCGs).

**Tying it all together:**

1. The LCG updates ```seed``` → a new pseudo-random number is generated.

2. Bitwise AND keeps ```seed``` within 48 bits → prevents overflow.

3. Right shift extracts only the most significant ```bits``` → ensuring the requested bit-length output.

So, ```seed >>> (48 - bits)``` is basically just a way to extract the top ```bits``` of our 48-bit seed to return the requested random value while keeping the distribution balanced (it ensures that the function behaves predictably when different bit lengths are requested).

After this deep dive into the mechanics of weak number generation, let's move forward and uncover more insights from the book.

Sometimes, developers attempt to create stronger tokens by concatenating multiple sequential outputs from a pseudorandom number generator. The idea is that a longer token implies greater security. However, this approach is often a mistake. If an attacker obtains several consecutive outputs, they may infer details about the generator’s internal state. In fact, this can make it even easier for the attacker to predict past or future values in the sequence.

### Testing the Quality of Randomness:

Assessing the randomness of tokens in web applications is crucial for ensuring security, as predictable tokens can be exploited by attackers. While manual inspection might reveal obvious patterns, a more rigorous approach involves statistical analysis. Burp Suite's Sequencer tool facilitates this process by evaluating the randomness of tokens such as session identifiers, anti-CSRF tokens, and password reset tokens.

Using Burp Sequencer:

1. Capture Tokens:

- Identify a response from the application that issues the token you want to test, such as a response to a login request that sets a session cookie.

- In Burp's HTTP history, locate this response, right-click, and select "Send to Sequencer."

- In the Sequencer tab, specify the token's location within the response.

- Start the live capture to collect a sample of tokens. 

2. Analyze Tokens:

- After capturing a sufficient number of tokens, pause the capture and initiate the analysis.

- Burp Sequencer performs multiple randomness tests and provides a summary of the token's entropy.

Sample Size Considerations:

The reliability of the analysis increases with the sample size. While Burp Sequencer allows analysis with as few as 100 tokens, this minimal sample may only detect blatant non-randomness. For more dependable results, capturing at least 5,000 tokens is advisable. To comply with formal FIPS standards for randomness testing, a sample of 20,000 tokens is required.

Interpreting Results:

Burp Sequencer reports the "bits of effective entropy" at various significance levels. A common significance level is 1%, indicating a 1% chance of incorrectly identifying random data as non-random. It's important to note that while passing these statistical tests suggests randomness, it doesn't guarantee unpredictability, especially if the token generation algorithm is flawed.

### Encrypted Tokens and Their Pitfalls:

Some applications generate tokens that contain meaningful user information and attempt to secure them by encrypting the tokens before issuing them. At first glance, this seems like a robust approach—since the tokens are encrypted with a secret key, users cannot easily decrypt or tamper with them.

However, depending on the encryption algorithm used and how the application processes these tokens, attackers may still be able to manipulate their contents without decrypting them. This may sound counterintuitive, but several well-documented attacks exploit weaknesses in encryption schemes to modify encrypted data in a controlled way.

The feasibility of such attacks depends on the cryptographic algorithm in use. Some common attack vectors include:

- Padding Oracle Attacks – Exploiting how applications handle padding errors in block ciphers (e.g., AES in CBC mode).

- Bit-Flipping Attacks – Modifying ciphertext in ways that result in predictable changes to decrypted data, often seen in XOR-based encryption schemes.

- Length Extension Attacks – Affecting hash-based message authentication codes (HMAC) if poorly implemented.

These vulnerabilities have been observed in real-world applications, often due to weak cryptographic design choices or improper implementation. To mitigate such risks, developers should use modern, authenticated encryption methods (such as AES-GCM) and avoid designing security mechanisms that rely on encryption alone for integrity protection.

#### The Risks of ECB Mode in Encrypted Tokens:

Applications that use encrypted tokens typically rely on symmetric encryption so they can decrypt received tokens and recover their original contents. However, some implementations use the **Electronic Codebook (ECB) mode**, which introduces serious security flaws.

ECB works by dividing plaintext into fixed-size blocks (e.g., 8 or 16 bytes) and encrypting each block separately with the same secret key. During decryption, each ciphertext block is decrypted independently to reconstruct the original plaintext. The major weakness of this approach is that **identical plaintext blocks always produce identical ciphertext blocks**—creating patterns in the encrypted data.

This leakage is particularly evident in structured data, such as bitmap images, where visual patterns from the original plaintext remain visible in the encrypted version. More critically, attackers can exploit these patterns to infer relationships between data blocks or even reconstruct parts of the original plaintext.

For secure encryption, ECB mode should be avoided entirely. Instead, applications should use cipher modes that introduce randomness and diffusion, such as Cipher Block Chaining (CBC) with a proper initialization vector (IV) or Authenticated Encryption modes like AES-GCM, which provide both confidentiality and integrity.

**More Details on How ECB Encryption Works:**

Applications that employ encrypted tokens often use symmetric encryption to encode user-related data. A commonly used but flawed encryption mode is the Electronic Codebook (ECB) cipher, which operates as follows:

- The plaintext is divided into fixed-size blocks (e.g., 8 bytes each).

- Each block is encrypted separately using the same key.

- During decryption, each ciphertext block is decrypted back into its original plaintext form using the same key.

- Identical plaintext blocks will always encrypt into identical ciphertext blocks.

This means that patterns in plaintext persist in ciphertext, making it vulnerable to manipulation.

**Example of an Encrypted Token:**

Consider an application that generates tokens containing user-specific information:

```
rnd=2458992;app=iTradeEUR_l;uid=218;username=dafydd;time=634430423694b
```

When this token is encrypted using ECB mode, the resulting ciphertext appears random:

```
68BAC980742B9EF80A27CBBBC0618E3876FF3D6C6E6A7B9CB8FCA486F9E11922776F
329140AABD223F003A8309DDB6B970C47BA2E249A0670592D74BCD07D51A3E150EF
885A5C8131E4210F
```

Since ECB encrypts identical plaintext blocks into identical ciphertext blocks, the structure of the original plaintext leaks into the ciphertext.

**Exploiting ECB for Token Manipulation:**

An attacker can manipulate the sequence of encrypted blocks to alter the token's meaning without decrypting it. Consider the mapping of plaintext blocks to ciphertext blocks:

![ECB example](https://raw.githubusercontent.com/PurityControl7/cookbooks/refs/heads/root/MISCELLANEOUS/ECB_example.png)

If the attacker rearranges these blocks—for instance, duplicating the second block (CIPH2) after the fourth block (CIPH4)—the decrypted plaintext could appear as:

```
rnd=2458992;app=iTradeEUR_l;uid=992;username=dafydd;time=634430423694
```

Now, the uid has changed from ```218``` to ```992```, meaning the application may now treat the attacker as a different user with higher privileges.

**Strengthening the Attack with Controlled Inputs:**

A more reliable attack involves choosing a specific username to manipulate block positioning. Suppose the attacker registers a username such that its placement aligns with the uid field when blocks are duplicated.

For example, registering ```username=daf1``` (instead of ```dafydd```) would structure the plaintext like this:

![ECB example 2](https://raw.githubusercontent.com/PurityControl7/cookbooks/refs/heads/root/MISCELLANEOUS/ECB_example2.png)

By duplicating the seventh block after the fourth block, the resulting decrypted plaintext could modify the uid to ```1```, which may correspond to an admin account or another privileged user.

By testing different usernames and observing the encrypted token’s structure, an attacker could cycle through all possible uid values and masquerade as any user. This kind of attack has been observed in vulnerable applications, especially when ECB encryption is combined with predictable data structures.

#### Cipher Block Chaining (CBC) Ciphers:

The flaws in Electronic Codebook (ECB) mode led to the development of **Cipher Block Chaining (CBC)** mode. In a CBC cipher, each plaintext block is XORed with the previous ciphertext block before encryption. This chaining process prevents identical plaintext blocks from producing identical ciphertext blocks, solving one of ECB’s major weaknesses. Here’s how CBC encryption works:

1. **Initialization Vector (IV):** The first plaintext block is XORed with a random IV before encryption. This ensures that even identical messages produce different ciphertexts.

2. **Chaining:** Each subsequent plaintext block is XORed with the previous block’s ciphertext before being encrypted.

3. **Decryption:** During decryption, the reverse process occurs—each decrypted block is XORed with the preceding ciphertext block to recover the original plaintext.

Let's say we want to encrypt the following plaintext blocks (simplified for clarity):

```
PLAINTEXT 1:  10110101  
PLAINTEXT 2:  11001011  
```

Using an **IV of 01100110**, the encryption process follows:

1. First Block XOR with IV:

```
10110101  
XOR 01100110  
---------------
11010011  (Resulting XOR output)
```

This output is then encrypted to form the first ciphertext block:

```
CIPHERTEXT 1: 10011010  (encrypted output)
```

2. Second Block XOR with Previous Ciphertext Block:

```
11001011  
XOR 10011010  
---------------
01010001  (Resulting XOR output)
```

This is then encrypted to form the second ciphertext block:

```
CIPHERTEXT 2: 01101100  (encrypted output)
```

Decryption follows the reverse process, where each decrypted block is XORed with the previous ciphertext block to recover the original plaintext.

Because CBC encryption introduces dependency between blocks, modifying a single ciphertext block affects all subsequent blocks during decryption. This feature has security benefits but also introduces potential vulnerabilities—especially if attackers can manipulate encrypted tokens in web applications.

Since CBC mode avoids some of the weaknesses of ECB, it is commonly used with symmetric encryption algorithms like AES and DES. However, in web applications, the way CBC-encrypted tokens are handled can introduce a vulnerability: an attacker may be able to modify parts of the decrypted data without knowing the secret key.

*How CBC Token Manipulation Works:**

Consider an application that uses CBC mode to encrypt user session tokens. These tokens contain structured data, such as a numeric **user ID (uid)**:

```
rnd=191432758301;app=eBankProdTC;uid=216;time=6343303;
```

After encryption, this structured data transforms into an apparently random token:

```
0FB1F1AFB4C874E695AAFC9AA4C2269D3E8E66BBA9B2829B173F255D447C5132158
6E459A93635636F45D7B1A43163201477
```

Since CBC mode decrypts each block by XORing it with the previous ciphertext block, an attacker who modifies part of the ciphertext can corrupt one block while predictably altering the next. If the attacker flips bits in the ciphertext of one block:

- That block will decrypt into garbage (unreadable data).

- But the **next** block will be XORed with modified values, leading to **controlled changes** in its plaintext.

This means an attacker could:

- Modify the user ID (uid) in a session token to impersonate another user.

- Escalate privileges by altering account roles (e.g., changing ```role=user``` to ```role=admin```).

**CBC Mode Token Manipulation & Attack Scenario:**

In applications using **CBC mode encryption** for session tokens, an attacker can exploit the way blocks are decrypted to modify certain values—such as user IDs—without knowing the encryption key. This attack leverages the **predictable impact of XOR operations** between modified ciphertext and decrypted plaintext.

In this attack, the attacker manipulates encrypted session tokens by modifying **one character at a time** and observing how the application responds. By systematically altering the encrypted token and analyzing changes in the application's behavior, an attacker can escalate privileges or impersonate another user.

Consider a structured session token before encryption:

```
rnd=191432758301;app=eBankProdTC;uid=216;time=6343303;
```

After encryption with CBC mode, it transforms into a seemingly random token:

```
0FB1F1AFB4C874E695AAFC9AA4C2269D3E8E66BBA9B2829B173F255D447C5132158
6E459A93635636F45D7B1A43163201477
```

Since CBC mode XORs each decrypted block with the previous ciphertext block, modifying one ciphertext block results in predictable changes in the next decrypted block. The attacker modifies the encrypted token by flipping bits in specific areas and resending it to the application.

The modified tokens decrypt as follows:

```
????????32858301;app=eBankProdTC;uid=216; t i me= g343303
????????32758321;app=eBankProdTC;uid=216;time=6343303;
rnd=1914????????;aqp=eBankProdTC;uid=216;time=6343303;
rnd=1914????????;app=eAankProdTC;uid=216;time=6343303;
rnd=191432758301????????nkPqodTC;uid=216;time=6343303;
rnd=191432758301????????nkProdUC;uid=216;time=6343303;
rnd=191432758301;app=eBa????????;uie=216;time=6343303;
rnd=191432758301;app=eBa????????;uid=226;time=6343303;
rnd=191432758301;app=eBankProdTC????????;timd=6343303;
rnd=191432758301;app=eBankProdTC????????;time=6343503;
```

Key observations:

- The block directly modified by the attacker decrypts to garbage (```????????```).

- The next block is affected in a predictable way due to CBC decryption rules.

- In some cases, the uid value changes from ```uid=216``` to ```uid=226```—allowing user impersonation.

**Exploitation Using Burp Suite:**

This attack can be automated using Burp Intruder’s “bit flipper” payload type:

1. Log in to the application with your own account.

2. Find a page that depends on the session token and displays the logged-in user (e.g., user profile page).

3. Set up Burp Intruder to target this page and mark the encrypted session token as the payload.

4. Configure the payload type as “bit flipping” on the token’s hex-encoded value.

5. Run the attack, which flips individual bits at different positions and sends the modified tokens.

**Interpreting Results:**

- No noticeable change? The first part of the token is likely unrelated to authentication.

- Redirects to login page? The token was corrupted and rejected.

- Different user ID appears? The attack was successful, proving user impersonation.

- Unknown user appears? The ```uid``` value changed but did not match an existing user.

Once a vulnerable block is identified, the attacker can use a number range payload in Burp Intruder to systematically test different uid values and impersonate a specific target user.

When exploiting this vulnerability, the goal is to impersonate other users—ideally an admin. If you're blindly modifying an encrypted token, success relies partly on luck. However, some applications unintentionally offer help. Many use the same encryption key and algorithm across functions, meaning any feature that reveals decrypted data can be leveraged to decrypt all protected information.

For example, one application encrypted filenames in download links to prevent path manipulation. But if a user requested a deleted file, the app returned an error message displaying the decrypted filename. This unintended "decryptor" allowed attackers to systematically reveal plaintext values of session tokens. Since these tokens stored structured data like usernames and roles (rather than numeric IDs), brute-force bit flipping would have been impractical. But by using the filename decryptor, an attacker could manipulate session tokens while observing the results—turning a blind attack into a precise one.

### Session Tokens in System Logs:

One major cause of session tokens leaking into system logs is when an application transmits them via URL query strings instead of using HTTP cookies or POST request bodies. This introduces serious risks, as tokens may end up in logs accessible to unauthorized parties, including:

- Users' browser history and logs

- Web server logs

- Corporate/ISP proxy server logs

- Reverse proxy logs within the hosting environment

- Referer logs of external websites visited from the application

Even if HTTPS is enforced throughout the application, session tokens in URLs remain vulnerable. This is because when users follow an external link, their browser may send the full URL—including the session token—in the Referer header.

**Exploiting Session Token Exposure via URLs**

A particularly dangerous attack vector involves exploiting applications that pass session tokens in URLs. An attacker could:

1. Send a crafted email to application users containing a link to a server under their control.

2. Embed an image or hidden resource in an HTML email that automatically loads when opened.

3. Capture session tokens in real-time from the Referer headers of affected users.

4. Hijack user sessions to send spam, harvest personal data, or change credentials.

Note: Older versions of Internet Explorer stripped the Referer header when following external links from HTTPS pages. However, browsers like Firefox still transmit it if the external site is also HTTPS, meaning session tokens in URLs remain vulnerable to leakage. (This behavior should be verified with up-to-date browser specs.)

#### Identifying and Exploiting Session Token Leaks:

1. **Map the application:** Identify all functions that log or expose session tokens. Determine who can access these logs—administrators, authenticated users, or even anonymous visitors.

2. **Find session tokens in URLs:** Even if tokens are generally secured, some parts of the app may improperly use URLs for token transmission (e.g., when interfacing with external systems).

3. **Inject off-site links:** Look for areas where users can submit links (e.g., forums, feedback forms, Q&A sections). Submit a URL pointing to a server you control, and check your logs to see if Referer headers leak any session tokens.

4. **Attempt session hijacking:** If tokens are exposed, try replacing your own session token with a captured one. In Burp Suite, set a global configuration to inject a stolen session cookie across all requests, allowing seamless session switching for testing.

### Vulnerable Mapping of Tokens to Sessions:

Various common vulnerabilities in session management mechanisms arise due to weaknesses in how the application maps session tokens to individual user sessions.

The simplest weakness is allowing multiple valid tokens to be concurrently assigned to the same user account. In virtually every application, there is no legitimate reason for a user to have more than one active session at a time. While users may abandon sessions—such as by closing a browser window or switching devices—if a user appears to be using two different sessions simultaneously, it often signals a security compromise. This could mean the user has shared their credentials or an attacker has obtained them through other means. Allowing concurrent sessions enables risky practices and lets attackers exploit stolen credentials without detection.

A related but distinct issue occurs when applications use static tokens. These tokens may appear similar to session tokens, but they do not function as such. In some applications, a user is assigned a token that is reissued every time they log in, and the application continuously accepts it as valid, regardless of whether a new session has been established. This misunderstanding of session management undermines security controls. Some applications implement this flawed behavior to create poorly designed "remember me" functionality, storing static tokens in persistent cookies.

In some cases, tokens themselves are vulnerable to prediction attacks, making the issue even more severe. Instead of compromising the sessions of currently logged-in users, a successful attack could compromise the accounts of all registered users indefinitely.

Other instances of flawed session management may involve improperly structured tokens. For example, consider a token structured as:

```
dXNlc j lkYWY7c j E9MTMwOTQxODEyMTMONTkwMTI =
```

When Base64-decoded, it reveals:

```
user=daf;r1=13094181213459012
```

If the ```r1``` component is sufficiently random, it may not be predictable based on observed values. However, if the application's session validation is flawed, an attacker might only need to submit any valid value for ```r1``` and any valid username to gain access to another user's session. This is effectively an access control vulnerability, as authentication and authorization decisions are being made based on user-supplied data outside of a properly managed session.

#### Identifying Weaknesses in Session Management:

1. **Check for Concurrent Sessions**

- Log in to the application twice using the same user account, either from different browsers or devices.

- See if both sessions remain active simultaneously.

- If they do, the application allows concurrent sessions, meaning an attacker who gains access to stolen credentials can use them without raising suspicion.

2. **Test for Static Session Tokens**

- Log in and out multiple times using the same account, switching between different browsers or devices.

- Observe whether the application issues a new session token each time or reuses the same one.

- If the same token is reused, the application is not implementing proper session handling, leaving it vulnerable.

3. **Analyze and Manipulate Token Structure**

- If session tokens appear to have a meaningful structure, try breaking them down into identifiable components.

- Identify parts that may reference the user separately from those that appear random or encrypted.

- Modify any user-related components to reference another known user and check if the application accepts the altered token, allowing you to impersonate them.

### Cookie Domain Scope:

A server cannot set cookies for just any domain. There are strict rules governing the scope of cookies:

- The domain specified in the cookie must either be the same as the application's domain or a parent domain.

- A cookie cannot be set for a top-level domain (e.g., .com or .co.uk), as this would allow a malicious server to manipulate cookies for other domains.

- If a server attempts to violate these rules, modern browsers ignore the ```Set-Cookie``` instruction.

If an application sets an overly permissive domain scope for its cookies, it may expose itself to security vulnerabilities.

Consider a blogging application hosted at ```wahh-blogs.com``` that allows users to register, log in, post blogs, and read other blogs. Upon login, a session token is issued and scoped to ```wahh-blogs.com```. Users can create their own blogs, which are accessible via personalized subdomains: ```herman.wahh-blogs.com```, ```solero.wahh-blogs.com```.

Because cookies are automatically sent to every subdomain within their scope, a logged-in user who visits another user’s blog unknowingly submits their session token with each request. If blog authors can inject arbitrary JavaScript into their pages, a malicious blogger could steal session tokens via a stored XSS attack.

The core issue arises from the way subdomains inherit cookies from their parent domain. There is no built-in mechanism in HTTP cookies to restrict cookies issued by the main domain from being accessible by subdomains.

The domain-based segregation of cookies is not as strict as the general same-origin policy (SOP). This leads to additional risks:

- Browsers ignore both protocol and port number when determining cookie scope.

- If an application shares a hostname with an untrusted application and relies solely on a difference in protocol (HTTP vs. HTTPS) or port number to separate them, it may still be vulnerable.

- Any cookies issued by the application could be accessed by another application that shares the hostname, bypassing intended security boundaries.

To assess potential risks related to cookie scope:

1. **Analyze All Cookies Issued by the Application**

- Check for any ```Domain``` attributes that expand the scope of cookies beyond what is necessary.

2. **Identify Overly Liberal Cookie Domains**

- If cookies are explicitly scoped to a parent domain, verify whether any other applications exist on that domain that could be exploited.

3. **Investigate Subdomain Risks**

- Even if an application restricts its cookies to its own domain, verify whether subdomains have functionality that could be leveraged to access session tokens.

4. **Map Out Potential Cross-Site Cookie Leaks**

- Determine all domain names that will receive the application's cookies.

- Identify any other web applications or services that could be manipulated to steal or misuse those cookies.

### Per-Page Tokens:

Finer-grained session control can enhance security and mitigate various session attacks by implementing per-page tokens alongside standard session tokens. With this approach, a unique page token is generated every time a user requests an application page (excluding static assets like images). This token is sent to the client via a cookie or a hidden HTML form field.

Each incoming request must include the correct page token from the previous response, in addition to the main session token. If the provided page token does not match the last issued value, the session is immediately terminated. This technique is commonly employed by security-critical applications, such as online banking platforms, to strengthen session management.

While per-page tokens introduce some navigation limitations—such as restrictions on using the back/forward buttons or multi-window browsing—they provide robust defenses against session fixation and session hijacking. If an attacker gains control of a session, their access will be revoked as soon as both they and the legitimate user attempt a request.

Additionally, per-page tokens can be leveraged to:

- Track user navigation patterns within the application.

- Detect unauthorized attempts to access functions out of sequence.

- Enhance protection against access control vulnerabilities.
