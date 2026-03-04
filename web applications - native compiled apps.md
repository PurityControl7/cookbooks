**Note:** This is the eleventh installment of my notes and reflections from The Web Application Hacker's Handbook. These reminders are neither exhaustive nor definitive—they're simply a personal tool to help me absorb, understand, and organize new material in a way that works for me.

# Attacking Native Compiled Applications:

Native compiled software—code that runs directly in an unmanaged execution environment—has historically been a rich hunting ground for severe vulnerabilities. Classic bug classes like **buffer overflows, format string vulnerabilities,** and **integer overflows** were practically endemic in software written in languages such as **C and C++**, where developers are responsible for manual memory management, pointer arithmetic, and boundary checks.

In contrast, most modern web applications are built using **managed execution environments** such as **Java, C#, and JVM/.NET-based frameworks.** One of their biggest advantages is that they abstract away raw memory handling, dramatically reducing the likelihood of entire categories of memory corruption bugs. Developers working in these environments typically don’t need to think about stack boundaries, heap layout, or pointer misuse—and as a result, many of the most catastrophic native-code flaws simply don’t arise.

However—*and this is where the cracks form*—native code has by no means disappeared.

Even today, you will encounter native code in web-facing contexts, often in less obvious ways:

- **Legacy components** wrapped inside otherwise managed applications

- **Native libraries** accessed via JNI (Java), P/Invoke (.NET), or FFI bindings

- **Performance-critical modules** written in C/C++ (image processing, crypto, compression, regex engines)

- **Third-party dependencies** compiled as native binaries

- **Hardware-backed web interfaces** (routers, firewalls, printers, IoT devices, industrial systems)

In fact, modern applications are *arguably more dangerous* here—not less—because native code is often hidden behind layers of abstraction, assumed to be “trusted,” and rarely audited with the same rigor as application-layer logic.

If you *cannot state with certainty* that your target contains *no native components,* it is worth performing *basic probing for classic native vulnerabilities.*

### Common Indicators of Native Code Exposure:

Certain application features and artifacts should immediately raise your suspicion:

- URLs, parameters, or resources containing names like:

	- ```.dll```, ```.exe```, ```.so```, ```.bin```

- Endpoints tied to:

	- File uploads
	
	- Image or media processing
	
	- Logging, debugging, or crash-reporting mechanisms
	
- Applications running on:

	- Network appliances
	
	- Embedded systems
	
	- Legacy enterprise software
	
- Functionality invoking:

	- External helpers
	
	- OS-level utilities
	
	- Custom binary parsers
	
Web interfaces exposed by hardware devices are especially notorious here—they often combine outdated C/C++ code with minimal hardening and poor input validation.

### Scope of Testing When Native Code Is Suspected:

If an application appears to contain **substantial native code**, your threat model should expand accordingly. In these cases, it may be appropriate to test **every piece of user-controlled input**, including:

- Parameter names *and* values

- Cookies

- HTTP headers

- File names and metadata

- Multipart boundaries

- Encodings and character sets

Native vulnerabilities don’t always care *where* the input comes from—only that it eventually reaches unsafe memory operations.

### Vulnerability Classes Covered in This Chapter:

This chapter focuses on three foundational categories of native software vulnerabilities:

**1. Buffer Overflows:**

Memory is written past the bounds of an allocated buffer, potentially leading to crashes, data corruption, or arbitrary code execution.

**2. Integer Vulnerabilities:**

Arithmetic errors such as integer overflows, underflows, and signedness issues that can bypass bounds checks or lead to incorrect memory allocations.

**3. Format String Vulnerabilities:**

Unsafe use of formatting functions (e.g., ```printf```-style calls) that allow attackers to read or write arbitrary memory.

For each category, we will outline:

- Common real-world vulnerability patterns

- Practical techniques for remote probing via a web interface

- Observable behaviors that may indicate unsafe native handling

This is a **vast** subject that extends well beyond web application security. If this chapter lights a fire (it should), deeper study is strongly recommended. If you want to descend properly into native exploitation territory, these remain excellent references:

- **The Shellcoder’s Handbook (2nd Edition)** Chris Anley, John Heasman, Felix Linder, Gerardo Richarte — Wiley, 2007

- **Gray Hat Hacking (2nd Edition)** Shon Harris, Allen Harper, Chris Eagle, Jonathan Ness — McGraw-Hill Osborne, 2008

**Important Warning: Denial of Service Risk:**

Remote probing for native vulnerabilities is *inherently dangerous.* Unlike flaws such as weak authentication or path traversal, merely *testing for* classic native bugs often causes:

- Unhandled exceptions

- Process crashes

- Service restarts

- Complete denial of service

In other words: *detection alone can be destructive.* If you are testing a live system, you *must* ensure that the application owner explicitly accepts this risk before proceeding.

### Side Note: Modern Exploitation Reality (Why This Is Harder—but Not Dead)

While classic native vulnerabilities still exist, exploiting them today is **far more constrained** than it was in the glory days of stack-smashing. Modern platforms typically deploy multiple defensive layers:

- **DEP / NX (Data Execution Prevention):** Prevents execution of code in non-executable memory regions. Shellcode-on-the-stack is mostly a ghost now unless DEP is misconfigured or bypassed.

- **ASLR (Address Space Layout Randomization):** Randomizes memory addresses, making reliable control-flow hijacking difficult without an information leak or brute-force window.

- **Stack Canaries:** Detect stack corruption before control flow is hijacked, often killing the process early and noisily.

- **Sandboxing & Process Isolation:** Even successful exploitation may land you inside a heavily restricted environment with limited privileges and short-lived impact.

The takeaway is *not* “don’t bother,” but rather this: **modern native exploitation often depends on chains,** not single bugs—information disclosure paired with memory corruption, logic flaws combined with native crashes, or unsafe native code embedded inside otherwise safe application logic.

From a web hacker’s perspective, native vulnerabilities are now less about instant shells and more about **denial of service, reliability testing, signal extraction,** and occasionally—when the stars misalign—**catastrophic failure.**

### Buffer Overflow Vulnerabilities:

A **buffer overflow vulnerability** occurs when an application copies user-controlled data into a memory buffer that is **too small to hold it,** without enforcing proper bounds checking. When this happens, data spills past the end of the buffer and **overwrites adjacent memory.**

Depending on *what* memory is overwritten and *how controllable* the overwrite is, an attacker may be able to:

- Crash the application (denial of service)

- Corrupt internal program state

- Redirect execution flow

- Execute arbitrary code

Historically, buffer overflows have been **the dominant source of critical vulnerabilities** in native software and are often described as *Public Enemy Number One* for C and C++ developers.

What makes a buffer overflow dangerous is **not simply memory misuse,** but *unchecked copying.* Over-provisioning memory (allocating a very large buffer “just in case”) can still be unsafe if:

- The input size is unbounded

- The allocation logic can be manipulated (e.g., integer overflows)

- The buffer is reused incorrectly

*The underlying sin is trusting size assumptions.* The exploitation mechanics differ, but the root cause is the same: **loss of control over memory boundaries.**

### Stack-Based Buffer Overflows:

Stack overflows commonly arise when an application uses an **unbounded copy operation**—such as ```strcpy```—to copy attacker-controlled data into a **fixed-size buffer** allocated on the stack. Stack programming refers to a programming paradigm that uses one or more stacks to manipulate data and pass parameters. In this approach, operations are performed using a last-in-first-out (LIFO) method, where data is pushed onto the stack and popped off for processing, often using postfix notation for commands.

Consider the following function:

```
bool CheckLogin(char* username, char* password)
{
    char _username[32];
    strcpy(_username, username);
    ...
}
```

Clarification:

- ```char _username[32];``` allocates **32 bytes on the stack**

- ```strcpy()``` copies bytes until it hits a null terminator

- No length check is performed

If ```username``` contains **more than 31 characters** (plus the null byte), ```_username``` will overflow. This is a classic, textbook vulnerability.

*Additional Notes:*

What is the *saved return address*? When a function is called, the CPU needs to remember **where to return after the function finishes.** At a high level, this happens as follows:

1. The caller places the **return address** (the next instruction to execute) onto the stack

2. The function allocates space for local variables (like ```_username```)

3. Execution proceeds inside the function

4. When the function returns, the CPU:

	- Pops the saved return address off the stack
	
	- Jumps to it
	
Because **local stack buffers are placed adjacent to this saved return address,** overflowing ```_username``` can overwrite it.

If an attacker overwrites the saved return address with a value of their choosing, the CPU will blindly jump to that address when the function returns—*effectively handing over control of execution.* This is the canonical stack-smashing scenario.

### Heap-Based Buffer Overflows:

Heap overflows involve the **same unsafe copying behavior,** but the destination buffer is allocated on the **heap** instead of the stack. A heap refers to a region of memory used for dynamic memory allocation, allowing programs to request and release memory blocks during runtime. It is different from stack memory, which has a fixed size and follows a last-in, first-out order.

Example:

```
bool CheckLogin(char* username, char* password)
{
    char* _username = (char*)malloc(32);
    strcpy(_username, username);
    ...
}
```

Code and memory clarification:

- ```malloc(32)``` allocates 32 bytes on the heap

- The heap stores **dynamically allocated memory** that persists beyond a single function call

- Unlike the stack, heap memory is managed by a **heap allocator**

Quick mental model:

- **Stack** → short-lived, structured, function-scoped

- **Heap** → long-lived, flexible, allocator-managed

If ```username``` exceeds 32 bytes, ```_username``` overflows into **adjacent heap structures.**

*Additional Notes:*

Most heap implementations organize memory as a **linked list of blocks.** Each allocated block is preceded (or followed) by **metadata**, commonly including:

- Size of the block

- Pointer to the previous block

- Pointer to the next block

Yes—this is *conceptually very similar to a filesystem:*

```
| Heap Concept      | Filesystem Analogy |
| ----------------- | ------------------ |
| Heap block        | File               |
| Control structure | Inode / metadata   |
| Forward pointer   | “Next file”        |
| Back pointer      | “Previous file”    |
| Freeing a block   | Deleting a file    |
```

Corrupt the metadata, and the system starts **trusting lies.**

**Forward and Backward Pointers (High-Level):**

At a high level, heap blocks are chained like this:

```
[Prev Block] <-> [Current Block] <-> [Next Block]
```

Each block contains pointers saying:

- “This is the block before me”

- “This is the block after me”

When a block is freed, the heap manager needs to **re-link the chain**, so the previous and next blocks point to each other.

If an attacker overflows a heap buffer and **overwrites these pointers,** they can trick the heap manager into performing writes like:

```
*(attacker_controlled_address) = attacker_controlled_value
```

This is known as an **arbitrary memory write**—one of the most powerful primitives in exploitation. Typical targets include:

- Function pointers

- Exception handler addresses

- Virtual method tables

- Security-critical flags

Once execution flow is redirected, arbitrary code execution becomes possible.

Heap-based exploitation is generally **more complex and fragile** than stack-based exploitation, but historically it has been extremely powerful—especially in environments where stack protections are strong but heap metadata is weakly protected.

Modern compilers and operating systems deploy multiple layers of protection against buffer overflows, including:

- Stack canaries

- Heap integrity checks

- ASLR (Address Space Layout Randomization)

- DEP / NX (Data Execution Prevention, a security feature that prevents code from being executed in certain areas of memory that are marked as non-executable)

- Hardened allocators

These defenses make exploitation **harder**, not impossible. Many real-world attacks still rely on chaining information leaks with memory corruption bugs. For deeper coverage of modern exploitation techniques and mitigations, *The Shellcoder’s Handbook* remains a gold standard.

### “Off-by-One” Vulnerabilities:

An **off-by-one vulnerability** is a special, deceptively mild-looking form of buffer overflow in which a programming error allows an attacker to overwrite **exactly one byte** (or a very small number of bytes) beyond the end of an allocated buffer. This sounds harmless. It absolutely is not.

Off-by-one bugs are especially dangerous because they often survive casual code review and can still corrupt **control-critical metadata** such as frame pointers, size fields, or string terminators.

Consider the following example:

```
bool CheckLogin(char* username, char* password)
{
    char _username[32];
    int i;

    for (i = 0; username[i] && i < 32; i++)
        _username[i] = username[i];

    _username[i] = '\0';
}
```

Breakdown:

- ```_username[32]``` allocates **32 bytes** on the stack

- Valid indices are ```0``` through ```31```

- The loop copies bytes while:

	- the source string hasn’t ended (```username[i]```)
	
	- ```i < 32```
	
So far, so good.

**Where it breaks:**

If ```username``` is **32 bytes or longer**:

 - The loop exits with ```i == 32```
	
 - The code then executes:
	
```
_username[32] = '\0';
```

- This writes **one byte past the end of the buffer**

That single null byte overwrites **adjacent stack memory.** This is a textbook off-by-one overflow.

Now let’s demystify the scary paragraph about frame pointers and “lower-order bytes.” Each function call gets a **stack frame**, which typically contains:

- Local variables (like ```_username```)

- A **saved frame pointer** (used to restore the caller’s stack)

- A **saved return address**

These values are packed tightly together in memory.

**Why overwriting one byte matters:**

On many architectures, addresses are stored **least-significant byte first** (little-endian). That means the *lowest byte* of a pointer has a disproportionate effect on *where it points.*

Imagine an address as a **four-tile stepping stone path,** laid left to right in memory, but the CPU reads it **backwards.** The *first* tile it steps on (the lowest byte) decides which **neighborhood** you’re in; the remaining tiles just fine-tune the exact doorstep. If that first tile gets nudged—even turned into zero—you don’t drift a little… you **teleport** into a nearby region, often straight into your own buffer. That’s why a single null byte feels small in code, yet enormous in consequence: it quietly bends the map beneath the program’s feet.

If your off-by-one overwrite:

- Zeros out the **lowest byte** of the saved frame pointer

- That pointer may suddenly point *into your buffer*

- Which contains attacker-controlled data

When the calling function later returns, the corrupted frame pointer can cause execution to:

- Unwind the stack incorrectly

- Read attacker-controlled values as return addresses

- Redirect control flow

Think of the stack as a **trail of breadcrumbs** dropped as functions call other functions. *Unwinding the stack* is the act of walking backward along that trail, step by step, to return home. If a frame pointer is corrupted, the program follows **fake breadcrumbs**—crumbs the attacker planted inside the buffer—so it “returns” to places that were never real call sites. At that moment, the program isn’t executing logic anymore; it’s sleepwalking through attacker-written memory, convinced it’s retracing its own past.

On a side note, C exists because sometimes you *want* to touch the metal directly: minimal overhead, predictable memory layout, no runtime babysitter, no GC pauses—perfect for kernels, drivers, firmware, routers, crypto, real-time systems. Python (and friends) trade raw control for safety and speed of development; C trades safety for **determinism and performance,** and that bargain still matters in places where milliseconds or bytes are sacred.

We keep C around not because it’s friendly, but because it’s *honest*—it lets you hang yourself, but it also lets you build things nothing else can. And that tension is exactly why these ghosts keep slipping into web-facing systems through native extensions and “just one small helper binary.”

So yes—**one byte is enough.**

Now consider this attempted fix:

```
bool CheckLogin(char* username, char* password)
{
    char* _username = (char*)malloc(32);
    strncpy(_username, username, 32);
}
```

**Why this looks safe:**

- Fixed-size heap allocation

- Bounded copy using ```strncpy```

- No obvious overflow

**Why it’s still broken:**

```strncpy()``` does **not guarantee null termination.**

If ```username``` is 32 bytes or longer:

- All 32 bytes are copied

- No ```'\0'``` is appended

- ```_username``` is no longer a valid C string

This is not an overflow—but it is **string corruption.**

**Why Missing a Null Terminator Is Dangerous:**

C strings do not store their length. A string ends when the program encounters a **null byte** (```0x00```). If the terminator is missing:

- The string continues reading into **adjacent memory**

- Until a random zero byte is found

This can lead to:

- Information disclosure

- Cross-request data leakage

- Authentication bypasses

- Logic errors that look “impossible” at the source-code level

#### Real-World Case Study: Cross-User Data Leakage

The authors encountered this exact bug in a web application running on a hardware device. The application used a relay page that accepted arbitrary POST parameters and reflected them back as hidden fields:

```
POST /formRelay.cgi HTTP/1.0
Content-Length: 3

a=b
```

Response (cleaned up for readability):

```
<form name="FORM_RELAY" action="page.cgi" method="POST">
  <input type="hidden" name="a" value="b">
</form>
```

So far, harmless.

**Triggering the Bug:**

When **4096 or more bytes** were submitted:

```
POST /formRelay.cgi HTTP/1.0
Content-Length: 4096

a=bbbbbbbbbbbbbbbbbbbbbbbb...
```

The response suddenly included **parameters from a previous request,** submitted by another user:

```
<input type="hidden" name="a" value="bbbbbbbb...">
<input type="hidden" name="strUsername" value="agriffiths">
<input type="hidden" name="strPassword" value="aufwiedersehen">
<input type="hidden" name="Log_in" value="Log+In">
```

This is catastrophic.

**Root Cause Explained Cleanly:**

- Parameters were stored as **null-terminated strings**

- Each request used **4096-byte memory blocks**

- Input was copied using a *checked* operation (no overflow)

- Overlong input filled the buffer completely

- The null terminator was lost

- String parsing continued into **adjacent memory**

- Adjacent memory contained **another user’s data**

No crash or exception, just silent, ongoing data exfiltration.

**Why This Is Especially Dangerous:**

Off-by-one and unterminated-string bugs:

- Often bypass traditional overflow defenses

- Rarely cause immediate crashes

- Can persist unnoticed for years

- Enable passive surveillance attacks

In this case, attackers could continuously poll the page and log every credential submitted by other users.

**Key Takeaway:** Memory safety bugs do not require large overflows. *One missing byte is enough to erase isolation.*

## Detecting Buffer Overflow Vulnerabilities:

The core methodology for detecting buffer overflow vulnerabilities is brutally simple: *send data that is longer than the application expects and watch how it breaks.*

While some edge-case bugs only appear at very specific lengths, most real-world overflows can be detected by submitting input that significantly exceeds common buffer sizes.

**Why “Odd” Lengths Matter?**

Programmers love *round numbers*—both decimal and hexadecimal—when allocating buffers:

- 32 / 64 / 128

- 100 / 256

- 1024 / 2048

- 4096

That’s why the suggested probe sizes look like this:

```
1100
4200
33000
```

What these do:

- **1100** → slightly larger than 1024

- **4200** → slightly larger than 4096

- **33000** → exceeds most “reasonable” assumptions

You’re not trying to be precise yet—you’re fishing for *low-hanging fruit.* If **any** of these cause instability, you’ve likely hit native code making unsafe size assumptions.

**One Parameter at a Time (Very Important)!**

Yes—this *is* parameter fuzzing, but along a **length axis**, not a payload axis. Target **one parameter at a time** while keeping everything else valid and boring. This maximizes code-path coverage and avoids confusing side effects where multiple parameters interact. Think of it as isolating a wire before you overload it.

*Tooling: Automating Length-Based Payloads*

*Burp Suite* makes this trivial:

- Intruder → Payload type: *Character blocks*

- Set:

	- Character: ```A``` (or any permitted char)
	
	- Min length / Max length
	
	- Step size (e.g. 100, 500)
	
This generates clean, repeatable length-based probes.

*OWASP ZAP* can do this too:

1. Right-click request → *Attack* → *Fuzz*

2. Select the parameter

3. Add a *Fuzzer Payload*

4. Choose:

	- *Strings*
	
	- *String Length Fuzzer* (or custom generator)
	
5. Configure:

- Character set (e.g. ```a```)

- Min / Max length

6. Start fuzzing and watch responses

Not as slick as Burp—but perfectly usable.

**What Counts as an Anomaly?**

Buffer overflows often crash *hard,* but not always immediately. Watch for:

- **HTTP 500** errors that don’t occur with other malformed input

- Messages referencing **native components,** libraries, or memory

- *Malformed or truncated responses*

- TCP connection resets or silent closes

- The application suddenly becoming **unresponsive**

These are *symptoms*, not proof—but they’re strong signals.

**Heap Overflows: Delayed Damage**

Heap corruption often detonates *later,* not at the moment of overflow.

You may need to:

- Re-submit normal requests after a large payload

- Observe crashes triggered by unrelated actions

- Correlate failures with earlier long-input probes

Heap bugs are slow-burn explosives.

**Off-by-One Bugs: No Crash, Still Dangerous**

Off-by-one vulnerabilities often:

- Do **not** crash the application

- Cause subtle data leakage

- Produce “impossible” output combinations

Unexpected extra fields, stale values, or cross-user data are huge red flags here.

**Dealing with Length Filters (URLs & Validation):**

If you see errors like:

```
“URL too long”
```

You’re hitting **front-end length limits,** not the vulnerable code.

*How to adjust buffer sizes:*

- Identify the *maximum accepted length* (often ~2000 chars for URLs)

- Stay *just under* that limit

- Switch to:

	- POST bodies
	
	- Cookies
	
	- Headers
	
Remember: *overflows can exist behind filters.* You don’t need huge input—just *slightly too much* for the backend.

**Character Restrictions? Mirror the Input!**

If a parameter only allows alphanumerics:

- Capture a *valid request*

- Extend the parameter using *the same characters*

- Avoid symbols unless permitted

Length breaks memory. Characters just decide whether you get inside.

**Exploitation Is Hard!**

Even when a buffer overflow exists, *remote code execution is rare* in modern environments. That said, detection alone can still yield:

- Denial of service

- Information disclosure

- Cross-user leakage

- Chained exploitation opportunities

**Further Reading:**

- *Blind Exploitation* – by Peter Winter-Smith

- Research from NCC Group (successor to NGSSoftware)

- Chapters in *The Shellcoder’s Handbook* on remote exploitation constraints

**Final Takeaway:** You are not hunting shells. You are hunting *symptoms of unsafe memory assumptions.*

### Integer Vulnerabilities:

Integer-related vulnerabilities arise when an application performs arithmetic on a value—often a **length**, **count**, or **offset**—and fails to account for how integers actually behave at the machine level. The key danger is this: *the program believes a number is safe, but the CPU has already wrapped it into something else.*

Two classes matter most here:

- Integer overflows

- Signedness errors

#### Integer Overflows:

An **integer overflow** occurs when a calculation produces a value that exceeds the maximum (or minimum) representable value for that integer type. Instead of throwing an error, the value *wraps around.*

*Simple illustration:*

Assume an *unsigned 8-bit integer* (range: ```0–255```):

```
255 + 1 = 0
```

The value doesn’t become 256—it wraps back to zero. Likewise:

```
0 - 1 = 255
```

This behavior is not a bug in the CPU—it’s *defined behavior* for unsigned integers. Now imagine this happening in memory allocation logic.

#### Overflow-Induced Heap Overflow (Classic Pattern):

Here’s the example, cleaned up for clarity:

```
bool CheckLogin(char* username, char* password)
{
    unsigned short len = strlen(username) + 1;
    char* _username = (char*)malloc(len);
    strcpy(_username, username);
}
```

What the programmer *intended:*

1. Measure the length of ```username```

2. Add 1 byte for the null terminator

3. Allocate a buffer of exactly that size

4. Copy the string safely

This *looks* careful. It is not.

*Where It Breaks:*

- ```unsigned short``` is a **16-bit** integer

- Its maximum value is **65,535**

- ```strlen(username)``` returns ```size_t``` (usually 32 or 64 bits)

- That value is silently **truncated** when assigned to ```unsigned short```

*The fatal case:*

If the attacker submits a username of length **65,535 bytes:**

```
strlen(username)     = 65535
strlen(username) + 1 = 65536
```

But ```unsigned short``` cannot represent 65,536. So the value **wraps**:

```
65536 → 0
```

Now the program does this:

```
malloc(0);
strcpy(_username, username);
```

Result:

- Zero-byte heap allocation

- Unbounded copy

- *Heap overflow*

The attacker didn’t bypass validation. They *used it against the program.* This pattern is especially nasty because:

- The code *looks defensive*

- Static analysis often misses it

- Length checks *appear* present

- The bug only triggers at extreme sizes

This is a *logic inversion vulnerability:* the safety mechanism becomes the exploit primitive.

*Additional Notes:*

A *zero-byte heap allocation* happens when ```malloc(0)``` is called—usually because an integer wrapped around to zero after some “safe-looking” math. The allocator may return a *non-NULL pointer,* but that pointer does *not* point to usable storage you’re allowed to write into. If the program then blindly copies data into it (like with ```strcpy```), *any write at all* is already an overflow. That’s why this bug is so sneaky: the allocation succeeds, the code keeps going, and memory corruption starts immediately without any obvious red flags.

**Key Lesson: Types Matter More Than Checks**

The vulnerability exists *not because of missing checks,* but because of:

- Incorrect integer type selection

- Implicit truncation

- Unsafe arithmetic on length values

*Safer version (conceptual):*

```
size_t len = strlen(username) + 1;

if (len > MAX_USERNAME_LEN)
    return false;

char* _username = malloc(len);
```

Even then, you must still consider:

- Maximum allocatable size

- Overflow in ```strlen + 1```

- Application-level constraints

**Mental Model to Keep:** Memory bugs don’t start at ```strcpy```. They start at arithmetic. If the number lies, the buffer will too.

#### Signedness Errors:

*Signedness errors* arise when an application mixes **signed** and **unsigned** integers while handling sizes, lengths, or offsets—and then quietly lets the compiler “fix” the mismatch. The danger is simple but brutal: *a negative number can turn into a very large positive number without anyone noticing.*

This typically happens in one of two ways:

- A signed value is compared to an unsigned value

- A signed value is passed to a function that expects an unsigned value

In both cases, implicit type conversion kicks in, and the signed value is treated as its unsigned equivalent.

**Signed vs Unsigned:**

Let’s ground this with a clear comparison. Assume a 32-bit integer:

```
| Type           | Range                           |
| -------------- | ------------------------------- |
| `signed int`   | −2,147,483,648 → +2,147,483,647 |
| `unsigned int` | 0 → 4,294,967,295               |
```

Now here’s the trap:

```
signed int len = -1;
unsigned int u = len;
```

The value of ```u``` becomes:

```
4294967295
```

Same bits. Totally different meaning. The compiler is not confused. The programmer is.

**Signedness Bug in Practice (Stack Overflow Variant):**

Here’s the example:

```
bool CheckLogin(char* username, int len, char* password)
{
    char _username[32];

    if (len < 32)
        strncpy(_username, username, len);
}
```

What the programmer intended:

- ```len``` represents the length of ```username```

- Only copy if the length fits into ```_username```

- Use ```strncpy``` to avoid overflow

This *looks* safe.

**Step-by-Step Failure Mode:**

*Case 1: Normal input*

If ```len = 10```:

- ```10 < 32``` → true

- ```strncpy(..., 10)``` copies safely

All good.

*Case 2: Negative length (the attack)*

If an attacker supplies:

```
len = -1
```

Now watch carefully.

*Step 1: The comparison*

```
if (len < 32)
```

- ```-1 < 32``` → **true**

- The check passes

*Step 2: The copy*

```
strncpy(_username, username, len);
```

But ```strncpy``` expects its length parameter to be of type ```size_t``` (which is **unsigned**). So the compiler silently converts:

```
-1  →  0xFFFFFFFF  →  4,294,967,295
```

Result:

- ```strncpy``` attempts to copy *billions of bytes*

- ```_username[32]``` is obliterated

- You get a *classic stack-based buffer overflow*

The guardrail didn’t just fail—it became the launch ramp. This vulnerability exists because:

- The comparison uses **signed logic**

- The copy uses **unsigned logic**

- The conversion happens **implicitly**

- No warning is required by the language

Everything compiles. Everything looks intentional. This attack is most feasible when:

- The length is **supplied directly by the client**

	- Hidden form fields
	
	- API parameters
	
	- JavaScript-calculated values
	
But there’s a second, sneakier path: **integer overflow → signedness error.** If ```len``` is stored in a **small signed type** (e.g. ```short```) and the server computes it:

- Attacker submits an overlong string

- The length overflows

- The result becomes negative

- That negative value later passes signed checks

- Then explodes when used as unsigned

This is how *integer overflows chain into signedness bugs.* Signedness errors don’t break memory directly. **They break the meaning of numbers.** Once size loses meaning, every buffer check becomes decorative.

*Defensive Wisdom:*

- Never mix signed and unsigned values in size logic

- Use ```size_t``` consistently for lengths

- Reject negative values *explicitly*

- Treat client-supplied lengths as hostile

- Remember: comparisons and copies may use *different types*

### Detecting Integer Vulnerabilities:

Integer vulnerabilities most often surface at **trust boundaries**, where numeric values cross from client to server. Any time the application relies on a client-supplied integer to describe size, length, or count, your hacker senses should start humming. There are two common patterns to look for.

**Client-Supplied Integers as Explicit Parameters:**

In many applications, integers are passed in a straightforward, human-readable way: query parameters, cookies, POST bodies, or JSON fields. These values are typically encoded as ASCII decimal numbers and are easy to spot during normal traffic inspection. A classic example looks like this:

```
POST /upload HTTP/1.1
Content-Type: application/x-www-form-urlencoded

filename=report.txt&length=128
```

Here, the ```length``` parameter claims to describe the size of the submitted data. Any field that *appears* to describe the length of a string, file, array, or buffer is an immediate candidate for integer testing — especially if the corresponding data is also supplied in the same request.

**Integers Embedded in Binary Data:**

In more complex applications, integer values may be hidden inside larger blobs of binary data. This is common when data originates from client-side components (for example, legacy ActiveX controls), serialized objects, or opaque tokens stored in cookies or hidden form fields. In this scenario, length values are harder to identify. They are often:

- Represented in hexadecimal

- Stored immediately before the buffer or string they describe

- Encoded using Base64 or similar schemes to survive HTTP transport

A typical pattern is: **[length field][data buffer]** — if you find one, you should suspect the other.

**Hacking Methodology: Boundary Abuse**

Once you’ve identified a candidate integer field, the goal is to **push it across representational boundaries** — places where the value flips meaning due to size, signedness, or wrapping behavior.

*Step 1: Boundary Payloads*

For each target, submit values that sit right on the edge of common integer sizes:

- ```0x7f``` → ```0x80``` (127 → 128): signed 8-bit boundary

- ```0xff``` → ```0x100``` (255 → 256): unsigned 8-bit boundary

- ```0x7fff``` → ```0x8000``` (32767 → 32768): signed 16-bit boundary

- ```0xffff``` → ```0x10000``` (65535 → 65536): unsigned 16-bit wrap

- ```0x7fffffff``` → ```0x80000000``` (2,147,483,647 → 2,147,483,648): signed 32-bit boundary

- ```0xffffffff``` → ```0x0``` (4,294,967,295 → 0): unsigned 32-bit wrap

**Moral of the story:** these numbers are not random — each pair straddles a point where the CPU or compiler *changes how it interprets the value.* If the developer didn’t account for that transition, the application may allocate too little memory, perform a dangerous copy, or mis-handle logic checks.

*Step 2: Endianness Matters*

When integers are transmitted in binary or hexadecimal form, you must test **both byte orders:**

- *Big-endian:* most significant byte first (```7fff```)

- *Little-endian:* least significant byte first (```ff7f```)

*Why this matters:* different platforms, libraries, and serialization routines expect different byte orders. If you only test one, you may miss the exact interpretation the server uses internally.

If hexadecimal values are sent as ASCII text, also mirror the application’s letter casing (```a–f``` vs ```A–F```) to avoid decoding quirks.

*Step 3: Watch for Subtle Breakage*

Just like with buffer overflows, integer vulnerabilities often don’t scream — they *whisper.* Pay attention to:

- Application crashes or resets

- Truncated responses

- Unexpected error messages

- Strange timing changes

- Logic behaving “impossibly” (zero-length objects, negative balances, infinite loops)

These are often the only clues that an integer has crossed a dangerous boundary inside the application. Integer bugs are *politeness exploits* — the program assumes you’re being honest, the compiler assumes the developer knew what they were doing, and the CPU assumes math is math. You’re just there to gently prove all three wrong.

### Format String Vulnerabilities:

Format string vulnerabilities occur when **user-controlled input is used as the** ***format string itself*** in a ```printf```-style function, rather than as a normal data argument.

In C, functions like ```printf```, ```sprintf```, ```fprintf```, and friends belong to the *variadic* family — meaning they accept a **variable number of arguments.** The function has no built-in way to know how many arguments were passed or what types they are. Instead, it relies entirely on the **format string** to describe:

- how many arguments exist

- what types they are

- how they should be interpreted and printed

This is where the danger lives.

**How the Format String Works (Conceptually):**

A ```printf``` call looks like this:

```
printf("format string", arg1, arg2, arg3, ...);
```

The **format string** is a template containing *format specifiers* like:

- ```%d``` → integer (decimal)

- ```%s``` → string

- ```%x``` → hexadecimal

- ```%p``` → pointer

- ```%n``` → *write count to memory* (we’ll get to this demon shortly)

Each specifier tells ```printf```: *“Pull the next value from the stack and interpret it* ***this way.”*** If the format string lies, ```printf``` blindly obeys.

**Basic Example:**

```
printf("The value of count is %d", count);
```

What happens here:

- ```%d``` tells ```printf``` to expect an integer

- ```count``` is fetched from the stack

- its value is rendered in decimal form

Safe, boring and civilized.

**Enter the Dangerous One: ```%n```**

The ```%n``` format specifier is special — and uniquely dangerous. Unlike other specifiers, ```%n``` **prints nothing.** Instead, it does this: *Writes the number of bytes printed* ***so far*** *into the memory address supplied as its argument.*

**```%n``` in Action — Line by Line:**

```
int count = 43;
int written = 0;
```

- ```count``` holds a value we’ll print

- ```written``` will receive the byte count

```
printf("The value of count is %d%n.\n", count, &written);
```

Execution flow:

1. ```"The value of count is "```

→ printed first (22 bytes)

2. ```%d```

→ prints ```43``` (2 bytes)

3. ```%n```

→ writes **24** (22 + 2) into ```written```

4. ```".\n"```

→ printed afterward, but **not included** in ```%n```’s count

Then:

```
printf("%d bytes were printed.\n", written);
```

Outputs:

```
The value of count is 43.
24 bytes were printed.
```

Nothing magical — just extremely dangerous if abused.

**Why This Becomes an Exploit?**

Here’s the key failure mode: ```printf``` **does not verify** that the number of format specifiers matches the number of supplied arguments.

So if the format string contains *more specifiers than arguments,* ```printf``` keeps pulling “arguments” from the stack anyway. If an attacker controls the format string, they can:

- Read arbitrary stack values using ```%x```, ```%p```, ```%s```

- **Write arbitrary values** using ```%n```

- Control *how many bytes* are written by padding output width

- Control where the write happens by manipulating stack alignment

This enables overwriting:

- Saved return addresses

- Function pointers

- Exception handler pointers

At that point, control flow bends — just like in a stack overflow, but **without overflowing anything.**

**Why Format String Bugs Are So Nasty?**

These are *social-engineering vulnerabilities for compilers.*

- The programmer assumes the string is harmless

- The compiler assumes the programmer was careful

- ```printf``` assumes the format string is gospel

**User input must never be used as a format string — only as data.**

Safe pattern:

```
printf("%s", user_input);
```

Dangerous pattern:

```
printf(user_input);
```

That single missing ```"%s"``` is the difference between logging and exploitation.

**Additional Notes:**

Picture the stack as a vertical pile of plates: first the **format string pointer**, then the **explicit arguments**, then a bunch of **other junk** (saved EIP/RIP, base pointer, locals, etc.). When ```printf``` runs, it doesn’t *know* how many real arguments exist — it just walks down the stack **one specifier at a time**, blindly trusting the format string. Every ```%x```, ```%p```, ```%s``` says “grab the next plate,” even if that plate is actually a return address or function pointer. ```%n``` is the moment where the spell snaps: instead of reading, it **writes** to whatever “plate” it lands on — turning stack disclosure into stack corruption.

That’s why format strings feel like controlled astral projection: you scroll through memory with reads, line yourself up, then *push a value back into reality.* Same vibe as stack overflows, just sneakier — no smashing, only *persuasion.*

### Detecting Format String Vulnerabilities:

Format string vulnerabilities are best detected by **actively injecting format specifiers** into application inputs and observing how the application behaves in response. Much like buffer overflow testing, this kind of probing is inherently dangerous: a vulnerable application is very likely to crash when mishandling a malicious format string. The goal here is not elegance — it’s to make the application **misinterpret user input as a format string** and force it to read from or write to unintended memory locations.

**Core Detection Technique:**

The basic strategy is simple: *“If I give the application format specifiers, does it treat them as data — or as instructions?”* If the latter, you’ve found something spicy.

*Hack Steps:*

1. **Spray the Stack with Format Specifiers:**

For each parameter (query string, POST field, cookie, header), submit strings containing **large numbers of ```%s``` and ```%n```** specifiers:

```
%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

*Why this works:*

- ```%s``` tells the function: *“Treat the next stack value as a pointer to a string and dereference it.”*

*Note:* Dereferencing in programming refers to accessing the value stored at the memory address pointed to by a pointer. It is commonly done using the dereference operator, typically represented by an asterisk (```*```), which allows you to manipulate the actual data rather than just the memory address.

- If that pointer is garbage → *access violation / crash*

- ```%n``` tells the function: *“Write to the address found on the stack.”*

- Even a single ```%n``` can be fatal if not blocked

Many modern runtimes disable ```%n```, but ```%s``` is still extremely effective for detection because it turns stack garbage into forced memory reads.

2. **Windows ```FormatMessage```:**

The function ```FormatMessage``` is a Windows API used to construct formatted error and status messages. Unlike ```printf```, ```FormatMessage``` uses *numbered placeholders:*

```
%1
%2
%3
```

These refer to argument positions, not a sequential walk like ```printf```.

*Detection strings* for ```FormatMessage``` are something like:

```
%n%1!n!%2!n!%3!n!
!s!%1!s!%2!s!%3!s!
```

look bizarre, but here’s the *moral of the story:*

- ```!s!``` forces string dereferencing

- ```!n!``` attempts memory writes

- ```%1```, ```%2```, ```%3``` probe argument indexing

- The goal is to *force the function to consume arguments that were never supplied*

If the application crashes, leaks memory, or behaves oddly → the format string is attacker-controlled.

3. **URL-Encoding Is Mandatory:**

Always remember:

```
%  →  %25
```

If you forget this, your payload never reaches the vulnerable code — it gets eaten by URL parsing long before it hits ```printf``` or ```FormatMessage```.

4. **Watch for the Same Red Flags as Overflows:**

Monitor for:

- HTTP 500 errors

- Partial or corrupted responses

- Sudden connection drops

- Application freezes or restarts

- Entire service becoming unresponsive

Format string bugs are *loud.* When they trigger, they usually scream.

**Summary and Conclusions:**

Native-code vulnerabilities are rarer in modern web apps, but when they appear, they are *high-impact and unforgiving.* They show up most often in:

- Embedded devices

- Network appliances

- Legacy components

- Native extensions called from managed code

Unlike XSS or auth bugs, *even detection can cause denial of service.* Testing without permission is reckless; testing with permission is powerful. Format strings, in particular, are elegant monsters: no shellcode or spraying — just letting the program betray itself. If buffer overflows are blunt force, format strings are whispered instructions the machine obeys without question.

### Reflection Questions:

1. *Unless any special defenses are in place, why are stack-based buffer overflows generally easier to exploit than heap-based overflows?*

Stack-based overflows are usually easier to exploit because the stack has a **predictable layout**. Critical control data — such as the **saved return address and saved frame pointer** — is placed at fixed, known offsets relative to local buffers. Overwriting these lets an attacker directly redirect execution.

Heap overflows are harder because heap layout is **dynamic**, varies between runs, and exploitation usually requires corrupting allocator metadata or targeting indirect pointers rather than immediate control-flow data.

2. *In the C and C++ languages, how is a string's length determined?*

C-style strings have **no intrinsic length**. Their length is determined by scanning memory until a **null terminator** (```\0```) is encountered. Functions like ```strlen()``` simply count bytes until they hit that terminator. This is precisely why so many overflows exist: the language itself provides **no bounds metadata.**

3. *Why would a buffer overflow in an off-the-shelf network device be more exploitable than one in a proprietary web application?*

Because the attacker can obtain the exact same hardware and firmware and debug it locally. This allows precise memory mapping, repeated crashes, instrumentation, and exploit refinement — none of which are feasible against a remote proprietary app. Remote-only exploitation removes observability, repeatability, and debugging — all fatal to reliable exploitation.

4. *Why would the following fuzz string fail to identify many format string vulnerabilities?*

```
%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%
```

There are two reasons:

- ```%``` must usually be **URL-encoded** as ```%25```, or it will be stripped or rejected before reaching the vulnerable function.

- Many environments block ```%n``` specifically, while remaining vulnerable to ```%s```, ```%x```, or positional specifiers. Relying only on ```%n``` is too narrow and too modern-defense-aware.

5. *Intermittent crashes when fuzzing native code — what’s the most likely cause?*

This behavior almost certainly indicates **heap corruption**. Heap overflows often damage allocator metadata or adjacent objects, causing crashes **later**, during unrelated allocations or frees. The delay, randomness, and sensitivity to request order are classic heap symptoms.
