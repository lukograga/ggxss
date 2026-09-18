Google XSS Game – Levels 1 to 6
Vulnerability Analysis, Source-to-Sink Flow, and Example Lab Payloads
This report summarizes the six levels of the Google XSS Game in a controlled training environment. The focus is on understanding the vulnerability, identifying the source and sink, recognizing the input context, and understanding why an example payload executes.
1. Executive Summary
The Google XSS Game demonstrates different ways attacker-controlled input can reach a browser execution context. Across Levels 1–6, the exercises progress from simple reflected XSS to stored XSS, DOM-based XSS, JavaScript-context injection, JavaScript URL injection, and dynamic script loading.
Level	Main Concept	Input / Source	Vulnerable Context / Sink	Example Lab Payload
1	Reflected XSS	Search/query input	HTML response	<script>alert(1)</script>
2	Stored XSS	Post/comment input	innerHTML / HTML context	<img src=x onerror=alert(1)>
3	DOM XSS	location.hash	jQuery .html()	#' onerror='alert(1)'
4	JavaScript-context injection	timer parameter	onload JavaScript string	');alert(1);//
5	JavaScript URL injection	next parameter	href="{{ next }}"	javascript:alert(1)
6	Dynamic script loading	location.hash	script.src / dynamic script	External JavaScript URL
2. Level 1 – Hello, World of XSS
Vulnerability: Reflected XSS
The application takes user-controlled search input and reflects it into the HTML response. If the input is not safely encoded for the HTML context, the browser may interpret injected markup as real HTML.
Example payload:
<script>alert(1)</script>
Source-to-execution flow:
User input → search parameter → server response → HTML parser → <script> → JavaScript execution
Key lesson: Reflected XSS occurs when untrusted input is returned in a response and reaches an executable browser context.
3. Level 2 – Persistence is Key
Vulnerability: Stored XSS
The application accepts input that is stored and later displayed to users. The important difference from Level 1 is that the malicious content can persist in the application's stored data.
Example payload:
<img src=x onerror=alert(1)>
The payload creates an image element. Because the image source is invalid, the browser triggers the onerror event, which contains JavaScript.
Source-to-execution flow:
User input → stored content → innerHTML → <img> → image error → onerror → alert(1)
Key lesson: XSS does not require a <script> tag. HTML elements with executable event handlers can also create an XSS path.
4. Level 3 – That Sinking Feeling
Vulnerability: DOM-based XSS
The application reads the URL fragment using location.hash and passes the value into JavaScript code. The value is eventually inserted into the page using jQuery's .html() method.
Important source and sink:
Source: location.hash
Sink: $('#tabContent').html(html)
Example payload:
#' onerror='alert(1)'
Source-to-sink flow:
URL #fragment → location.hash → chooseTab(num) → HTML string → .html(html) → browser parses HTML → XSS
Key lesson: In DOM XSS, the vulnerable behavior can occur entirely in client-side JavaScript without the malicious value being reflected by the server in the original HTML response.
5. Level 4 – Context Matters
Vulnerability: Injection into a JavaScript string inside an HTML event-handler attribute
The timer value is inserted into an onload attribute similar to: onload="startTimer('USER_INPUT');". The input therefore appears inside a JavaScript string. A successful test must change the JavaScript structure rather than simply adding ordinary HTML.
Example lab payload:
');alert(1);//
Conceptual transformation:
Original: onload="startTimer('USER_INPUT');"
After injection, the input can conceptually close the original string, execute alert(1), and comment out the remaining characters.
Source-to-execution flow:
timer parameter → template value → onload JavaScript string → break out of string → JavaScript execution
Key lesson: The payload must match the context in which the input is inserted.
6. Level 5 – JavaScript URL Injection
Vulnerability: JavaScript URL / protocol injection
The signup frame contains a link similar to <a href="{{ next }}">Next >></a>. The value of the next parameter is inserted directly into the href attribute.
Example lab payload:
javascript:alert(1)
Conceptual result:
<a href="javascript:alert(1)">Next >></a>
Source-to-execution flow:
next parameter → {{ next }} → href → javascript:alert(1) → user clicks link → JavaScript execution
Key lesson: A JavaScript execution path can be created through a URL-valued attribute. A <script> tag is not required.
7. Level 6 – Follow the Rabbit
Vulnerability: Dynamic script loading / unsafe script source
The application takes a value influenced by the URL fragment and uses it as the source for a dynamically created script element. If an attacker can control the script source, the browser may request and execute attacker-controlled JavaScript.
Conceptual vulnerable behavior:
var s = document.createElement('script');
s.src = url;
document.head.appendChild(s);
Example lab approach: provide a URL that points to JavaScript containing alert(1), using the mechanism expected by the training game.
Source-to-execution flow:
location.hash → URL value → script.src → browser requests JavaScript → script executes
Key lesson: Validating a URL as if it were ordinary text is not sufficient when the value becomes a script source.
8. Comparison of the Six Levels
Level	Primary Source	Primary Sink / Context	Main Concept Learned
1	Search input	HTML response	Reflected XSS
2	Stored user input	innerHTML / event handler	Stored XSS
3	location.hash	.html()	DOM source-to-sink flow
4	timer parameter	JavaScript string in onload	Context-specific injection
5	next parameter	href	JavaScript URL
6	location.hash	script.src	Dynamic script loading
9. General XSS Analysis Method
For any XSS lab, use the following process:
1.	Identify the source: Find where attacker-controlled data enters the application, such as a form field, URL parameter, or location.hash.
2.	Trace the data: Follow the value through variables, functions, templates, and transformations.
3.	Identify the sink: Find where the value is interpreted as HTML, JavaScript, a URL, or another executable context.
4.	Identify the context: Determine whether the input is inside HTML, an attribute, a JavaScript string, a URL, or another context.
5.	Test safely: Use the training lab's alert(1) objective to verify that the value reaches an executable context.
6.	Document the flow: Record the source, transformation, sink, payload, and resulting browser behavior.
10. Key Takeaways
•	XSS is fundamentally about untrusted data reaching a browser execution context.
•	A source is where attacker-controlled data originates; a sink is where that data is interpreted in a potentially dangerous way.
•	The same payload does not work in every context. HTML, attribute, JavaScript-string, URL, and script-source contexts require different analysis.
•	DOM XSS can happen entirely in client-side JavaScript.
•	A <script> tag is only one possible execution mechanism; event handlers and JavaScript URLs can also create execution paths in vulnerable applications.
•	For academic analysis, the most useful evidence is the source-to-sink flow plus the browser result, rather than simply recording the final payload.
11. Safety and Scope
The payloads and techniques in this report are intended for the Google XSS Game and other authorized training environments. They should not be used against systems without permission.
googlexxs
