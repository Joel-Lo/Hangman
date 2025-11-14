const wordList = [
    {
        word: "Phishing attack",
        hint: "Tricking users into giving sensitive information"
    },
    {
        word: "SQL injection",
        hint: "Exploiting database vulnerabilities with malicious queries"
    },
    {
        word: "Cross site scripting",
        hint: "Injecting scripts into webpages viewed by others"
    },
    {
        word: "Denial of service",
        hint: "Overloading a system to make it unavailable"
    },
    {
        word: "Man in the middle",
        hint: "Intercepting communications between two parties"
    },
    {
        word: "Password brute force",
        hint: "Attempting multiple passwords to gain access"
    },
    {
        word: "Credential stuffing",
        hint: "Using stolen credentials on multiple sites"
    },
    {
        word: "Remote code execution",
        hint: "Executing malicious code on a remote system"
    },
    {
        word: "File inclusion attack",
        hint: "Including local or remote files to execute code"
    },
    {
        word: "Cross site request forgery",
        hint: "Forcing users to perform actions without consent"
    },
    {
        word: "Buffer overflow",
        hint: "Writing more data than allocated memory allows"
    },
    {
        word: "Privilege escalation",
        hint: "Gaining higher access than authorized"
    },
    {
        word: "Malware injection",
        hint: "Introducing malicious software into a system"
    },
    {
        word: "Ransomware attack",
        hint: "Encrypting files and demanding payment"
    },
    {
        word: "Trojan horse",
        hint: "Carry out malicious operations by masking its true intent to exploit your user privileges"
    },
    {
        word: "Spyware",
        hint: "Software that secretly monitors user activity"
    },
    {
        word: "Keylogger",
        hint: "Recording keystrokes to steal information"
    },
    {
        word: "Rootkit",
        hint: "Malware designed to hide in the system"
    },
    {
        word: "Backdoor",
        hint: "Hidden method to bypass security"
    },
    {
        word: "Zero day exploit",
        hint: "Attacking a vulnerability before a patch exists"
    },
    {
        word: "Social engineering",
        hint: "Manipulating people to disclose confidential info"
    },
    {
        word: "DNS spoofing",
        hint: "Redirecting traffic by faking DNS responses"
    },
    {
        word: "ARP poisoning",
        hint: "Misleading network traffic to attacker devices"
    },
    {
        word: "WiFi packet sniffing",
        hint: "Capturing wireless traffic to extract information"
    },
    {
        word: "Bluetooth hacking",
        hint: "Exploiting vulnerabilities in Bluetooth connections"
    },
    {
        word: "IoT exploitation",
        hint: "Targeting weak Internet of Things devices"
    },
    {
        word: "Firmware hacking",
        hint: "Tampering with device firmware to gain control"
    },
    {
        word: "Botnet deployment",
        hint: "Using networked infected devices for attacks"
    },
    {
        word: "Cryptojacking",
        hint: "Using victim's device to mine cryptocurrency"
    },
    {
        word: "Web shell",
        hint: "Script uploaded to control a web server"
    },
    {
        word: "Remote desktop hijack",
        hint: "Gaining unauthorised control via RDP"
    },
    {
        word: "Browser exploit",
        hint: "Abusing browser vulnerabilities to run code"
    },
    {
        word: "Cookie theft",
        hint: "Stealing cookies to impersonate users"
    },
    {
        word: "Session hijacking",
        hint: "Taking over an active session of a user"
    },
    {
        word: "Token manipulation",
        hint: "Changing authentication tokens to gain access"
    },
    {
        word: "JavaScript injection",
        hint: "Inserting scripts to alter page behavior"
    },
    {
        word: "HTML injection",
        hint: "Inserting HTML elements maliciously into a page"
    },
    {
        word: "CSS injection",
        hint: "Using CSS to manipulate page or steal data"
    },
    {
        word: "API abuse",
        hint: "Misusing APIs for unauthorised actions"
    },
    {
        word: "API key leak",
        hint: "Exposing keys for accessing protected APIs"
    },
    {
        word: "Server misconfiguration",
        hint: "Weak server settings that expose data"
    },
    {
        word: "Cloud storage misconfiguration",
        hint: "Exposing cloud files due to weak permissions"
    },
    {
        word: "Open redirect",
        hint: "Redirecting users to malicious sites"
    },
    {
        word: "Unvalidated input",
        hint: "Not checking user input leading to attacks"
    },
    {
        word: "File upload vulnerability",
        hint: "Allowing dangerous files to be uploaded"
    },
    {
        word: "Command injection",
        hint: "Injecting system commands into applications"
    },
    {
        word: "Reverse shell",
        hint: "Shell connecting back to attacker machine"
    },
    {
        word: "Memory corruption",
        hint: "Exploiting memory errors to run arbitrary code"
    },
    {
        word: "Cross domain attack",
        hint: "Abusing trust between different domains"
    },
    {
        word: "Certificate spoofing",
        hint: "Faking digital certificates to bypass security"
    },
    {
        word: "Phishing attack",
        hint: "Tricking users into giving sensitive information"
    },
    {
        word: "SQL injection",
        hint: "Exploiting database vulnerabilities with malicious queries"
    },
    {
        word: "Cross site scripting",
        hint: "Injecting scripts into webpages viewed by others"
    },
    {
        word: "Denial of service",
        hint: "Overloading a system to make it unavailable"
    },
    {
        word: "Man in the middle",
        hint: "Intercepting communications between two parties"
    },
    {
        word: "Password brute force",
        hint: "Attempting multiple passwords to gain access"
    },
    {
        word: "Credential stuffing",
        hint: "Using stolen credentials on multiple sites"
    },
    {
        word: "Remote code execution",
        hint: "Executing malicious code on a remote system"
    },
    {
        word: "File inclusion attack",
        hint: "Including local or remote files to execute code"
    },
    {
        word: "Cross site request forgery",
        hint: "Forcing users to perform actions without consent"
    },
    {
        word: "Buffer overflow",
        hint: "Writing more data than allocated memory allows"
    },
    {
        word: "Privilege escalation",
        hint: "Gaining higher access than authorized"
    },
    {
        word: "Malware injection",
        hint: "Introducing malicious software into a system"
    },
    {
        word: "Ransomware attack",
        hint: "Encrypting files and demanding payment"
    },
    {
        word: "Trojan horse",
        hint: "Malicious program disguised as legitimate software"
    },
    {
        word: "Spyware",
        hint: "Software that secretly monitors user activity"
    },
    {
        word: "Keylogger",
        hint: "Recording keystrokes to steal information"
    },
    {
        word: "Rootkit",
        hint: "Malware designed to hide in the system"
    },
    {
        word: "Backdoor",
        hint: "Hidden method to bypass security"
    },
    {
        word: "Zero day exploit",
        hint: "Attacking a vulnerability before a patch exists"
    },
    {
        word: "Social engineering",
        hint: "Manipulating people to disclose confidential info"
    },
    {
        word: "DNS spoofing",
        hint: "Redirecting traffic by faking DNS responses"
    },
    {
        word: "ARP poisoning",
        hint: "Misleading network traffic to attacker devices"
    },
    {
        word: "WiFi packet sniffing",
        hint: "Capturing wireless traffic to extract information"
    },
    {
        word: "Bluetooth hacking",
        hint: "Exploiting vulnerabilities in Bluetooth connections"
    },
    {
        word: "IoT exploitation",
        hint: "Targeting weak Internet of Things devices"
    },
    {
        word: "Firmware hacking",
        hint: "Tampering with device firmware to gain control"
    },
    {
        word: "Botnet deployment",
        hint: "Using networked infected devices for attacks"
    },
    {
        word: "Cryptojacking",
        hint: "Using victim's device to mine cryptocurrency"
    },
    {
        word: "Web shell",
        hint: "Script uploaded to control a web server"
    },
    {
        word: "Remote desktop hijack",
        hint: "Gaining unauthorised control via RDP"
    },
    {
        word: "Browser exploit",
        hint: "Abusing browser vulnerabilities to run code"
    },
    {
        word: "Cookie theft",
        hint: "Stealing cookies to impersonate users"
    },
    {
        word: "Session hijacking",
        hint: "Taking over an active session of a user"
    },
    {
        word: "Token manipulation",
        hint: "Changing authentication tokens to gain access"
    },
    {
        word: "JavaScript injection",
        hint: "Inserting scripts to alter page behavior"
    },
    {
        word: "HTML injection",
        hint: "Inserting HTML elements maliciously into a page"
    },
    {
        word: "CSS injection",
        hint: "Using CSS to manipulate page or steal data"
    },
    {
        word: "API abuse",
        hint: "Misusing APIs for unauthorised actions"
    },
    {
        word: "API key leak",
        hint: "Exposing keys for accessing protected APIs"
    },
    {
        word: "Server misconfiguration",
        hint: "Weak server settings that expose data"
    },
    {
        word: "Cloud storage misconfiguration",
        hint: "Exposing cloud files due to weak permissions"
    },
    {
        word: "Open redirect",
        hint: "Redirecting users to malicious sites"
    },
    {
        word: "Unvalidated input",
        hint: "Not checking user input leading to attacks"
    },
    {
        word: "File upload vulnerability",
        hint: "Allowing dangerous files to be uploaded"
    },
    {
        word: "Command injection",
        hint: "Injecting system commands through vulnerabilities"
    },
    {
        word: "Reverse shell",
        hint: "Shell connecting back to attacker machine"
    },
    {
        word: "Memory corruption",
        hint: "Exploiting memory errors to execute arbitrary code"
    },
    {
        word: "Cross domain attack",
        hint: "Abusing trust between different domains"
    },
    {
        word: "Certificate spoofing",
        hint: "Faking digital certificates to bypass security"
    },
    {
        word: "Two factor bypass",
        hint: "Circumventing multi factor authentication"
    },
    {
        word: "Biometric spoofing",
        hint: "Faking fingerprints or facial recognition to gain access"
    },
    {
        word: "Network sniffing",
        hint: "Monitoring data packets on a network"
    },
    {
        word: "ARP spoofing",
        hint: "Sending fake ARP messages to intercept network traffic"
    },
    {
        word: "DNS cache poisoning",
        hint: "Injecting false DNS records to redirect traffic"
    },
    {
        word: "Port scanning",
        hint: "Checking open ports on a system for vulnerabilities"
    },
    {
        word: "Network reconnaissance",
        hint: "Gathering information about a network before attacking"
    },
    {
        word: "Web application fuzzing",
        hint: "Sending unexpected inputs to find vulnerabilities"
    },
    {
        word: "Directory traversal",
        hint: "Accessing files outside of allowed directories"
    },
    {
        word: "Local file inclusion",
        hint: "Including files from the local server in execution"
    },
    {
        word: "Remote file inclusion",
        hint: "Including files from remote sources for code execution"
    },
    {
        word: "Security misconfiguration",
        hint: "Improper settings leading to vulnerabilities"
    },
    {
        word: "Broken access control",
        hint: "Weak enforcement of permissions on resources"
    },
    {
        word: "Sensitive data exposure",
        hint: "Accidental exposure of confidential data"
    },
    {
        word: "Insufficient logging",
        hint: "Not recording security events, hiding attacks"
    },
    {
        word: "Unrestricted file download",
        hint: "Allowing access to sensitive files without restriction"
    },
    {
        word: "Open cloud bucket",
        hint: "Cloud storage accessible without authorization"
    },
    {
        word: "Cloud key compromise",
        hint: "Leaking cloud service access keys"
    },
    {
        word: "Malicious npm package",
        hint: "Harming systems via malicious JavaScript packages"
    },
    {
        word: "Python dependency attack",
        hint: "Injecting harmful code via Python libraries"
    },
    {
        word: "Reverse engineering",
        hint: "Analyzing software to find vulnerabilities"
    },
    {
        word: "Malicious macro",
        hint: "Macro script in documents that executes harmful code"
    },
    {
        word: "Remote access trojan",
        hint: "Malware providing full control of a victim’s machine"
    },
    {
        word: "Key exchange attack",
        hint: "Interfering with encryption key distribution"
    },
    {
        word: "SSL stripping",
        hint: "Downgrading HTTPS connections to HTTP to intercept traffic"
    },
    {
        word: "TLS handshake attack",
        hint: "Intercepting TLS negotiation to capture sensitive data"
    },
    {
        word: "Certificate authority compromise",
        hint: "Manipulating authorities to issue fake certificates"
    },
    {
        word: "Session fixation",
        hint: "Forcing a user to use a known session ID"
    },
    {
        word: "Browser sandbox escape",
        hint: "Breaking out of browser isolation for code execution"
    },
    {
        word: "Shadow DOM attack",
        hint: "Abusing hidden DOM elements to manipulate pages"
    },
    {
        word: "WebSocket hijacking",
        hint: "Intercepting or manipulating WebSocket communications"
    },
    {
        word: "HTML form spoofing",
        hint: "Creating fake forms to steal input data"
    },
    {
        word: "Browser autofill theft",
        hint: "Stealing data auto-filled by browser"
    },
    {
        word: "Password reset attack",
        hint: "Intercepting or abusing password reset functionality"
    },
    {
        word: "API rate limit bypass",
        hint: "Exceeding API usage limits to gain extra access"
    },
    {
        word: "API endpoint discovery",
        hint: "Finding hidden API routes or services"
    },
    {
        word: "API key leakage",
        hint: "Exposing sensitive API authentication keys"
    },
    {
        word: "Unauthorised API access",
        hint: "Calling API functions without permission"
    },
    {
        word: "Command injection",
        hint: "Injecting system commands through vulnerabilities"
    },
    {
        word: "Local privilege escalation",
        hint: "Gaining higher permissions on a local system"
    },
    {
        word: "Remote privilege escalation",
        hint: "Gaining administrative rights on a remote system"
    },
    {
        word: "Memory corruption",
        hint: "Exploiting memory errors to execute arbitrary code"
    },
    {
        word: "File permission abuse",
        hint: "Accessing or modifying files due to weak permissions"
    },
    {
        word: "Code repository attack",
        hint: "Compromising source code repositories for malicious purposes"
    },
    {
        word: "Supply chain attack",
        hint: "Exploiting third-party software to attack a target"
    },
    {
        word: "Malicious browser extension",
        hint: "Browser plugin designed to steal data or manipulate pages"
    },
    {
        word: "Social engineering toolkit",
        hint: "Tools used to automate phishing and impersonation attacks"
    },
    {
        word: "Automated vulnerability scanning",
        hint: "Using tools to find system weaknesses automatically"
    },
    {
        word: "IoT device hijack",
        hint: "Taking control of Internet of Things devices"
    },
    {
        word: "Bluetooth pairing hijack",
        hint: "Intercepting or manipulating Bluetooth connections"
    },
    {
        word: "WiFi handshake cracking",
        hint: "Capturing and cracking WiFi authentication handshakes"
    },
    {
        word: "Rogue access point",
        hint: "Fake WiFi network used to intercept data"
    },
    {
        word: "Digital certificate spoofing",
        hint: "Faking certificates to appear trusted"
    },
    {
        word: "Browser developer tool abuse",
        hint: "Using browser dev tools to manipulate page or steal info"
    },
    {
        word: "Mobile device rooting",
        hint: "Gaining privileged access on mobile operating systems"
    },
    {
        word: "Hardware keylogger installation",
        hint: "Physically recording keystrokes on a device"
    },
    {
        word: "Unsecured network traffic",
        hint: "Data sent without encryption that can be intercepted"
    },
    {
        word: "Cloud key leakage",
        hint: "Exposing keys for cloud service access"
    },
    {
        word: "Server side request forgery",
        hint: "Making the server perform unintended requests"
    },
    {
        word: "Network service enumeration",
        hint: "Identifying available network services for attacks"
    },
    {
        word: "Privilege escalation chain",
        hint: "Using multiple exploits to gain full access"
    },
    {
        word: "Cyber forensic evasion",
        hint: "Avoiding detection by forensic investigators"
    },
    {
        word: "Stealth malware injection",
        hint: "Injecting malware designed to stay hidden"
    },
    {
        word: "Botnet command injection",
        hint: "Sending unauthorised commands to a botnet"
    },
    {
        word: "Browser insecure context exploitation",
        hint: "Abusing pages not served over HTTPS"
    },
    {
        word: "Malware reverse engineering",
        hint: "Analyzing malware to understand its behavior"
    },
    {
        word: "IoT firmware reverse engineering",
        hint: "Examining IoT device firmware for vulnerabilities"
    },
    {
        word: "Automated phishing",
        hint: "Using scripts or bots to send phishing messages at scale"
    },
    {
        word: "Credential harvesting",
        hint: "Collecting usernames and passwords from victims"
    },
    {
        word: "Malicious PDF",
        hint: "Embedding harmful scripts inside PDF files"
    },
    {
        word: "Email spoofing",
        hint: "Faking email sender information to deceive users"
    },
    {
        word: "Drive by download",
        hint: "Automatically downloading malware when visiting a website"
    },
    {
        word: "Clickjacking attack",
        hint: "Tricking users into clicking hidden or disguised elements"
    },
    {
        word: "Webcam hijacking",
        hint: "Gaining unauthorised access to a victim’s webcam"
    },
    {
        word: "Microphone hijacking",
        hint: "Gaining unauthorised access to record audio"
    },
    {
        word: "Browser plugin exploitation",
        hint: "Exploiting vulnerabilities in installed browser plugins"
    },
    {
        word: "Session replay attack",
        hint: "Reusing captured session data to impersonate users"
    },
    {
        word: "OAuth token theft",
        hint: "Stealing authentication tokens to bypass login"
    },
    {
        word: "DNS rebinding attack",
        hint: "Tricking browsers to bypass same origin policies"
    },
    {
        word: "HTTP response splitting",
        hint: "Injecting headers to manipulate web server responses"
    },
    {
        word: "Subdomain takeover",
        hint: "Taking control of abandoned subdomains"
    },
    {
        word: "Insecure cookie handling",
        hint: "Cookies not properly secured, allowing theft"
    },
    {
        word: "HTTP header injection",
        hint: "Manipulating headers to perform malicious actions"
    },
    {
        word: "Local storage attack",
        hint: "Abusing browser local storage to steal or manipulate data"
    },
    {
        word: "Cross origin resource sharing attack",
        hint: "Exploiting improperly configured CORS policies"
    },
    {
        word: "Browser memory scraping",
        hint: "Extracting sensitive information stored in browser memory"
    },
    {
        word: "Automated vulnerability exploitation",
        hint: "Using tools to exploit found weaknesses automatically"
    },
    {
        word: "Web server fingerprinting",
        hint: "Identifying server type and software versions"
    },
    {
        word: "Directory brute forcing",
        hint: "Systematically trying directory paths to discover hidden files"
    },
    {
        word: "Cloud storage enumeration",
        hint: "Finding files or buckets in cloud environments"
    },
    {
        word: "Mobile application exploitation",
        hint: "Targeting weaknesses in mobile apps for attacks"
    },
    {
        word: "Reverse proxy attack",
        hint: "Abusing proxy servers to intercept or manipulate traffic"
    },
    {
        word: "Browser cache poisoning",
        hint: "Injecting malicious content into cached files"
    },
    {
        word: "Application sandbox escape",
        hint: "Breaking out of restricted environments to run code"
    },
    {
        word: "Digital certificate compromise",
        hint: "Faking or stealing certificates to bypass security"
    },
    {
        word: "Server side template injection",
        hint: "Injecting templates that the server executes"
    },
    {
        word: "Memory disclosure vulnerability",
        hint: "Revealing sensitive data from memory"
    },
    {
        word: "Credential dumping",
        hint: "Extracting stored passwords from a system"
    },
    {
        word: "DNS tunneling",
        hint: "Using DNS queries to transfer data secretly"
    },
    {
        word: "Malicious container image",
        hint: "Embedding harmful code in Docker or container images"
    },
    {
        word: "Code signing bypass",
        hint: "Running unsigned or maliciously signed code"
    },
    {
        word: "Insider threat",
        hint: "Malicious actions performed by someone within the organization"
    },
    {
        word: "Firmware downgrade attack",
        hint: "Installing an older, vulnerable firmware to compromise a device"
    },
    {
        word: "Web application logic flaw",
        hint: "Weaknesses in application workflow that attackers exploit"
    },
    {
        word: "Broken authentication",
        hint: "Authentication mechanisms that can be bypassed"
    },
    {
        word: "Cross site WebSocket hijack",
        hint: "Attacking WebSocket communication to steal data"
    },
    {
        word: "Automated brute force",
        hint: "Using tools to systematically guess passwords"
    },
    {
        word: "Privilege abuse",
        hint: "Using legitimate access in an unauthorised way"
    },
    {
        word: "Software supply chain attack",
        hint: "Compromising third-party software to attack users"
    },
    {
        word: "Malicious script injection",
        hint: "Injecting harmful scripts into websites or apps"
    },
    {
        word: "Web form tampering",
        hint: "Modifying web forms to bypass validation or steal data"
    },
    {
        word: "Browser history manipulation",
        hint: "Altering or reading browser history maliciously"
    },
    {
        word: "File system traversal",
        hint: "Accessing files outside the intended directories"
    },
    {
        word: "Unauthorised resource access",
        hint: "Accessing data or functionality without permission"
    },
    {
        word: "Cloud misconfiguration scanning",
        hint: "Automated discovery of misconfigured cloud resources"
    },
    {
        word: "Network port misuse",
        hint: "Using network ports for malicious purposes"
    },
    {
        word: "ARP cache poisoning",
        hint: "Poisoning ARP cache to intercept traffic"
    },
    {
        word: "VPN exploitation",
        hint: "Abusing vulnerabilities in virtual private networks"
    },
    {
        word: "TLS downgrade attack",
        hint: "Forcing weaker encryption to intercept data"
    },
    {
        word: "JavaScript prototype pollution",
        hint: "Injecting properties into object prototypes to affect code"
    },
    {
        word: "Browser autofill exploitation",
        hint: "Stealing sensitive data auto-filled by the browser"
    },
    {
        word: "Click fraud",
        hint: "Automated or malicious clicking to generate revenue"
    },
    {
        word: "Command shell hijacking",
        hint: "Taking control of command-line sessions"
    },
    {
        word: "Local network pivoting",
        hint: "Using one compromised machine to access other network segments"
    },
    {
        word: "WiFi evil twin attack",
        hint: "Creating a fake WiFi network to capture traffic"
    },
    {
        word: "Bluetooth device spoofing",
        hint: "Pretending to be a trusted Bluetooth device"
    },
    {
        word: "IoT device enumeration",
        hint: "Discovering IoT devices and their vulnerabilities"
    },
    {
        word: "Firmware tampering",
        hint: "Modifying device firmware to gain control or bypass security"
    },
    {
        word: "Browser cookie manipulation",
        hint: "Altering cookies to impersonate users or steal data"
    },
    {
        word: "HTTP request smuggling",
        hint: "Manipulating HTTP requests to bypass security controls"
    },
    {
        word: "TLS session hijacking",
        hint: "Stealing or taking over an encrypted session"
    },
    {
        word: "Malicious browser extension",
        hint: "A plugin designed to steal data or manipulate pages"
    },
    {
        word: "Automated exploit chaining",
        hint: "Combining multiple exploits automatically for attacks"
    },
    {
        word: "Credential replay attack",
        hint: "Reusing captured credentials to gain unauthorised access"
    },
    {
        word: "Subdomain enumeration",
        hint: "Discovering hidden or forgotten subdomains"
    },
    {
        word: "Server side include injection",
        hint: "Injecting code into SSI-enabled web pages"
    },
    {
        word: "Web cache poisoning",
        hint: "Injecting malicious content into cache to affect users"
    },
    {
        word: "Template injection attack",
        hint: "Injecting code into templates that the server executes"
    },
    {
        word: "Browser content spoofing",
        hint: "Manipulating what users see in their browsers"
    },
    {
        word: "Reverse proxy exploitation",
        hint: "Abusing reverse proxies to access internal systems"
    },
    {
        word: "Software version enumeration",
        hint: "Finding software versions to identify vulnerabilities"
    },
    {
        word: "Memory dump analysis",
        hint: "Analyzing memory dumps to extract sensitive information"
    },
    {
        word: "Cryptographic key theft",
        hint: "Stealing keys used for encryption or authentication"
    },
    {
        word: "Password hash cracking",
        hint: "Decrypting password hashes to obtain plaintext passwords"
    },
    {
        word: "Browser autofill spoofing",
        hint: "Tricking browsers into filling sensitive data into malicious forms"
    },
    {
        word: "Insecure direct object reference",
        hint: "Accessing data or objects directly without proper authorization"
    },
    {
        word: "Automated penetration testing",
        hint: "Using tools to simulate attacks on a system automatically"
    },
    {
        word: "IoT device brute force",
        hint: "Trying multiple credentials to access IoT devices"
    },
    {
        word: "Reverse engineering API",
        hint: "Analyzing API behavior to discover hidden functions or vulnerabilities"
    },
    {
        word: "Cross site WebSocket hijacking",
        hint: "Abusing WebSocket communication to steal data"
    },
    {
        word: "Browser storage poisoning",
        hint: "Injecting malicious data into browser storage"
    },
    {
        word: "Web application backdoor",
        hint: "Hidden code allowing unauthorised access to a web app"
    },
    {
        word: "Command line injection",
        hint: "Executing system commands via vulnerable input"
    },
    {
        word: "Remote shell execution",
        hint: "Running shell commands on a remote system"
    },
    {
        word: "Network traffic replay",
        hint: "Re-sending captured network traffic to achieve unauthorised actions"
    },
    {
        word: "Browser event hijacking",
        hint: "Capturing and manipulating browser events for attacks"
    },
    {
        word: "Server configuration disclosure",
        hint: "Revealing sensitive server configuration details"
    },
    {
        word: "Cloud function abuse",
        hint: "Exploiting cloud functions for malicious purposes"
    },
    {
        word: "Automated credential testing",
        hint: "Systematically trying credentials to gain access"
    },
    {
        word: "Session token prediction",
        hint: "Guessing or generating valid session tokens"
    },
    {
        word: "Cache side channel attack",
        hint: "Extracting sensitive information via cache behavior"
    },
    {
        word: "Memory leak exploitation",
        hint: "Abusing memory leaks to access sensitive data or crash applications"
    },
    {
        word: "Local network sniffing",
        hint: "Capturing traffic on a local network segment"
    },
    {
        word: "Malicious JavaScript injection",
        hint: "Injecting scripts to execute unwanted actions in the browser"
    },
    {
        word: "Browser fingerprinting bypass",
        hint: "Avoiding detection mechanisms based on browser fingerprints"
    },
    {
        word: "Cloud API misconfiguration",
        hint: "Exposing cloud APIs due to improper settings"
    },
    {
        word: "Email header injection",
        hint: "Manipulating email headers to bypass filters or spoof messages"
    },
    {
        word: "Security token replay",
        hint: "Reusing tokens to bypass authentication"
    },
    {
        word: "Insecure deserialization",
        hint: "Executing malicious code by sending crafted serialized objects"
    },
    {
        word: "Remote file overwrite",
        hint: "Replacing files on remote servers maliciously"
    },
    {
        word: "Cross site DOM manipulation",
        hint: "Altering the Document Object Model of another site"
    },
    {
        word: "Browser cache abuse",
        hint: "Manipulating cache to serve malicious content"
    },
    {
        word: "Click fraud bot",
        hint: "Automated clicks to generate fraudulent advertising revenue"
    },
    {
        word: "DNS amplification attack",
        hint: "Using DNS servers to amplify a DDoS attack"
    },
    {
        word: "Network protocol fuzzing",
        hint: "Testing network protocols with unexpected input to find vulnerabilities"
    },
    {
        word: "Web socket sniffing",
        hint: "Intercepting data sent over WebSockets"
    },
    {
        word: "Malicious dependency injection",
        hint: "Injecting harmful code via project dependencies"
    },
    {
        word: "Insecure mobile storage",
        hint: "Storing sensitive data insecurely on mobile devices"
    },
    {
        word: "Browser extension hijack",
        hint: "Taking control of a browser extension to steal data"
    },
    {
        word: "Cryptographic downgrade attack",
        hint: "Forcing weaker cryptography to intercept or manipulate data"
    },
    {
        word: "Mobile push notification spoofing",
        hint: "Sending fake push notifications to deceive users"
    },
    {
        word: "Social media account takeover",
        hint: "Gaining unauthorised control over social accounts"
    },
    {
        word: "Malware persistence",
        hint: "Ensuring malware continues to operate after system restart"
    },
    {
        word: "Browser URL spoofing",
        hint: "Tricking users with fake URLs in the address bar"
    },
    {
        word: "Web server directory disclosure",
        hint: "Exposing directory structures and sensitive files"
    },
    {
        word: "IoT firmware downgrade",
        hint: "Installing older, vulnerable firmware to compromise IoT devices"
    },
    {
        word: "Credential phishing kit",
        hint: "Pre-made tools to automate phishing attacks"
    },
    {
        word: "Cloud infrastructure enumeration",
        hint: "Discovering resources and services in cloud environments"
    },
    {
        word: "Automated malware deployment",
        hint: "Using scripts to distribute malware at scale"
    },
    {
        word: "Browser sandbox abuse",
        hint: "Breaking isolation mechanisms in browsers to execute code"
    },
    {
        word: "Mobile device jailbreak",
        hint: "Gaining root access to a mobile operating system"
    },
    {
        word: "IoT device default password",
        hint: "Exploiting weak or default credentials on devices"
    },
    {
        word: "Web server request smuggling",
        hint: "Sending crafted requests to bypass security controls"
    },
    {
        word: "Network man in the browser",
        hint: "Intercepting and altering browser communications"
    },
    {
        word: "Certificate pinning bypass",
        hint: "Ignoring certificate verification to intercept traffic"
    },
    {
        word: "File system symbolic link attack",
        hint: "Abusing symbolic links to access restricted files"
    },
    {
        word: "Server side JavaScript injection",
        hint: "Injecting code that the server executes in Node.js"
    },
    {
        word: "Unauthorised database access",
        hint: "Accessing or modifying data without permission"
    },
    {
        word: "Cross site WebSocket pollution",
        hint: "Injecting malicious data into WebSocket communication"
    },
    {
        word: "Cloud storage enumeration",
        hint: "Discovering files or buckets in cloud environments"
    },
    {
        word: "Server side request manipulation",
        hint: "Altering server requests to achieve unauthorised actions"
    },
    {
        word: "Cross site local storage attack",
        hint: "Injecting malicious data into browser local storage"
    },
    {
        word: "Automated credential stuffing",
        hint: "Using tools to try stolen credentials across multiple sites"
    },
    {
        word: "Command execution vulnerability",
        hint: "Flaw allowing attackers to run system commands"
    },
    {
        word: "Remote administration tool abuse",
        hint: "Misusing remote admin tools for unauthorised control"
    },
    {
        word: "File upload bypass",
        hint: "Uploading files despite restrictions or validation"
    },
    {
        word: "Network sniffing attack",
        hint: "Intercepting and analyzing network packets for sensitive data"
    },
    {
        word: "HTTP verb tampering",
        hint: "Changing HTTP methods to bypass security controls"
    },
    {
        word: "Browser auto-update bypass",
        hint: "Preventing or manipulating browser updates to exploit vulnerabilities"
    },
    {
        word: "Cross origin data theft",
        hint: "Stealing data from different domains due to misconfigurations"
    },
    {
        word: "Insecure API endpoint",
        hint: "Exposed API route that allows unauthorised access"
    },
    {
        word: "Web shell persistence",
        hint: "Maintaining a hidden web shell for long-term access"
    },
    {
        word: "Cloud configuration drift",
        hint: "Unexpected changes in cloud settings exposing vulnerabilities"
    },
    {
        word: "Memory disclosure attack",
        hint: "Revealing sensitive information from memory"
    },
    {
        word: "Privilege escalation via kernel",
        hint: "Exploiting OS kernel flaws to gain admin access"
    },
    {
        word: "Local file overwrite",
        hint: "Replacing files on the local system maliciously"
    },
    {
        word: "Malicious CI/CD pipeline",
        hint: "Injecting harmful code into build and deployment processes"
    },
    {
        word: "Server side object injection",
        hint: "Injecting objects for malicious server-side execution"
    },
    {
        word: "DNS tunneling data exfiltration",
        hint: "Using DNS queries to secretly extract data"
    },
    {
        word: "Cross site script inclusion",
        hint: "Including scripts from external sites to run malicious code"
    },
    {
        word: "Browser history sniffing",
        hint: "Extracting user browsing history via vulnerabilities"
    },
    {
        word: "Insecure cloud function",
        hint: "Cloud function that can be misused for attacks"
    },
    {
        word: "TLS certificate manipulation",
        hint: "Faking or altering certificates to intercept traffic"
    },
    {
        word: "Browser plugin privilege escalation",
        hint: "Using browser plugin vulnerabilities to gain higher access"
    },
    {
        word: "Automated phishing kit",
        hint: "Tools to automate phishing campaigns"
    },
    {
        word: "Command injection via API",
        hint: "Sending malicious commands through API endpoints"
    },
    {
        word: "Browser cookie theft",
        hint: "Stealing cookies to impersonate users"
    },
    {
        word: "Malware self propagation",
        hint: "Malware spreading itself without user interaction"
    },
    {
        word: "Mobile app reverse engineering",
        hint: "Analyzing mobile apps to find vulnerabilities"
    },
    {
        word: "Cloud function code injection",
        hint: "Injecting malicious code into serverless functions"
    },
    {
        word: "Web server misconfiguration",
        hint: "Improper server settings that expose vulnerabilities"
    },
    {
        word: "Automated vulnerability scanner",
        hint: "Tools that scan systems for weaknesses automatically"
    },
    {
        word: "Browser fingerprint spoofing",
        hint: "Pretending to be a different browser to avoid detection"
    },
    {
        word: "Remote firmware injection",
        hint: "Installing malicious firmware over a network"
    },
    {
        word: "IoT device default credentials",
        hint: "Exploiting unchanged default passwords on devices"
    },
    {
        word: "Local network privilege escalation",
        hint: "Gaining higher access within a local network"
    },
    {
        word: "Cross site WebSocket injection",
        hint: "Injecting malicious data into WebSocket communication"
    },
    {
        word: "Automated brute force attack",
        hint: "Using tools to systematically guess passwords or keys"
    },
    {
        word: "Server side template manipulation",
        hint: "Altering templates on the server to execute code"
    },
    {
        word: "Browser sandbox escape attack",
        hint: "Breaking browser isolation to execute code"
    },
    {
        word: "IoT device firmware analysis",
        hint: "Examining IoT firmware to find vulnerabilities"
    },
    {
        word: "API token misuse",
        hint: "Abusing authentication tokens to gain unauthorised access"
    },
    {
        word: "Mobile device data exfiltration",
        hint: "Stealing sensitive data from mobile devices"
    },
    {
        word: "Insecure password recovery",
        hint: "Weak password reset mechanisms that can be exploited"
    },
    {
        word: "Malicious email attachment",
        hint: "Files sent via email designed to infect systems"
    },
    {
        word: "Browser dev tool abuse",
        hint: "Using browser developer tools maliciously"
    },
    {
        word: "Web form input tampering",
        hint: "Altering form data to bypass validation or steal info"
    },
    {
        word: "Cloud service token theft",
        hint: "Stealing access tokens for cloud services"
    },
    {
        word: "IoT default password attack",
        hint: "Exploiting default passwords on IoT devices"
    },
    {
        word: "Automated malware execution",
        hint: "Scripts or tools that deploy malware automatically"
    },
    {
        word: "Browser autofill theft",
        hint: "Stealing sensitive information filled automatically in forms"
    },
    {
        word: "Server side configuration disclosure",
        hint: "Exposing server settings unintentionally"
    },
    {
        word: "TLS downgrade exploitation",
        hint: "Forcing weaker encryption protocols to intercept data"
    },
    {
        word: "Browser memory scraping",
        hint: "Extracting sensitive information from browser memory"
    },
    {
        word: "Malicious npm dependency",
        hint: "Harmful code hidden in JavaScript package dependencies"
    },
    {
        word: "Mobile device rooting exploit",
        hint: "Gaining root privileges on mobile devices via vulnerabilities"
    },
    {
        word: "Browser extension vulnerability",
        hint: "Flaws in browser plugins that can be exploited"
    },
    {
        word: "Remote access vulnerability",
        hint: "Weakness allowing unauthorised remote control"
    },
    {
        word: "API endpoint enumeration",
        hint: "Finding all accessible API routes for potential exploitation"
    },
    {
        word: "Command line privilege escalation",
        hint: "Using command line flaws to gain higher access"
    },
    {
        word: "Web server log manipulation",
        hint: "Altering logs to hide malicious activity"
    },
    {
        word: "Server side encryption bypass",
        hint: "Skipping server encryption mechanisms to access data"
    },
    {
        word: "Cloud key rotation bypass",
        hint: "Avoiding key rotation policies to maintain access"
    },
    {
        word: "Memory buffer overflow",
        hint: "Writing beyond allocated memory to execute code"
    },
    {
        word: "WebSocket message injection",
        hint: "Sending malicious messages via WebSocket channels"
    },
    {
        word: "Malware persistence mechanism",
        hint: "Techniques to ensure malware remains after reboot"
    },
    {
        word: "IoT firmware exploitation",
        hint: "Using firmware vulnerabilities to compromise IoT devices"
    },
    {
        word: "Cross site request smuggling",
        hint: "Manipulating requests to bypass security policies"
    },
    {
        word: "Unauthorised cloud access",
        hint: "Accessing cloud resources without permission"
    },
    {
        word: "Reverse engineering malware",
        hint: "Analyzing malware to understand its behavior"
    },
    {
        word: "Browser sandbox compromise",
        hint: "Breaking browser isolation to run malicious code"
    },
    {
        word: "Certificate authority attack",
        hint: "Compromising certificate authorities to issue fake certificates"
    },
    {
        word: "Automated web scanner",
        hint: "Tools that automatically scan websites for vulnerabilities"
    },
    {
        word: "IoT device enumeration",
        hint: "Discovering IoT devices and their weaknesses"
    },
    {
        word: "Cloud function injection",
        hint: "Injecting malicious code into serverless cloud functions"
    },
    {
        word: "Unauthorised API operation",
        hint: "Performing API actions without proper authorization"
    },
    {
        word: "Mobile app token theft",
        hint: "Stealing authentication tokens from mobile applications"
    },
    {
        word: "Browser developer console attack",
        hint: "Abusing the developer console for malicious activity"
    },
    {
        word: "Cross site DOM injection",
        hint: "Injecting code that manipulates another site’s DOM"
    },
    {
        word: "TLS certificate spoofing",
        hint: "Faking TLS certificates to intercept or impersonate"
    },
    {
        word: "Malicious cloud deployment",
        hint: "Deploying harmful applications or scripts in cloud infrastructure"
    },
    {
        word: "Session fixation attack",
        hint: "Forcing a known session ID on a user to hijack their session"
    },
    {
        word: "Browser local storage abuse",
        hint: "Manipulating local storage for unauthorised actions"
    },
    {
        word: "Cross site clickjacking",
        hint: "Tricking users into clicking hidden or disguised elements"
    },
    {
        word: "IoT device default key attack",
        hint: "Exploiting default security keys on IoT devices"
    },
    {
        word: "Browser URL manipulation",
        hint: "Altering URLs to perform unauthorised actions"
    },
    {
        word: "Server side file injection",
        hint: "Injecting malicious files on the server to execute code"
    },
    {
        word: "Cloud infrastructure enumeration",
        hint: "Mapping cloud resources to find vulnerabilities"
    },
    {
        word: "Automated password attack",
        hint: "Systematically attempting passwords using tools"
    },
    {
        word: "Cross site script injection",
        hint: "Injecting scripts into other sites to execute malicious actions"
    },
    {
        word: "IoT device remote control",
        hint: "Gaining unauthorised control of IoT devices"
    },
    {
        word: "Browser session hijacking",
        hint: "Taking over active browser sessions to impersonate users"
    },
    {
        word: "Malicious CI pipeline",
        hint: "Injecting harmful code into continuous integration processes"
    },
    {
        word: "Web server directory traversal",
        hint: "Accessing directories outside intended paths on the server"
    },
    {
        word: "Memory leak attack",
        hint: "Exploiting memory leaks to crash applications or access data"
    },
    {
        word: "Cloud access token abuse",
        hint: "Misusing access tokens to perform unauthorised cloud operations"
    },
    {
        word: "Browser cache manipulation",
        hint: "Altering cache to serve malicious content or steal info"
    },
    {
        word: "IoT device privilege escalation",
        hint: "Gaining higher access on IoT devices through vulnerabilities"
    },
    {
        word: "Remote shell injection",
        hint: "Executing commands on a remote shell via vulnerabilities"
    },
    {
        word: "Automated malware installation",
        hint: "Using scripts to install malware across systems automatically"
    },
    {
        word: "Cloud function privilege abuse",
        hint: "Exploiting serverless functions to gain unauthorised access"
    },
    {
        word: "Browser content manipulation",
        hint: "Altering web page content in the browser maliciously"
    },
    {
        word: "Certificate pinning bypass",
        hint: "Avoiding certificate validation to intercept traffic"
    },
    {
        word: "Cross origin resource attack",
        hint: "Exploiting misconfigured cross origin policies"
    },
    {
        word: "Unauthorised mobile access",
        hint: "Gaining access to mobile apps or data without permission"
    },
    {
        word: "Malware command and control",
        hint: "Communicating with malware remotely to control it"
    },
    {
        word: "Reverse engineering firmware",
        hint: "Analyzing firmware to find vulnerabilities or hidden functions"
    },
    {
        word: "WebSocket data injection",
        hint: "Injecting malicious messages over WebSocket channels"
    },
    {
        word: "Cloud misconfiguration exploitation",
        hint: "Using configuration mistakes in cloud environments to attack"
    },
    {
        word: "Server side object manipulation",
        hint: "Altering objects on the server to execute code"
    },
    {
        word: "IoT device brute force",
        hint: "Trying multiple credentials to gain access to IoT devices"
    },
    {
        word: "Automated exploit framework",
        hint: "Tools that chain multiple exploits automatically"
    },
    {
        word: "Browser history manipulation",
        hint: "Changing or reading browser history maliciously"
    },
    {
        word: "Remote API exploitation",
        hint: "Exploting API endpoints to perform unauthorised actions"
    },
    {
        word: "TLS handshake attack",
        hint: "Intercepting or manipulating TLS negotiation to capture data"
    },
    {
        word: "Browser autofill attack",
        hint: "Tricking the browser to fill sensitive data into malicious forms"
    },
    {
        word: "Cross site authentication bypass",
        hint: "Exploiting web vulnerabilities to bypass login"
    },
    {
        word: "Mobile device exploit",
        hint: "Abusing vulnerabilities in mobile devices or apps"
    },
    {
        word: "Cloud key injection",
        hint: "Injecting malicious keys into cloud configurations"
    },
    {
        word: "Web form vulnerability",
        hint: "Flaws in forms that allow injection or bypass"
    },
    {
        word: "Browser sandbox escape",
        hint: "Breaking out of isolation to execute arbitrary code"
    },
    {
        word: "IoT device enumeration attack",
        hint: "Mapping IoT devices for vulnerabilities"
    },
    {
        word: "Server side encryption bypass",
        hint: "Skipping server encryption to access data"
    },
    {
        word: "Credential replay attack",
        hint: "Reusing captured credentials to gain unauthorised access"
    },
    {
        word: "Automated cloud scanning",
        hint: "Scanning cloud infrastructure for misconfigurations or vulnerabilities automatically"
    },
    {
        word: "Browser plugin exploitation",
        hint: "Abusing vulnerabilities in browser extensions"
    },
    {
        word: "API misuse attack",
        hint: "Abusing API endpoints to perform unauthorised actions"
    },
    {
        word: "Cloud misconfiguration audit",
        hint: "Checking cloud settings for security weaknesses"
    },
    {
        word: "Reverse engineering web app",
        hint: "Analyzing web apps to find vulnerabilities"
    },
    {
        word: "Malicious npm package injection",
        hint: "Inserting harmful JavaScript packages into projects"
    },
    {
        word: "IoT default password exploitation",
        hint: "Using default credentials to access IoT devices"
    },
    {
        word: "Automated vulnerability exploitation",
        hint: "Using tools to exploit discovered vulnerabilities automatically"
    },
    {
        word: "Browser cookie tampering",
        hint: "Modifying cookies to impersonate users or steal data"
    },
    {
        word: "Server side template injection",
        hint: "Injecting malicious code into server templates"
    },
    {
        word: "API token theft",
        hint: "Stealing authentication tokens to bypass security"
    },
    {
        word: "Browser storage manipulation",
        hint: "Altering local or session storage for unauthorised access"
    },
    {
        word: "Cross site scripting attack",
        hint: "Injecting scripts to steal data or manipulate pages"
    },
    {
        word: "Command injection vulnerability",
        hint: "Executing system commands through unsafe input"
    },
    {
        word: "Automated penetration testing",
        hint: "Using scripts or tools to simulate attacks on systems automatically"
    },
    {
        word: "Web server misconfiguration",
        hint: "Weak server settings that expose vulnerabilities"
    },
    {
        word: "Cloud key leakage",
        hint: "Exposing access keys that grant cloud permissions"
    },
    {
        word: "Mobile device token theft",
        hint: "Stealing authentication tokens from mobile applications"
    },
    {
        word: "Browser developer console abuse",
        hint: "Using dev tools for malicious purposes"
    },
    {
        word: "Cross origin data leakage",
        hint: "Stealing data due to misconfigured cross-origin policies"
    },
    {
        word: "TLS certificate manipulation",
        hint: "Faking or altering certificates to intercept traffic"
    },
    {
        word: "Malware persistence technique",
        hint: "Methods used by malware to survive system reboots"
    },
    {
        word: "IoT device privilege escalation",
        hint: "Gaining higher access on IoT devices via vulnerabilities"
    },
    {
        word: "Reverse engineering firmware",
        hint: "Analyzing device firmware to discover vulnerabilities"
    },
    {
        word: "Cloud function privilege abuse",
        hint: "Exploiting serverless cloud functions to gain unauthorised access"
    },
    {
        word: "Server side object injection",
        hint: "Injecting objects to manipulate server-side code execution"
    },
    {
        word: "Browser cache manipulation",
        hint: "Altering cached content for malicious purposes"
    },
    {
        word: "Credential stuffing attack",
        hint: "Using leaked credentials to gain unauthorised access"
    },
    {
        word: "Automated brute force attack",
        hint: "Systematically guessing passwords using tools"
    },
    {
        word: "Cross site request forgery",
        hint: "Forcing users to perform actions without their consent"
    },
    {
        word: "Mobile app reverse engineering",
        hint: "Analyzing mobile apps to find weaknesses or extract data"
    },
    {
        word: "WebSocket injection",
        hint: "Sending malicious messages via WebSocket connections"
    },
    {
        word: "Server side file inclusion",
        hint: "Including files on the server to execute malicious code"
    },
    {
        word: "Browser sandbox escape",
        hint: "Breaking isolation mechanisms in browsers to run code"
    },
    {
        word: "Cross site clickjacking",
        hint: "Tricking users into clicking hidden elements"
    },
    {
        word: "Cloud access token abuse",
        hint: "Misusing tokens to perform unauthorised cloud actions"
    },
    {
        word: "Automated malware deployment",
        hint: "Using scripts to install malware on multiple systems automatically"
    },
    {
        word: "Insecure API endpoint",
        hint: "Exposed API that can be exploited without proper authentication"
    },
    {
        word: "Memory buffer overflow",
        hint: "Writing beyond allocated memory to execute arbitrary code"
    },
    {
        word: "Command line injection",
        hint: "Injecting system commands via unsafe input"
    },
    {
        word: "Browser cookie theft",
        hint: "Stealing cookies to impersonate users"
    },
    {
        word: "Web server directory traversal",
        hint: "Accessing directories outside the intended path on the server"
    },
    {
        word: "TLS downgrade attack",
        hint: "Forcing weaker encryption to intercept communications"
    },
    {
        word: "Malicious cloud deployment",
        hint: "Deploying harmful applications or scripts in cloud infrastructure"
    },
    {
        word: "Session fixation attack",
        hint: "Forcing a known session ID to hijack a user session"
    },
    {
        word: "API key leakage",
        hint: "Exposing sensitive API keys that grant access to services"
    },
    {
        word: "IoT firmware exploitation",
        hint: "Using firmware vulnerabilities to compromise IoT devices"
    },
    {
        word: "Browser autofill attack",
        hint: "Tricking the browser to fill sensitive data into malicious forms"
    },
    {
        word: "Mobile device rooting exploit",
        hint: "Gaining root privileges on mobile devices via vulnerabilities"
    },
    {
        word: "Cloud configuration drift",
        hint: "Unexpected changes in cloud configurations exposing vulnerabilities"
    },
    {
        word: "Reverse proxy exploitation",
        hint: "Abusing reverse proxies to access internal resources"
    },
    {
        word: "Web form input tampering",
        hint: "Altering form data to bypass validation or steal information"
    },
    {
        word: "Browser URL spoofing",
        hint: "Faking URLs to trick users or bypass security"
    },
    {
        word: "Server side JavaScript injection",
        hint: "Injecting JS that runs on the server (Node.js)"
    },
    {
        word: "Automated exploit chaining",
        hint: "Using tools that combine multiple exploits automatically"
    },
    {
        word: "Credential replay attack",
        hint: "Reusing stolen credentials to gain unauthorised access"
    },
    {
        word: "Browser plugin exploitation",
        hint: "Abusing flaws in browser extensions for malicious purposes"
    },
    {
        word: "Cloud infrastructure enumeration",
        hint: "Mapping cloud resources to identify potential weaknesses"
    },
    {
        word: "Automated cloud scanning",
        hint: "Scanning cloud infrastructure for vulnerabilities using tools"
    },
    {
        word: "Browser memory scraping",
        hint: "Extracting sensitive information from browser memory"
    },
    {
        word: "IoT device enumeration attack",
        hint: "Mapping IoT devices for vulnerabilities or access points"
    },
    {
        word: "Server side encryption bypass",
        hint: "Skipping encryption mechanisms on the server to access data"
    },
    {
        word: "Unauthorised mobile access",
        hint: "Accessing mobile apps or devices without permission"
    },
    {
        word: "Malware command and control",
        hint: "Remotely controlling malware on infected systems"
    },
    {
        word: "Reverse engineering API",
        hint: "Analyzing APIs to discover hidden endpoints or vulnerabilities"
    },
    {
        word: "WebSocket data manipulation",
        hint: "Injecting or altering messages in WebSocket communications"
    },
    {
        word: "Cloud function misconfiguration",
        hint: "Exposing cloud functions due to improper settings"
    },
    {
        word: "Server side object manipulation",
        hint: "Altering objects on the server to execute malicious code"
    },
    {
        word: "IoT device brute force attack",
        hint: "Trying multiple credentials to gain access to IoT devices"
    },
    {
        word: "Automated exploit framework",
        hint: "Tools that chain multiple exploits automatically for attacks"
    },
    {
        word: "Browser history manipulation",
        hint: "Altering or reading browser history for malicious purposes"
    },
    {
        word: "Remote API exploitation",
        hint: "Exploting API endpoints to perform unauthorised actions"
    },
    {
        word: "TLS handshake interception",
        hint: "Intercepting or manipulating TLS negotiation to steal data"
    },
    {
        word: "Browser autofill spoofing",
        hint: "Tricking the browser into filling sensitive data into malicious forms"
    },
    {
        word: "Cross site authentication bypass",
        hint: "Exploiting web vulnerabilities to bypass login authentication"
    },
    {
        word: "Mobile device exploit",
        hint: "Abusing vulnerabilities in mobile devices or apps"
    },
    {
        word: "Cloud key injection",
        hint: "Injecting malicious keys into cloud configurations to gain access"
    },
    {
        word: "Web form vulnerability",
        hint: "Flaws in forms that allow injection or bypass"
    },
    {
        word: "Browser sandbox escape attack",
        hint: "Breaking out of browser isolation to execute arbitrary code"
    },
    {
        word: "IoT device enumeration",
        hint: "Discovering IoT devices and their vulnerabilities"
    },
    {
        word: "Server side encryption bypass attack",
        hint: "Skipping server-side encryption to access sensitive data"
    },
    {
        word: "Credential replay attack automation",
        hint: "Automating the reuse of stolen credentials to gain access"
    },
    {
        word: "Cloud misconfiguration exploitation",
        hint: "Exploiting improper cloud configurations for unauthorised access"
    },
    {
        word: "Browser plugin privilege escalation",
        hint: "Exploiting browser plugin vulnerabilities to gain higher privileges"
    },
    {
        word: "API misuse exploitation",
        hint: "Exploting API endpoints to perform unauthorised actions"
    },
    {
        word: "Memory leak exploitation",
        hint: "Using memory leaks to extract sensitive data or crash apps"
    },
    {
        word: "Command injection via web",
        hint: "Injecting system commands through vulnerable web input"
    },
    {
        word: "Automated malware execution",
        hint: "Using scripts to deploy malware automatically across systems"
    },
    {
        word: "Server configuration disclosure",
        hint: "Revealing sensitive server settings unintentionally"
    },
    {
        word: "TLS downgrade exploitation",
        hint: "Forcing weaker encryption protocols to intercept data"
    },
    {
        word: "Malicious npm dependency",
        hint: "Injecting harmful JavaScript package dependencies"
    },
    {
        word: "Mobile device rooting exploit",
        hint: "Gaining root access to a mobile device via vulnerabilities"
    },
    {
        word: "Browser cookie tampering",
        hint: "Modifying cookies to impersonate users or steal data"
    },
    {
        word: "Server side template injection attack",
        hint: "Injecting code into server templates to execute malicious actions"
    },
    {
        word: "API token theft automation",
        hint: "Automating the theft of authentication tokens"
    },
    {
        word: "Browser storage abuse",
        hint: "Manipulating local or session storage for unauthorised actions"
    },
    {
        word: "Cross site scripting automation",
        hint: "Automating XSS attacks for multiple targets"
    },
    {
        word: "Command injection vulnerability automation",
        hint: "Using tools to exploit command injection automatically"
    },
    {
        word: "Reverse engineering mobile apps",
        hint: "Analyzing mobile applications for vulnerabilities or data extraction"
    },
    {
        word: "WebSocket injection automation",
        hint: "Automating malicious WebSocket message injections"
    },
    {
        word: "Server side file inclusion attack",
        hint: "Including malicious files on the server to execute code"
    },
    {
        word: "Browser sandbox escape automation",
        hint: "Automating methods to break browser isolation"
    },
    {
        word: "Cross site clickjacking automation",
        hint: "Automating hidden element click attacks"
    },
    {
        word: "Cloud access token abuse automation",
        hint: "Automating misuse of access tokens for unauthorised cloud actions"
    },
    {
        word: "Malware deployment automation",
        hint: "Using automated scripts to install malware widely"
    },
    {
        word: "Insecure API endpoint automation",
        hint: "Exploiting weak APIs automatically"
    },
    {
        word: "Memory buffer overflow exploitation",
        hint: "Using buffer overflow vulnerabilities to execute arbitrary code"
    },
    {
        word: "Command line injection automation",
        hint: "Automating command injection attacks"
    },
    {
        word: "Browser cookie theft automation",
        hint: "Automating stealing of cookies for user impersonation"
    },
    {
        word: "Web server directory traversal attack",
        hint: "Exploiting directory traversal vulnerabilities on a server"
    },
    {
        word: "TLS downgrade automation",
        hint: "Automating TLS protocol downgrade to intercept data"
    },
    {
        word: "Malicious cloud deployment automation",
        hint: "Automating deployment of harmful applications or scripts in cloud"
    },
    {
        word: "Session fixation attack automation",
        hint: "Automating session ID forcing to hijack user sessions"
    },
    {
        word: "API key leakage automation",
        hint: "Automating exposure of sensitive API keys"
    },
    {
        word: "IoT firmware exploitation automation",
        hint: "Automating exploitation of IoT device firmware"
    },
    {
        word: "Browser autofill attack automation",
        hint: "Automating attacks on browser autofill data"
    },
    {
        word: "Mobile device rooting automation",
        hint: "Automating gaining root access on mobile devices"
    },
    {
        word: "Cloud misconfiguration audit automation",
        hint: "Automating checks for weak cloud settings"
    },
    {
        word: "Reverse engineering web application",
        hint: "Analyzing web apps to discover hidden vulnerabilities"
    },
    {
        word: "Malicious npm package injection automation",
        hint: "Automating insertion of harmful JavaScript packages"
    },
    {
        word: "IoT default password exploitation automation",
        hint: "Automating attacks using default IoT credentials"
    },
    {
        word: "Browser cookie tampering automation",
        hint: "Automating modification of cookies to steal data or impersonate users"
    },
    {
        word: "Server side template injection automation",
        hint: "Automating injection of malicious code into server templates"
    },
    {
        word: "API token theft automation",
        hint: "Automating theft of authentication tokens"
    },
    {
        word: "Browser storage abuse automation",
        hint: "Automating manipulation of browser local or session storage"
    },
    {
        word: "Cross site scripting attack automation",
        hint: "Automating XSS attacks across multiple targets"
    },
    {
        word: "Command injection vulnerability exploitation automation",
        hint: "Automating the exploitation of command injection vulnerabilities"
    },
    {
        word: "Reverse engineering mobile apps automation",
        hint: "Automating the analysis of mobile apps for weaknesses or data extraction"
    },
    {
        word: "WebSocket injection automation",
        hint: "Automating malicious WebSocket message injections"
    },
    {
        word: "Server side file inclusion attack automation",
        hint: "Automating inclusion of malicious files on a server"
    },
    {
        word: "Browser sandbox escape attack automation",
        hint: "Automating methods to break browser isolation and execute code"
    },
    {
        word: "Cross site clickjacking attack automation",
        hint: "Automating hidden element click attacks on websites"
    },
    {
        word: "Cloud access token abuse automation",
        hint: "Automating misuse of cloud access tokens for unauthorised actions"
    },
    {
        word: "Malware deployment automation",
        hint: "Using scripts or tools to deploy malware widely and automatically"
    },
    {
        word: "Insecure API endpoint exploitation automation",
        hint: "Automating attacks on weak or exposed API endpoints"
    },
    {
        word: "Memory buffer overflow exploitation automation",
        hint: "Automating exploitation of buffer overflow vulnerabilities"
    },
    {
        word: "Command line injection automation",
        hint: "Automating command injection attacks on systems"
    },
    {
        word: "Browser cookie theft automation",
        hint: "Automating stealing of cookies to impersonate users"
    },
    {
        word: "Web server directory traversal attack automation",
        hint: "Automating directory traversal attacks on web servers"
    },
    {
        word: "TLS downgrade attack automation",
        hint: "Automating forcing of weaker TLS protocols to intercept data"
    },
    {
        word: "Malicious cloud deployment automation",
        hint: "Automating deployment of harmful applications or scripts in cloud environments"
    },
    {
        word: "Session fixation attack automation",
        hint: "Automating forcing of session IDs to hijack user sessions"
    },
    {
        word: "API key leakage automation",
        hint: "Automating exposure of sensitive API keys for unauthorised access"
    },
    {
        word: "IoT firmware exploitation automation",
        hint: "Automating exploitation of IoT device firmware vulnerabilities"
    },
    {
        word: "Browser autofill attack automation",
        hint: "Automating attacks on sensitive browser autofill data"
    },
    {
        word: "Mobile device rooting exploit automation",
        hint: "Automating gaining root access on mobile devices"
    },
    {
        word: "Server side encryption bypass automation",
        hint: "Automating bypass of server-side encryption mechanisms"
    },
    {
        word: "Credential replay attack automation",
        hint: "Automating the reuse of stolen credentials to gain unauthorised access"
    },
    {
        word: "Cloud misconfiguration exploitation automation",
        hint: "Automating exploitation of weak cloud configurations"
    },
    {
        word: "Browser plugin privilege escalation automation",
        hint: "Automating abuse of browser plugin vulnerabilities for higher access"
    },
    {
        word: "API misuse exploitation automation",
        hint: "Automating misuse of APIs to perform unauthorised actions"
    },
    {
        word: "Memory leak exploitation automation",
        hint: "Automating use of memory leaks to extract sensitive data or crash apps"
    },
    {
        word: "Command injection via web automation",
        hint: "Automating injection of system commands through web inputs"
    },
    {
        word: "Automated malware execution",
        hint: "Using scripts to deploy malware automatically across multiple systems"
    },
    {
        word: "Server configuration disclosure automation",
        hint: "Automating exposure of sensitive server settings"
    },
    {
        word: "TLS downgrade exploitation automation",
        hint: "Automating forcing of weaker encryption protocols to intercept data"
    },
    {
        word: "Malicious npm dependency automation",
        hint: "Automating injection of harmful npm packages"
    },
    {
        word: "Mobile device rooting automation",
        hint: "Automating gaining root privileges on mobile devices"
    },
    {
        word: "Browser cookie tampering automation",
        hint: "Automating modification of cookies to impersonate users or steal data"
    },
    {
        word: "Server side template injection automation",
        hint: "Automating injection of malicious code into server-side templates"
    },
    {
        word: "API token theft automation",
        hint: "Automating stealing of API tokens for unauthorised access"
    },
    {
        word: "Browser storage manipulation automation",
        hint: "Automating manipulation of local/session storage for malicious purposes"
    },
    {
        word: "Cross site scripting automation",
        hint: "Automating injection of scripts to perform XSS attacks"
    },
    {
        word: "Hypertext markup language",
        hint: "The standard language used to create webpages"
    },
    {
        word: "Cascading style sheets",
        hint: "Language used to style and layout web pages"
    },
    {
        word: "JavaScript event listener",
        hint: "Function that waits for user actions like clicks or keypresses"
    },
    {
        word: "Python list comprehension",
        hint: "Short syntax to create a new list from an existing list"
    },
    {
        word: "Black hat hacking",
        hint: "Illegal hacking performed for malicious purposes"
    },
    {
        word: "White hat hacking",
        hint: "Ethical hacking performed to improve security"
    },
    {
        word: "Grey hat hacking",
        hint: "Hackers who sometimes break rules but without malicious intent"
    },
    {
        word: "Structured query language injection",
        hint: "A hacking technique used to manipulate databases"
    },
    {
        word: "Cross site scripting attack",
        hint: "Injecting malicious scripts into webpages viewed by others"
    },
    {
        word: "Social engineering attack",
        hint: "Manipulating people to gain confidential information"
    },
    {
        word: "HTML semantic elements",
        hint: "Elements like header and footer that describe page structure"
    },
    {
        word: "CSS flexbox layout",
        hint: "A flexible layout model used for arranging items in a row or column"
    },
    {
        word: "CSS grid layout",
        hint: "A two dimensional layout system used to align content"
    },
    {
        word: "JavaScript asynchronous function",
        hint: "Function that allows non blocking operations using async and await"
    },
    {
        word: "Python virtual environment",
        hint: "Isolated environment to manage dependencies for projects"
    },
    {
        word: "Phishing attack method",
        hint: "Cyber attack that tricks users into revealing information"
    },
    {
        word: "Whaling attack technique",
        hint: "Phishing targeted at high profile individuals"
    },
    {
        word: "HTML document object",
        hint: "The root element of a webpage represented as a tree structure"
    },
    {
        word: "CSS media queries",
        hint: "CSS technique used to apply different styles on different devices"
    },
    {
        word: "JavaScript arrow functions",
        hint: "Short syntax for writing functions introduced in ES6"
    },
    {
        word: "Python lambda function",
        hint: "Small anonymous function defined with the lambda keyword"
    },
    {
        word: "SQL injection bypass",
        hint: "Ways attackers avoid filters to exploit SQL vulnerabilities"
    },
    {
        word: "Cross site request forgery",
        hint: "Attack where a user unknowingly performs actions on a website"
    },
    {
        word: "HTML anchor element",
        hint: "Element used to create hyperlinks in webpages"
    },
    {
        word: "CSS animation property",
        hint: "Property that allows smooth transitions and movements in CSS"
    },
    {
        word: "JavaScript promise chaining",
        hint: "Linking multiple asynchronous operations together"
    },
    {
        word: "Python decorators",
        hint: "Feature that allows modification of functions using wrappers"
    },
    {
        word: "Brute force password attack",
        hint: "Repeatedly trying many password combinations to gain access"
    },
    {
        word: "Dictionary attack method",
        hint: "Using a list of known words to guess passwords"
    },
    {
        word: "HTML meta tags",
        hint: "Tags that provide information about a webpage to browsers"
    },
    {
        word: "CSS pseudo classes",
        hint: "Keywords added to selectors to style elements in specific states"
    },
    {
        word: "JavaScript json parsing",
        hint: "Converting JSON text into JavaScript objects"
    },
    {
        word: "Python tuples",
        hint: "Immutable ordered collections of data"
    },
    {
        word: "Keylogger attack",
        hint: "Malware that records typed keystrokes"
    },
    {
        word: "Man in the middle attack",
        hint: "Intercepting communication between two parties"
    },
    {
        word: "HTML form element",
        hint: "Used to collect user input such as text fields and buttons"
    },
    {
        word: "CSS box model",
        hint: "Describes margins padding borders and content of an element"
    },
    {
        word: "JavaScript dom manipulation",
        hint: "Changing HTML and CSS dynamically using JavaScript"
    },
    {
        word: "Python exception handling",
        hint: "Using try and except to manage errors"
    },
    {
        word: "Ransomware attack",
        hint: "Malware that locks files until payment is made"
    },
    {
        word: "SQL enumeration attack",
        hint: "Gathering information about a database during an attack"
    },
    {
        word: "HTML list elements",
        hint: "Elements used to create ordered and unordered lists"
    },
    {
        word: "CSS transform property",
        hint: "Used to rotate scale skew or translate elements"
    },
    {
        word: "JavaScript interval function",
        hint: "Runs code repeatedly at fixed time intervals"
    },
    {
        word: "Python class inheritance",
        hint: "Feature allowing classes to inherit attributes from others"
    },
    {
        word: "Denial of service attack",
        hint: "Attack that floods a server with traffic to take it offline"
    },
    {
        word: "Distributed denial of service attack",
        hint: "DoS attack using many compromised systems"
    },
    {
        word: "HTML table element",
        hint: "Used to display rows and columns of data"
    },
    {
        word: "CSS position property",
        hint: "Controls how an element is placed on a page"
    },
    {
        word: "JavaScript fetch api",
        hint: "Method used to request resources over networks"
    },
    {
        word: "Python dictionary operations",
        hint: "Key value data structures used widely in applications"
    },
    {
        word: "Zero day exploit",
        hint: "Vulnerability unknown to developers and actively exploited"
    },
    {
        word: "Spyware installation attack",
        hint: "Malicious software used to monitor user activities"
    },
    {
        word: "HTML iframe element",
        hint: "Embeds another webpage inside the current page"
    },
    {
        word: "CSS z index property",
        hint: "Controls stacking order of elements"
    },
    {
        word: "JavaScript local storage",
        hint: "Browser storage system that saves data persistently"
    },
    {
        word: "Python regular expressions",
        hint: "Patterns used to search or manipulate strings"
    },
    {
        word: "Credential stuffing attack",
        hint: "Using leaked passwords to access accounts on other services"
    },
    {
        word: "Packet sniffing attack",
        hint: "Capturing network traffic to analyze data"
    },
    {
        word: "Button",
        hint: "A HTML element that creates clickable buttons on webpages"
    },
    {
        word: "Border radius",
        hint: "A CSS property used to create rounded corners"
    },
    {
        word: "Class syntax",
        hint: "JavaScript class-based approach for creating objects"
    },
    {
        word: "List slicing",
        hint: "Python method of extracting portions of a list using index ranges"
    },
    {
        word: "Spyware",
        hint: "Monitors your online activity and log every key you press on your keyboard"
    },
    {
        word: "Adware",
        hint: "Installed with some versions of software and is designed to automatically deliver advertisements to a user"
    },
    {
        word: "Backdoor",
        hint: "Gain unauthorized access by bypassing the normal authentication procedures to access a system"
    },
    {
        word: "Ransomware",
        hint: "Hold a computer system or the data it contains captive until a payment is made"
    },
    {
        word: "Scareware",
        hint: "Consists of operating system style windows that pop up to warn you that your system is at risk and needs to run a specific program for it to return to normal operation"
    },
    {
        word: "Rootkit",
        hint: "Modify the operating system to create a backdoor to access your computer remotely"
    },
    {
        word: "Virus",
        hint: "Replicates and attaches itself to other executable files by inserting its own code when excuted"
    },
    {
        word: "Worms",
        hint: "Replicates itself to spread from one computer to another which runs by themselves"
    },
];