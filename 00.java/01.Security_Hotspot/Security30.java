###### Using non-standard cryptographic algorithms is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 1d

The use of a non-standard algorithm is dangerous because a determined attacker may be able to break the algorithm and compromise whatever data has been protected. Standard algorithms like SHA-256, SHA-384, SHA-512, …​ should be used instead.

This rule tracks creation of java.security.MessageDigest subclasses.


###### Sensitive Code Example

public class MyCryptographicAlgorithm extends MessageDigest {
  ...
}



######## Recommended Secure Coding Practices

    Use a standard algorithm instead of creating a custom one.

Compliant Solution

MessageDigest digest = MessageDigest.getInstance("SHA-256");

See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    SANS Top 25 - Porous Defenses
    Derived from FindSecBugs rule MessageDigest is Custom
