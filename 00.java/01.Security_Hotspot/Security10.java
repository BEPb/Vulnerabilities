###### CCreating cookies without the "secure" flag is security-sensitive

Security Hotspot
Minor

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

When a cookie is protected with the secure attribute set to true it will not be send by the browser over an unencrypted HTTP request and thus cannot be observed by an unauthorized person during a man-in-the-middle attack.


###### Ask Yourself Whether

    the cookie is for instance a session-cookie not designed to be sent over non-HTTPS communication.
    it’s not sure that the website contains mixed content or not (ie HTTPS everywhere or not)

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

If you create a security-sensitive cookie in your JAVA code:

Cookie c = new Cookie(COOKIENAME, sensitivedata);
c.setSecure(false);  // Sensitive: a security-ensitive cookie is created with the secure flag set to false

By default the secure flag is set to false:

Cookie c = new Cookie(COOKIENAME, sensitivedata);  // Sensitive: a security-sensitive cookie is created with the secure flag not defined (by default set to false)




######## Recommended Secure Coding Practices

    It is recommended to use HTTPs everywhere so setting the secure flag to true should be the default behaviour when creating cookies.
    Set the secure flag to true for session-cookies.

Compliant Solution

Cookie c = new Cookie(COOKIENAME, sensitivedata);
c.setSecure(true); // Compliant: the sensitive cookie will not be send during an unencrypted HTTP request thanks to the secure flag set to true

See

    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-311 - Missing Encryption of Sensitive Data
    MITRE, CWE-315 - Cleartext Storage of Sensitive Information in a Cookie
    MITRE, CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    SANS Top 25 - Porous Defenses

