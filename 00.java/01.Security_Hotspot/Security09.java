###### Creating cookies without the "HttpOnly" flag is security-sensitive

Security Hotspot
Minor

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 10min

When a cookie is configured with the HttpOnly attribute set to true, the browser guaranties that no client-side script will be able to read it. In most cases, when a cookie is created, the default value of HttpOnly is false and it’s up to the developer to decide whether or not the content of the cookie can be read by the client-side script. As a majority of Cross-Site Scripting (XSS) attacks target the theft of session-cookies, the HttpOnly attribute can help to reduce their impact as it won’t be possible to exploit the XSS vulnerability to steal session-cookies.


###### Ask Yourself Whether

    the cookie is sensitive, used to authenticate the user, for instance a session-cookie
    the HttpOnly attribute offer an additional protection (not the case for an XSRF-TOKEN cookie / CSRF token for example)

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

If you create a security-sensitive cookie in your JAVA code:

Cookie c = new Cookie(COOKIENAME, sensitivedata);
c.setHttpOnly(false);  // Sensitive: this sensitive cookie is created with the httponly flag set to false and so it can be stolen easily in case of XSS vulnerability

By default the HttpOnly flag is set to false:

Cookie c = new Cookie(COOKIENAME, sensitivedata);  // Sensitive: this sensitive cookie is created with the httponly flag not defined (by default set to false) and so it can be stolen easily in case of XSS vulnerability




######## Recommended Secure Coding Practices

    By default the HttpOnly flag should be set to true for most of the cookies and it’s mandatory for session / sensitive-security cookies.

Compliant Solution

Cookie c = new Cookie(COOKIENAME, sensitivedata);
c.setHttpOnly(true); // Compliant: this sensitive cookie is protected against theft (HttpOnly=true)

See

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP HttpOnly
    OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
    MITRE, CWE-1004 - Sensitive Cookie Without 'HttpOnly' Flag
    SANS Top 25 - Insecure Interaction Between Components
    Derived from FindSecBugs rule HTTPONLY_COOKIE

