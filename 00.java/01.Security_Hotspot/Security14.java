###### Disclosing fingerprints from web application technologies is security-sensitive

Security Hotspot
Minor

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

Disclosing technology fingerprints allows an attacker to gather information about the technologies used to develop the web application and to perform relevant security assessments more quickly (like the identification of known vulnerable components).


###### Ask Yourself Whether

    The x-powered-by HTTP header or similar is used by the application.
    Technologies used by the application are confidential and should not be easily guessed.

There is a risk if you answered yes to any of these questions.
Sensitive Code Example

public ResponseEntity<String> testResponseEntity() {
  HttpHeaders responseHeaders = new HttpHeaders();
  responseHeaders.set("x-powered-by", "myproduct"); // Sensitive

  return new ResponseEntity<String>("foo", responseHeaders, HttpStatus.CREATED);
}






######## Recommended Secure Coding Practices

It’s recommended to not disclose technologies used on a website, with x-powered-by HTTP header for example.

In addition, it’s better to completely disable this HTTP header rather than setting it a random value.
Compliant Solution

Don’t use x-powered-by or Server HTTP header or any other means disclosing fingerprints of the application.
See

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Testing Guide - OTG-INFO-008 - Fingerprint Web Application Framework
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-200 - Information Exposure
