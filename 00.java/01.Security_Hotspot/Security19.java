###### Hard-coded passwords are security-sensitive

Security Hotspot
Blocker

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 30min

Because it is easy to extract strings from an application source code or binary, passwords should not be hard-coded. This is particularly true for applications that are distributed or that are open-source.

In the past, it has led to the following vulnerabilities:

    CVE-2019-13466
    CVE-2018-15389

Passwords should be stored outside of the code in a configuration file, a database, or a password management service.

This rule flags instances of hard-coded passwords used in database and LDAP connections. It looks for hard-coded passwords in connection strings, and for variable names that match any of the patterns from the provided list.

###### Ask Yourself Whether

    The password allows access to a sensitive component like a database, a file storage, an API, or a service.
    The password is used in production environments.
    Application re-distribution is required before updating the password.

There would be a risk if you answered yes to any of those questions.
Sensitive Code Example

String username = "steve";
String password = "blue";
Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +
                  "user=" + uname + "&password=" + password); // Sensitive






######## Recommended Secure Coding Practices

    Store the credentials in a configuration file that is not pushed to the code repository.
    Store the credentials in a database.
    Use your cloud provider’s service for managing secrets.
    If a password has been disclosed through the source code: change it.

Compliant Solution

String username = getEncryptedUser();
String password = getEncryptedPassword();
Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test?" +
                  "user=" + uname + "&password=" + password);

See

    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A2 - Broken Authentication
    MITRE, CWE-798 - Use of Hard-coded Credentials
    MITRE, CWE-259 - Use of Hard-coded Password
    CERT, MSC03-J. - Never hard code sensitive information
    Derived from FindSecBugs rule Hard Coded Password
