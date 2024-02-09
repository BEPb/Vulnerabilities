###### Using biometric authentication without a cryptographic solution is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

Android comes with Android KeyStore, a secure container for storing key materials. It’s possible to define certain keys to be unlocked when users authenticate using biometric credentials. This way, even if the application process is compromised, the attacker cannot access keys, as presence of the authorized user is required.

These keys can be used, to encrypt, sign or create a message authentication code (MAC) as proof that the authentication result has not been tampered with. This protection defeats the scenario where an attacker with physical access to the device would try to hook into the application process and call the onAuthenticationSucceeded method directly. Therefore he would be unable to extract the sensitive data or to perform the critical operations protected by the biometric authentication.


###### Ask Yourself Whether

The application contains:

    Cryptographic keys / sensitive information that need to be protected using biometric authentication.

There is a risk if you answered yes to this question.
Noncompliant Code Example

A CryptoObject is not used during authentication:

// ...
BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor, callback);
// ...
biometricPrompt.authenticate(promptInfo); // Noncompliant





######## Recommended Secure Coding Practices

It’s recommended to tie the biometric authentication to a cryptographic operation by using a CryptoObject during authentication.
Compliant Solution

A CryptoObject is used during authentication:

// ...
BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor, callback);
// ...
biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher)); // Compliant

See

    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    developer.android.com - Use a cryptographic solution that depends on authentication
    OWASP Mobile Top 10 Category M4 - Insecure Authentication
    OWASP MASVS - Authentication and Session Management Requirements
    MITRE, CWE-287 - Improper Authentication
