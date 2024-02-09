###### Using weak hashing algorithms is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)

Cryptographic hash algorithms such as MD2, MD4, MD5, MD6, HAVAL-128, HMAC-MD5, DSA (which uses SHA-1), RIPEMD, RIPEMD-128, RIPEMD-160, HMACRIPEMD160 and SHA-1 are no longer considered secure, because it is possible to have collisions (little computational effort is enough to find two or more different inputs that produce the same hash).


###### Ask Yourself Whether

The hashed value is used in a security context like:

    User-password storage.
    Security token generation (used to confirm e-mail when registering on a website, reset password, etc …​).
    To compute some message integrity.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

MessageDigest md1 = MessageDigest.getInstance("SHA");  // Sensitive:  SHA is not a standard name, for most security providers it's an alias of SHA-1
MessageDigest md2 = MessageDigest.getInstance("SHA1");  // Sensitive






######## Recommended Secure Coding Practices

Safer alternatives, such as SHA-256, SHA-512, SHA-3 are recommended, and for password hashing, it’s even better to use algorithms that do not compute too "quickly", like bcrypt, scrypt, argon2 or pbkdf2 because it slows down brute force attacks.
Compliant Solution

MessageDigest md1 = MessageDigest.getInstance("SHA-512"); // Compliant

See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    Mobile AppSec Verification Standard - Cryptography Requirements
    OWASP Mobile Top 10 2016 Category M5 - Insufficient Cryptography
    MITRE, CWE-1240 - Use of a Risky Cryptographic Primitive
    SANS Top 25 - Porous Defenses




