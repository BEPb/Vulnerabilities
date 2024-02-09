###### Using unencrypted files in mobile applications is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 10min

Storing files locally is a common task for mobile applications. Files that are stored unencrypted can be read out and modified by an attacker with physical access to the device. Access to sensitive data can be harmful for the user of the application, for example when the device gets stolen.


###### Ask Yourself Whether

    The file contains sensitive data that could cause harm when leaked.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

Files.write(path, content); // Sensitive

FileOutputStream out = new FileOutputStream(file); // Sensitive

FileWriter fw = new FileWriter("outfilename", false); // Sensitive




######## Recommended Secure Coding Practices

It’s recommended to password-encrypt local files that contain sensitive information. The class EncryptedFile can be used to easily encrypt files.
Compliant Solution

String masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);

File file = new File(context.getFilesDir(), "secret_data");
EncryptedFile encryptedFile = EncryptedFile.Builder(
    file,
    context,
    masterKeyAlias,
    EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
).build();

// write to the encrypted file
FileOutputStream encryptedOutputStream = encryptedFile.openFileOutput();

See

    OWASP Top 10 2021 Category A4 - Insecure Design
    Mobile AppSec Verification Standard - Data Storage and Privacy Requirements
    OWASP Mobile Top 10 2016 Category M2 - Insecure Data Storage
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data



