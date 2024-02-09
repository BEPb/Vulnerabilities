###### Using unencrypted databases in mobile applications is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 10min

Storing data locally is a common task for mobile applications. Such data includes preferences or authentication tokens for external services, among other things. There are many convenient solutions that allow storing data persistently, for example SQLiteDatabase, SharedPreferences, and Realm. By default these systems store the data unencrypted, thus an attacker with physical access to the device can read them out easily. Access to sensitive data can be harmful for the user of the application, for example when the device gets stolen.



###### Ask Yourself Whether

    The database contains sensitive data that could cause harm when leaked.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

For SQLiteDatabase:

SQLiteDatabase db = activity.openOrCreateDatabase("test.db", Context.MODE_PRIVATE, null); // Sensitive

For SharedPreferences:

SharedPreferences pref = activity.getPreferences(Context.MODE_PRIVATE); // Sensitive

For Realm:

RealmConfiguration config = new RealmConfiguration.Builder().build();
Realm realm = Realm.getInstance(config); // Sensitive


######## Recommended Secure Coding Practices

It’s recommended to password-encrypt local databases that contain sensitive information. Most systems provide secure alternatives to plain-text storage that should be used. If no secure alternative is available the data can also be encrypted manually before it is stored.

The encryption password should not be hard-coded in the application. There are different approaches how the password can be provided to encrypt and decrypt the database. In the case of EncryptedSharedPreferences the Android Keystore can be used to store the password. Other databases can rely on EncryptedSharedPreferences to store passwords. The password can also be provided dynamically by the user of the application or it can be fetched from a remote server if the other methods are not feasible.
Compliant Solution

Instead of SQLiteDatabase you can use SQLCipher:

SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase("test.db", getKey(), null);

Instead of SharedPreferences you can use EncryptedSharedPreferences:

String masterKeyAlias = new MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);
EncryptedSharedPreferences.create(
    "secret",
    masterKeyAlias,
    context,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);

For Realm an encryption key can be specified in the config:

RealmConfiguration config = new RealmConfiguration.Builder()
    .encryptionKey(getKey())
    .build();
Realm realm = Realm.getInstance(config);

See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    Mobile AppSec Verification Standard - Data Storage and Privacy Requirements
    OWASP Mobile Top 10 2016 Category M2 - Insecure Data Storage
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data


