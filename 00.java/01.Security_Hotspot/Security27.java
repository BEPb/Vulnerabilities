###### Using clear-text protocols is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)

Clear-text protocols such as ftp, telnet, or http lack encryption of transported data, as well as the capability to build an authenticated connection. It means that an attacker able to sniff traffic from the network can read, modify, or corrupt the transported content. These protocols are not secure as they expose applications to an extensive range of risks:

    sensitive data exposure
    traffic redirected to a malicious endpoint
    malware-infected software update or installer
    execution of client-side code
    corruption of critical information

Even in the context of isolated networks like offline environments or segmented cloud environments, the insider threat exists. Thus, attacks involving communications being sniffed or tampered with can still happen.

For example, attackers could successfully compromise prior security layers by:

    bypassing isolation mechanisms
    compromising a component of the network
    getting the credentials of an internal IAM account (either from a service account or an actual person)

In such cases, encrypting communications would decrease the chances of attackers to successfully leak data or steal credentials from other network components. By layering various security practices (segmentation and encryption, for example), the application will follow the defense-in-depth principle.

Note that using the http protocol is being deprecated by major web browsers.

In the past, it has led to the following vulnerabilities:

    CVE-2019-6169
    CVE-2019-12327
    CVE-2019-11065

Exceptions

No issue is reported for the following cases because they are not considered sensitive:

    Insecure protocol scheme followed by loopback addresses like 127.0.0.1 or localhost.


###### Ask Yourself Whether

    Application data needs to be protected against falsifications or leaks when transiting over the network.
    Application data transits over an untrusted network.
    Compliance rules require the service to encrypt data in transit.
    Your application renders web pages with a relaxed mixed content policy.
    OS-level protections against clear-text traffic are deactivated.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

These clients from Apache commons net libraries are based on unencrypted protocols and are not recommended:

TelnetClient telnet = new TelnetClient(); // Sensitive

FTPClient ftpClient = new FTPClient(); // Sensitive

SMTPClient smtpClient = new SMTPClient(); // Sensitive

Unencrypted HTTP connections, when using okhttp library for instance, should be avoided:

ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.CLEARTEXT) // Sensitive
  .build();

Android WebView can be configured to allow a secure origin to load content from any other origin, even if that origin is insecure (mixed content);

import android.webkit.WebView

WebView webView = findViewById(R.id.webview)
webView.getSettings().setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW); // Sensitive




######## Recommended Secure Coding Practices

    Make application data transit over a secure, authenticated and encrypted protocol like TLS or SSH. Here are a few alternatives to the most common clear-text protocols:
        Use ssh as an alternative to telnet.
        Use sftp, scp, or ftps instead of ftp.
        Use https instead of http.
        Use SMTP over SSL/TLS or SMTP with STARTTLS instead of clear-text SMTP.
    Enable encryption of cloud components communications whenever it is possible.
    Configure your application to block mixed content when rendering web pages.
    If available, enforce OS-level deactivation of all clear-text traffic.

It is recommended to secure all transport channels, even on local networks, as it can take a single non-secure connection to compromise an entire application or system.
Compliant Solution

Use instead these clients from Apache commons net and JSch/ssh library:

JSch jsch = new JSch(); // Compliant

if(implicit) {
  // implicit mode is considered deprecated but offer the same security than explicit mode
  FTPSClient ftpsClient = new FTPSClient(true); // Compliant
}
else {
  FTPSClient ftpsClient = new FTPSClient(); // Compliant
}

if(implicit) {
  // implicit mode is considered deprecated but offer the same security than explicit mode
  SMTPSClient smtpsClient = new SMTPSClient(true); // Compliant
}
else {
  SMTPSClient smtpsClient = new SMTPSClient(); // Compliant
  smtpsClient.connect("127.0.0.1", 25);
  if (smtpsClient.execTLS()) {
    // commands
  }
}

Perform HTTP encrypted connections, with okhttp library for instance:

ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS) // Compliant
  .build();

The most secure mode for Android WebView is MIXED_CONTENT_NEVER_ALLOW;

import android.webkit.WebView

WebView webView = findViewById(R.id.webview)
webView.getSettings().setMixedContentMode(MIXED_CONTENT_NEVER_ALLOW);

See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    Mobile AppSec Verification Standard - Network Communication Requirements
    OWASP Mobile Top 10 2016 Category M3 - Insecure Communication
    MITRE, CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
    MITRE, CWE-319 - Cleartext Transmission of Sensitive Information
    Google, Moving towards more secure web
    Mozilla, Deprecating non secure http
    AWS Documentation - Listeners for your Application Load Balancers
    AWS Documentation - Stream Encryption
