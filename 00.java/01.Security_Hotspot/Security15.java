###### Enabling file access for WebViews is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

WebViews can be used to display web content as part of a mobile application. A browser engine is used to render and display the content. Like a web application a mobile application that uses WebViews can be vulnerable to Cross-Site Scripting if untrusted code is rendered.

If malicious JavaScript code in a WebView is executed this can leak the contents of sensitive files when access to local files is enabled.


###### Ask Yourself Whether

    No local files have to be accessed by the Webview.
    The WebView contains untrusted data that could cause harm when rendered.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

import android.webkit.WebView;

WebView webView = (WebView) findViewById(R.id.webview);
webView.getSettings().setAllowFileAccess(true); // Sensitive
webView.getSettings().setAllowContentAccess(true); // Sensitive



######## Recommended Secure Coding Practices

It’s recommended to disable access to local files for WebViews unless it is necessary. In the case of a successful attack through a Cross-Site Scripting vulnerability the attackers attack surface decreases drastically if no files can be read out.
Compliant Solution

import android.webkit.WebView;

WebView webView = (WebView) findViewById(R.id.webview);
webView.getSettings().setAllowFileAccess(false);
webView.getSettings().setAllowContentAccess(false);

See

    OWASP Top 10 2021 Category A3 - Injection
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
    MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
