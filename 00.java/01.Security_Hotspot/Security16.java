###### Enabling JavaScript support for WebViews is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

WebViews can be used to display web content as part of a mobile application. A browser engine is used to render and display the content. Like a web application a mobile application that uses WebViews can be vulnerable to Cross-Site Scripting if untrusted code is rendered. In the context of a WebView JavaScript code can exfiltrate local files that might be sensitive or even worse, access exposed functions of the application that can result in more severe vulnerabilities such as code injection. Thus JavaScript support should not be enabled for WebViews unless it is absolutely necessary and the authenticity of the web resources can be guaranteed.

###### Ask Yourself Whether

    The WebWiew only renders static web content that does not require JavaScript code to be executed.
    The WebView contains untrusted data that could cause harm when rendered.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

import android.webkit.WebView;

WebView webView = (WebView) findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true); // Sensitive



######## Recommended Secure Coding Practices

It’s recommended to disable JavaScript support for WebViews unless it is necessary to execute JavaScript code. Only trusted pages should be rendered.
Compliant Solution

import android.webkit.WebView;

WebView webView = (WebView) findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(false);

See

    OWASP Top 10 2021 Category A3 - Injection
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
    MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

