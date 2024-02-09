###### Disabling CSRF protections is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

A cross-site request forgery (CSRF) attack occurs when a trusted user of a web application can be forced, by an attacker, to perform sensitive actions that he didn’t intend, such as updating his profile or sending a message, more generally anything that can change the state of the application.

The attacker can trick the user/victim to click on a link, corresponding to the privileged action, or to visit a malicious web site that embeds a hidden web request and as web browsers automatically include cookies, the actions can be authenticated and sensitive.


###### Ask Yourself Whether

    The web application uses cookies to authenticate users.
    There exist sensitive operations in the web application that can be performed when the user is authenticated.
    The state / resources of the web application can be modified by doing HTTP POST or HTTP DELETE requests for example.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

Spring Security provides by default a protection against CSRF attacks which can be disabled:

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable(); // Sensitive: csrf protection is entirely disabled
   // or
    http.csrf().ignoringAntMatchers("/route/"); // Sensitive: csrf protection is disabled for specific routes
  }
}




######## Recommended Secure Coding Practices

    Protection against CSRF attacks is strongly recommended:
        to be activated by default for all unsafe HTTP methods.
        implemented, for example, with an unguessable CSRF token
    Of course all sensitive operations should not be performed with safe HTTP methods like GET which are designed to be used only for information retrieval.

Compliant Solution

Spring Security CSRF protection is enabled by default, do not disable it:

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // http.csrf().disable(); // Compliant
  }
}

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    MITRE, CWE-352 - Cross-Site Request Forgery (CSRF)
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    OWASP: Cross-Site Request Forgery
    SANS Top 25 - Insecure Interaction Between Components
