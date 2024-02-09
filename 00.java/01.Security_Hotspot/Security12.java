###### Disabling auto-escaping in template engines is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

To reduce the risk of cross-site scripting attacks, templating systems, such as Twig, Django, Smarty, Groovy's template engine, allow configuration of automatic variable escaping before rendering templates. When escape occurs, characters that make sense to the browser (eg: <a>) will be transformed/replaced with escaped/sanitized values (eg: & lt;a& gt; ).

Auto-escaping is not a magic feature to annihilate all cross-site scripting attacks, it depends on the strategy applied and the context, for example a "html auto-escaping" strategy (which only transforms html characters into html entities) will not be relevant when variables are used in a html attribute because ':' character is not escaped and thus an attack as below is possible:

<a href="{{ myLink }}">link</a> // myLink = javascript:alert(document.cookie)
<a href="javascript:alert(document.cookie)">link</a> // JS injection (XSS attack)


###### Ask Yourself Whether

    Templates are used to render web content and
        dynamic variables in templates come from untrusted locations or are user-controlled inputs
        there is no local mechanism in place to sanitize or validate the inputs.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

With JMustache by samskivert:

Mustache.compiler().escapeHTML(false).compile(template).execute(context); // Sensitive
Mustache.compiler().withEscaper(Escapers.NONE).compile(template).execute(context); // Sensitive

With Freemarker:

freemarker.template.Configuration configuration = new freemarker.template.Configuration();
configuration.setAutoEscapingPolicy(DISABLE_AUTO_ESCAPING_POLICY); // Sensitive



######## Recommended Secure Coding Practices

Enable auto-escaping by default and continue to review the use of inputs in order to be sure that the chosen auto-escaping strategy is the right one.
Compliant Solution

With JMustache by samskivert:

Mustache.compiler().compile(template).execute(context); // Compliant, auto-escaping is enabled by default
Mustache.compiler().escapeHTML(true).compile(template).execute(context); // Compliant

With Freemarker. See "setAutoEscapingPolicy" documentation for more details.

freemarker.template.Configuration configuration = new freemarker.template.Configuration();
configuration.setAutoEscapingPolicy(ENABLE_IF_DEFAULT_AUTO_ESCAPING_POLICY); // Compliant

See

    OWASP Top 10 2021 Category A3 - Injection
    OWASP Cheat Sheet - XSS Prevention Cheat Sheet
    OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
    MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

