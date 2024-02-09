###### Setting JavaBean properties is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 15min

Setting JavaBean properties is security sensitive. Doing it with untrusted values has led in the past to the following vulnerability:

    CVE-2014-0114

JavaBeans can have their properties or nested properties set by population functions. An attacker can leverage this feature to push into the JavaBean malicious data that can compromise the software integrity. A typical attack will try to manipulate the ClassLoader and finally execute malicious code.

This rule raises an issue when:

    BeanUtils.populate(…​) or BeanUtilsBean.populate(…​) from Apache Commons BeanUtils are called
    BeanUtils.setProperty(…​) or BeanUtilsBean.setProperty(…​) from Apache Commons BeanUtils are called
    org.springframework.beans.BeanWrapper.setPropertyValue(…​) or org.springframework.beans.BeanWrapper.setPropertyValues(…​) from Spring is called



###### Ask Yourself Whether

    the new property values might have been tampered with or provided by an untrusted source.
    sensitive properties can be modified, for example: class.classLoader

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

Company bean = new Company();
HashMap map = new HashMap();
Enumeration names = request.getParameterNames();
while (names.hasMoreElements()) {
    String name = (String) names.nextElement();
    map.put(name, request.getParameterValues(name));
}
BeanUtils.populate(bean, map); // Sensitive: "map" is populated with data coming from user input, here "request.getParameterNames()"





######## Recommended Secure Coding Practices

Sanitize all values used as JavaBean properties.

Don’t set any sensitive properties. Keep full control over which properties are set. If the property names are provided by an unstrusted source, filter them with a whitelist.
See

    OWASP Top 10 2021 Category A3 - Injection
    OWASP Top 10 2021 Category A8 - Software and Data Integrity Failures
    OWASP Top 10 2017 Category A1 - Injection
    MITRE, CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes
    CERT, MSC61-J. - Do not use insecure or weak cryptographic algorithms
    Derived from FindSecBugs rule BEAN_PROPERTY_INJECTION

