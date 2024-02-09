###### Using unsafe Jackson deserialization configuration is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 15min

Using unsafe Jackson deserialization configuration is security-sensitive. It has led in the past to the following vulnerabilities:

    CVE-2017-4995
    CVE-2018-19362

When Jackson is configured to allow Polymorphic Type Handling (aka PTH), formerly known as Polymorphic Deserialization, "deserialization gadgets" may allow an attacker to perform remote code execution.

This rule raises an issue when:

    enableDefaultTyping() is called on an instance of com.fasterxml.jackson.databind.ObjectMapper or org.codehaus.jackson.map.ObjectMapper.
    or when the annotation @JsonTypeInfo is set at class, interface or field levels and configured with use = JsonTypeInfo.Id.CLASS or use = Id.MINIMAL_CLASS.


###### Ask Yourself Whether

    You configured the Jackson deserializer as mentioned above.
    The serialized data might come from an untrusted source.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // Sensitive

@JsonTypeInfo(use = Id.CLASS) // Sensitive
abstract class PhoneNumber {
}





######## Recommended Secure Coding Practices

    Use the latest patch versions of jackson-databind blocking the already discovered "deserialization gadgets".
    Avoid using the default typing configuration: ObjectMapper.enableDefaultTyping().
    If possible, use @JsonTypeInfo(use = Id.NAME) instead of @JsonTypeInfo(use = Id.CLASS) or @JsonTypeInfo(use = Id. MINIMAL_CLASS) and so rely on @JsonTypeName and @JsonSubTypes.

See

    OWASP Top 10 2021 Category A8 - Software and Data Integrity Failures
    OWASP Top 10 2017 Category A8 - Insecure Deserialization
    OWASP - Deserialization of untrusted data
    MITRE, CWE-502 - Deserialization of Untrusted Data
    On Jackson CVEs: Don’t Panic
    CVE-2017-1509
    CVE-2017-7525
    Derived from FindSecBugs rule JACKSON_UNSAFE_DESERIALIZATION




