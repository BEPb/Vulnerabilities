###### Searching OS commands in PATH is security-sensitive

Security Hotspot
Minor

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 15min

When executing an OS command and unless you specify the full path to the executable, then the locations in your application’s PATH environment variable will be searched for the executable. That search could leave an opening for an attacker if one of the elements in PATH is a directory under his control.

###### Ask Yourself Whether

    The directories in the PATH environment variable may be defined by not trusted entities.

There is a risk if you answered yes to this question.
Sensitive Code Example

The full path of the command is not specified and thus the executable will be searched in all directories listed in the PATH environment variable:

Runtime.getRuntime().exec("make");  // Sensitive
Runtime.getRuntime().exec(new String[]{"make"});  // Sensitive

ProcessBuilder builder = new ProcessBuilder("make");  // Sensitive
builder.command("make");  // Sensitive






######## Recommended Secure Coding Practices

Fully qualified/absolute path should be used to specify the OS command to execute.
Compliant Solution

The command is defined by its full path:

Runtime.getRuntime().exec("/usr/bin/make");  // Compliant
Runtime.getRuntime().exec(new String[]{"~/bin/make"});  // Compliant

ProcessBuilder builder = new ProcessBuilder("./bin/make");  // Compliant
builder.command("../bin/make");  // Compliant
builder.command(Arrays.asList("..\bin\make", "-j8")); // Compliant

builder = new ProcessBuilder(Arrays.asList(".\make"));  // Compliant
builder.command(Arrays.asList("C:\bin\make", "-j8"));  // Compliant
builder.command(Arrays.asList("\\SERVER\bin\make"));  // Compliant

See

    OWASP Top 10 2021 Category A8 - Software and Data Integrity Failures
    OWASP Top 10 2017 Category A1 - Injection
    MITRE, CWE-426 - Untrusted Search Path
    MITRE, CWE-427 - Uncontrolled Search Path Element


