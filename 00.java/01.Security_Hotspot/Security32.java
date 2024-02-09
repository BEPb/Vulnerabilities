###### Using publicly writable directories is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)

Operating systems have global directories where any user has write access. Those folders are mostly used as temporary storage areas like /tmp in Linux based systems. An application manipulating files from these folders is exposed to race conditions on filenames: a malicious user can try to create a file with a predictable name before the application does. A successful attack can result in other files being accessed, modified, corrupted or deleted. This risk is even higher if the application runs with elevated permissions.

In the past, it has led to the following vulnerabilities:

    CVE-2012-2451
    CVE-2015-1838

This rule raises an issue whenever it detects a hard-coded path to a publicly writable directory like /tmp (see examples bellow). It also detects access to environment variables that point to publicly writable directories, e.g., TMP and TMPDIR.

    /tmp
    /var/tmp
    /usr/tmp
    /dev/shm
    /dev/mqueue
    /run/lock
    /var/run/lock
    /Library/Caches
    /Users/Shared
    /private/tmp
    /private/var/tmp
    \Windows\Temp
    \Temp
    \TMP


###### Ask Yourself Whether

    Files are read from or written into a publicly writable folder
    The application creates files with predictable names into a publicly writable folder

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

new File("/tmp/myfile.txt"); // Sensitive
Paths.get("/tmp/myfile.txt"); // Sensitive

java.io.File.createTempFile("prefix", "suffix"); // Sensitive, will be in the default temporary-file directory.
java.nio.file.Files.createTempDirectory("prefix"); // Sensitive, will be in the default temporary-file directory.

Map<String, String> env = System.getenv();
env.get("TMP"); // Sensitive





######## Recommended Secure Coding Practices

    Use a dedicated sub-folder with tightly controlled permissions
    Use secure-by-design APIs to create temporary files. Such API will make sure:
        The generated filename is unpredictable
        The file is readable and writable only by the creating user ID
        The file descriptor is not inherited by child processes
        The file will be destroyed as soon as it is closed

Compliant Solution

new File("/myDirectory/myfile.txt");  // Compliant

File.createTempFile("prefix", "suffix", new File("/mySecureDirectory"));  // Compliant

if(SystemUtils.IS_OS_UNIX) {
  FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));
  Files.createTempFile("prefix", "suffix", attr); // Compliant
}
else {
  File f = Files.createTempFile("prefix", "suffix").toFile();  // Compliant
  f.setReadable(true, true);
  f.setWritable(true, true);
  f.setExecutable(true, true);
}

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-377 - Insecure Temporary File
    MITRE, CWE-379 - Creation of Temporary File in Directory with Incorrect Permissions
    OWASP, Insecure Temporary File

