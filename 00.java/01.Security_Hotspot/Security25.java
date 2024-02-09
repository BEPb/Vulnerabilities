###### Setting loose POSIX file permissions is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 5min

In Unix, "others" class refers to all users except the owner of the file and the members of the group assigned to this file.

Granting permissions to this group can lead to unintended access to files.


###### Ask Yourself Whether

    The application is designed to be run on a multi-user environment.
    Corresponding files and directories may contain confidential information.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

    public void setPermissions(String filePath) {
        Set<PosixFilePermission> perms = new HashSet<PosixFilePermission>();
        // user permission
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        // group permissions
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        // others permissions
        perms.add(PosixFilePermission.OTHERS_READ); // Sensitive
        perms.add(PosixFilePermission.OTHERS_WRITE); // Sensitive
        perms.add(PosixFilePermission.OTHERS_EXECUTE); // Sensitive

        Files.setPosixFilePermissions(Paths.get(filePath), perms);
    }

    public void setPermissionsUsingRuntimeExec(String filePath) {
        Runtime.getRuntime().exec("chmod 777 file.json"); // Sensitive
    }

    public void setOthersPermissionsHardCoded(String filePath ) {
        Files.setPosixFilePermissions(Paths.get(filePath), PosixFilePermissions.fromString("rwxrwxrwx")); // Sensitive
    }



######## Recommended Secure Coding Practices

The most restrictive possible permissions should be assigned to files and directories.
Compliant Solution

On operating systems that implement POSIX standard. This will throw a UnsupportedOperationException on Windows.

    public void setPermissionsSafe(String filePath) throws IOException {
        Set<PosixFilePermission> perms = new HashSet<PosixFilePermission>();
        // user permission
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        // group permissions
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        // others permissions removed
        perms.remove(PosixFilePermission.OTHERS_READ); // Compliant
        perms.remove(PosixFilePermission.OTHERS_WRITE); // Compliant
        perms.remove(PosixFilePermission.OTHERS_EXECUTE); // Compliant

        Files.setPosixFilePermissions(Paths.get(filePath), perms);
    }

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2017 Category A5 - Broken Access Control
    OWASP File Permission
    MITRE, CWE-732 - Incorrect Permission Assignment for Critical Resource
    MITRE, CWE-266 - Incorrect Privilege Assignment
    CERT, FIO01-J. - Create files with appropriate access permissions
    CERT, FIO06-C. - Create files with appropriate access permissions
    SANS Top 25 - Porous Defenses
