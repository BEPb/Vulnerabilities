###### Using long-term access keys is security-sensitive

Security Hotspot
Major

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 1h

In AWS, long-term access keys will be valid until you manually revoke them. This makes them highly sensitive as any exposure can have serious consequences and should be used with care.

This rule will trigger when encountering an instantiation of com.amazonaws.auth.BasicAWSCredentials.

###### Ask Yourself Whether

    The access key is used directly in an application or AWS CLI script running on an Amazon EC2 instance.
    Cross-account access is needed.
    The access keys need to be embedded within a mobile application.
    Existing identity providers (SAML 2.0, on-premises identity store) already exists.

For more information, see Use IAM roles instead of long-term access keys.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.BasicAWSCredentials;
// ...

AWSCredentials awsCredentials = new BasicAWSCredentials(accessKeyId, secretAccessKey);



######## Recommended Secure Coding Practices

Consider using IAM roles or other features of the AWS Security Token Service that provide temporary credentials, limiting the risks.
Compliant Solution

Example for AWS STS (see Getting Temporary Credentials with AWS STS).

BasicSessionCredentials sessionCredentials = new BasicSessionCredentials(
   session_creds.getAccessKeyId(),
   session_creds.getSecretAccessKey(),
   session_creds.getSessionToken());

See

    Best practices for managing AWS access keys
    Managing access keys for IAM users
