###### Hard-coded secrets are security-sensitive

Security Hotspot
Blocker

    Available SinceDec 19, 2023
    SonarQube (Java)
    Constant/issue: 30min

Because it is easy to extract strings from an application source code or binary, secrets should not be hard-coded. This is particularly true for applications that are distributed or that are open-source.

In the past, it has led to the following vulnerabilities:

    CVE-2022-25510
    CVE-2021-42635

Secrets should be stored outside of the source code in a configuration file or a management service for secrets.

This rule detects variables/fields having a name matching a list of words (secret, token, credential, auth, api[_.-]?key) being assigned a pseudorandom hard-coded value. The pseudorandomness of the hard-coded value is based on its entropy and the probability to be human-readable. The randomness sensibility can be adjusted if needed. Lower values will detect less random values, raising potentially more false positives.


###### Ask Yourself Whether

    The secret allows access to a sensitive component like a database, a file storage, an API, or a service.
    The secret is used in a production environment.
    Application re-distribution is required before updating the secret.

There would be a risk if you answered yes to any of those questions.
Sensitive Code Example

private static final String MY_SECRET = "47828a8dd77ee1eb9dde2d5e93cb221ce8c32b37";

public static void main(String[] args) {
  MyClass.callMyService(MY_SECRET);
}




######## Recommended Secure Coding Practices

    Store the secret in a configuration file that is not pushed to the code repository.
    Use your cloud provider’s service for managing secrets.
    If a secret has been disclosed through the source code: revoke it and create a new one.

Compliant Solution

Using AWS Secrets Manager:

import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

public static void main(String[] args) {
  SecretsManagerClient secretsClient = ...
  MyClass.doSomething(secretsClient, "MY_SERVICE_SECRET");
}

public static void doSomething(SecretsManagerClient secretsClient, String secretName) {
  GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
    .secretId(secretName)
    .build();

  GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
  String secret = valueResponse.secretString();
  // do something with the secret
  MyClass.callMyService(secret);
}

Using Azure Key Vault Secret:

import com.azure.identity.DefaultAzureCredentialBuilder;

import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;

public static void main(String[] args) throws InterruptedException, IllegalArgumentException {
  String keyVaultName = System.getenv("KEY_VAULT_NAME");
  String keyVaultUri = "https://" + keyVaultName + ".vault.azure.net";

  SecretClient secretClient = new SecretClientBuilder()
    .vaultUrl(keyVaultUri)
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();

  MyClass.doSomething(secretClient, "MY_SERVICE_SECRET");
}

public static void doSomething(SecretClient secretClient, String secretName) {
  KeyVaultSecret retrievedSecret = secretClient.getSecret(secretName);
  String secret = retrievedSecret.getValue(),

  // do something with the secret
  MyClass.callMyService(secret);
}

See

    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A2 - Broken Authentication
    MITRE, CWE-798 - Use of Hard-coded Credentials
    CERT, MSC03-J. - Never hard code sensitive information
