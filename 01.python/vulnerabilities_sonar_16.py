'''A secure password should be used when connecting to a database

Vulnerability
Blocker

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 45min

When relying on the password authentication mode for the database connection, a secure password should be chosen.

This rule raises an issue when an empty password is used.
Noncompliant Code Example

Flask-SQLAlchemy'''

def configure_app(app):
    app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://user:@domain.com" # Noncompliant

### Django
# settings.py

DATABASES = {
    'postgresql_db': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'quickdb',
        'USER': 'sonarsource',
        'PASSWORD': '', # Noncompliant
        'HOST': 'localhost',
        'PORT': '5432'
    }
}

# mysql/mysql-connector-python

from mysql.connector import connection
connection.MySQLConnection(host='localhost', user='sonarsource', password='')  # Noncompliant

### Compliant Solution
# Flask-SQLAlchemy

def configure_app(app, pwd):
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://user:{pwd}@domain.com" # Compliant

### Django
# settings.py
import os

DATABASES = {
    'postgresql_db': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'quickdb',
        'USER': 'sonarsource',
        'PASSWORD': os.getenv('DB_PASSWORD'),      # Compliant
        'HOST': 'localhost',
        'PORT': '5432'
    }
}

# mysql/mysql-connector-python

from mysql.connector import connection
import os

db_password = os.getenv('DB_PASSWORD')
connection.MySQLConnection(host='localhost', user='sonarsource', password=db_password)  # Compliant

'''See

    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A2 - Broken Authentication
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-521 - Weak Password Requirements'''

'''Administration services access should be restricted to specific IP addresses

Vulnerability
Minor

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 5min

Cloud platforms such as AWS, Azure, or GCP support virtual firewalls that can be used to restrict access to services by controlling inbound and outbound traffic.
Any firewall rule allowing traffic from all IP addresses to standard network ports on which administration services traditionally listen, such as 22 for SSH, can expose these services to exploits and unauthorized access.
Recommended Secure Coding Practices

It’s recommended to restrict access to remote administration services to only trusted IP addresses. In practice, trusted IP addresses are those held by system administrators or those of bastion-like servers.
Noncompliant Code Example

For aws_cdk.aws_ec2.Instance and other constructs that support a connections attribute:'''

from aws_cdk import aws_ec2 as ec2

instance = ec2.Instance(
    self,
    "my_instance",
    instance_type=nano_t2,
    machine_image=ec2.MachineImage.latest_amazon_linux(),
    vpc=vpc
)

instance.connections.allow_from(
    ec2.Peer.any_ipv4(), # Noncompliant
    ec2.Port.tcp(22),
    description="Allows SSH from all IPv4"
)
instance.connections.allow_from_any_ipv4( # Noncompliant
    ec2.Port.tcp(3389),
    description="Allows Terminal Server from all IPv4"
)

# For aws_cdk.aws_ec2.SecurityGroup

from aws_cdk import aws_ec2 as ec2
security_group = ec2.SecurityGroup(
    self,
    "custom-security-group",
    vpc=vpc
)

security_group.add_ingress_rule(
    ec2.Peer.any_ipv4(), # Noncompliant
    ec2.Port.tcp_range(1, 1024)
)

# For aws_cdk.aws_ec2.CfnSecurityGroup

from aws_cdk import aws_ec2 as ec2

ec2.CfnSecurityGroup(
    self,
    "cfn-based-security-group",
    group_description="cfn based security group",
    group_name="cfn-based-security-group",
    vpc_id=vpc.vpc_id,
    security_group_ingress=[
        ec2.CfnSecurityGroup.IngressProperty( # Noncompliant
            ip_protocol="6",
            cidr_ip="0.0.0.0/0",
            from_port=22,
            to_port=22
        ),
        ec2.CfnSecurityGroup.IngressProperty( # Noncompliant
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=3389,
            to_port=3389
        ),
        { # Noncompliant
            "ipProtocol":"-1",
            "cidrIpv6":"::/0"
        }
    ]
)

# For aws_cdk.aws_ec2.CfnSecurityGroupIngress

from aws_cdk import aws_ec2 as ec2

ec2.CfnSecurityGroupIngress( # Noncompliant
    self,
    "ingress-all-ip-tcp-ssh",
    ip_protocol="tcp",
    cidr_ip="0.0.0.0/0",
    from_port=22,
    to_port=22,
    group_id=security_group.attr_group_id
)

ec2.CfnSecurityGroupIngress( # Noncompliant
    self,
    "ingress-all-ipv6-all-tcp",
    ip_protocol="-1",
    cidr_ipv6="::/0",
    group_id=security_group.attr_group_id
)

# Compliant Solution
# For aws_cdk.aws_ec2.Instance and other constructs that support a connections attribute:

from aws_cdk import aws_ec2 as ec2

instance = ec2.Instance(
    self,
    "my_instance",
    instance_type=nano_t2,
    machine_image=ec2.MachineImage.latest_amazon_linux(),
    vpc=vpc
)

instance.connections.allow_from_any_ipv4(
    ec2.Port.tcp(1234),
    description="Allows 1234 from all IPv4"
)

instance.connections.allow_from(
    ec2.Peer.ipv4("192.0.2.0/24"),
    ec2.Port.tcp(22),
    description="Allows SSH from all IPv4"
)

# For aws_cdk.aws_ec2.SecurityGroup

from aws_cdk import aws_ec2 as ec2
security_group = ec2.SecurityGroup(
    self,
    "custom-security-group",
    vpc=vpc
)

security_group.add_ingress_rule(
    ec2.Peer.any_ipv4(),
    ec2.Port.tcp_range(1024, 1048)
)

# For aws_cdk.aws_ec2.CfnSecurityGroup

from aws_cdk import aws_ec2 as ec2

ec2.CfnSecurityGroup(
    self,
    "cfn-based-security-group",
    group_description="cfn based security group",
    group_name="cfn-based-security-group",
    vpc_id=vpc.vpc_id,
    security_group_ingress=[
        ec2.CfnSecurityGroup.IngressProperty(
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=1024,
            to_port=1048
        ),
        {
            "ipProtocol":"6",
            "cidrIp":"192.0.2.0/24",
            "fromPort":22,
            "toPort":22
        }
    ]
)

# For aws_cdk.aws_ec2.CfnSecurityGroupIngress

from aws_cdk import aws_ec2 as ec2

ec2.CfnSecurityGroupIngress(
    self,
    "ingress-all-ipv4-tcp-http",
    ip_protocol="6",
    cidr_ip="0.0.0.0/0",
    from_port=80,
    to_port=80,
    group_id=security_group.attr_group_id
)

ec2.CfnSecurityGroupIngress(
    self,
    "ingress-range-tcp-rdp",
    ip_protocol="tcp",
    cidr_ip="192.0.2.0/24",
    from_port=3389,
    to_port=3389,
    group_id=security_group.attr_group_id
)

'''See

    MITRE, CWE-284 - Improper Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control
    OWASP Top 10 2021 Category A1 - Broken Access Control
    AWS Documentation - Security groups for your VPC
    Azure Documentation - Network security groups
    GCP Documentation - Firewalls
'''
'''python:S6317
AWS IAM policies should not allow privilege escalation

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 1h

AWS Identity and Access Management (IAM) is the service that defines access to AWS resources. One of the core components of IAM is the policy which, 
when attached to an identity or a resource, defines its permissions. Policies granting permission to an Identity (a User, a Group or Role) are called 
identity-based policies. They add the ability to an identity to perform a predefined set of actions on a list of resources.

Here is an example of a policy document defining a limited set of permission that grants a user the ability to manage his own access keys.

Privilege escalation generally happens when an identity policy gives an identity the ability to grant more privileges than the ones it already has. 
Here is another example of a policy document that hides a privilege escalation. It allows an identity to generate a new access key for any user from the account, 
including users with high privileges.

Although it looks like it grants a limited set of permissions, this policy would, in practice, give the highest privileges to the identity it’s attached to.

Privilege escalation is a serious issue as it allows a malicious user to easily escalate to a high privilege identity from a low privilege identity it took control of.

The example above is just one of many permission escalation vectors. Here is the list of vectors that the rule can detect:
Vector name 	Summary

Create Policy Version
	

Create a new IAM policy and set it as default

Set Default Policy Version
	

Set a different IAM policy version as default

Create AccessKey
	

Create a new access key for any user

Create Login Profile
	

Create a login profile with a password chosen by the attacker

Update Login Profile
	

Update the existing password with one chosen by the attacker

Attach User Policy
	

Attach a permissive IAM policy like "AdministratorAccess" to a user the attacker controls

Attach Group Policy
	

Attach a permissive IAM policy like "AdministratorAccess" to a group containing a user the attacker controls

Attach Role Policy
	

Attach a permissive IAM policy like "AdministratorAccess" to a role that can be assumed by the user the attacker controls

Put User Policy
	

Alter the existing inline IAM policy from a user the attacker controls

Put Group Policy
	

Alter the existing inline IAM policy from a group containing a user that the attacker controls

Put Role Policy
	

Alter an existing inline IAM role policy. The rule will then be assumed by the user that the attacker controls

Add User to Group
	

Add a user that the attacker controls to a group that has a larger range of permissions

Update Assume Role Policy
	

Update a role’s "AssumeRolePolicyDocument" to allow a user the attacker controls to assume it

EC2
	

Create an EC2 instance that will execute with high privileges

Lambda Create and Invoke
	

Create a Lambda function that will execute with high privileges and invoke it

Lambda Create and Add Permission
	

Create a Lambda function that will execute with high privileges and grant permission to invoke it to a user or a service

Lambda triggered with an external event
	

Create a Lambda function that will execute with high privileges and link it to an external event

Update Lambda code
	

Update the code of a Lambda function executing with high privileges

CloudFormation
	

Create a CloudFormation stack that will execute with high privileges

Data Pipeline
	

Create a Pipeline that will execute with high privileges

Glue Development Endpoint
	

Create a Glue Development Endpoint that will execute with high privileges

Update Glue Dev Endpoint
	

Update the associated SSH key for the Glue endpoint

The general recommendation to protect against privilege escalation is to restrict the resources to which sensitive permissions are granted. The first example above is a good demonstration of sensitive permissions being used with a narrow scope of resources and where no privilege escalation is possible.
Noncompliant Code Example

The following policy allows an attacker to update the code of any Lambda function. An attacker can achieve privilege escalation by altering the code of a Lambda that executes with high privileges.

'''






from aws_cdk.aws_iam import Effect, PolicyDocument, PolicyStatement

PolicyDocument(
    statements=[
        PolicyStatement(
            effect=Effect.ALLOW,
            actions=["lambda:UpdateFunctionCode"],
            resources=["*"]  # Noncompliant
        )
    ]
)

# Compliant Solution

# Narrow the policy such that only updates to the code of certain Lambda functions are allowed.

from aws_cdk.aws_iam import Effect, PolicyDocument, PolicyStatement

PolicyDocument(
    statements=[
        PolicyStatement(
            effect=Effect.ALLOW,
            actions=["lambda:UpdateFunctionCode"],
            resources=[
                "arn:aws:lambda:us-east-2:123456789012:function:my-function:1"
            ]
        )
    ]
)

'''See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    Rhino Security Labs - AWS IAM Privilege Escalation – Methods and Mitigation
    OWASP Top 10 2017 Category A5 - Broken Access Control
    MITRE, CWE-269 - Improper Privilege Management
'''

'''Cipher algorithms should be robust

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 15min

Strong cipher algorithms are cryptographic systems resistant to cryptanalysis, they are not vulnerable to well-known attacks like brute force attacks for example.

A general recommendation is to only use cipher algorithms intensively tested and promoted by the cryptographic community.

More specifically for block cipher, it’s not recommended to use algorithm with a block size inferior than 128 bits.
Noncompliant Code Example

pycryptodomex library:'''

from Cryptodome.Cipher import DES, DES3, ARC2, ARC4, Blowfish, AES
from Cryptodome.Random import get_random_bytes

key = b'-8B key-'
DES.new(key, DES.MODE_OFB) # Noncompliant: DES works with 56-bit keys allow attacks via exhaustive search

key = DES3.adjust_key_parity(get_random_bytes(24))
cipher = DES3.new(key, DES3.MODE_CFB) # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack

key = b'Sixteen byte key'
cipher = ARC2.new(key, ARC2.MODE_CFB) # Noncompliant: RC2 is vulnerable to a related-key attack

key = b'Very long and confidential key'
cipher = ARC4.new(key) # Noncompliant: vulnerable to several attacks (see https://en.wikipedia.org/wiki/RC4#Security)

key = b'An arbitrarily long key'
cipher = Blowfish.new(key, Blowfish.MODE_CBC) # Noncompliant: Blowfish use a 64-bit block size makes it vulnerable to birthday attacks

# pycryptodome library:

from Crypto.Cipher import DES, DES3, ARC2, ARC4, Blowfish, AES
from Crypto.Random import get_random_bytes

key = b'-8B key-'
DES.new(key, DES.MODE_OFB) # Noncompliant: DES works with 56-bit keys allow attacks via exhaustive search

key = DES3.adjust_key_parity(get_random_bytes(24))
cipher = DES3.new(key, DES3.MODE_CFB) # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack

key = b'Sixteen byte key'
cipher = ARC2.new(key, ARC2.MODE_CFB) # Noncompliant: RC2 is vulnerable to a related-key attack

key = b'Very long and confidential key'
cipher = ARC4.new(key) # Noncompliant: vulnerable to several attacks (see https://en.wikipedia.org/wiki/RC4#Security)

key = b'An arbitrarily long key'
cipher = Blowfish.new(key, Blowfish.MODE_CBC) # Noncompliant: Blowfish use a 64-bit block size makes it vulnerable to birthday attacks

# pyca library:

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = os.urandom(16)
iv = os.urandom(16)

tdes4 = Cipher(algorithms.TripleDES(key), mode=None, backend=default_backend()) # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack
bf3 = Cipher(algorithms.Blowfish(key), mode=None, backend=default_backend()) # Noncompliant: Blowfish use a 64-bit block size makes it vulnerable to birthday attacks
rc42 = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend()) # Noncompliant: vulnerable to several attacks (see https://en.wikipedia.org/wiki/RC4#Security)

# pydes library:

import pyDes;

des1 = pyDes.des('ChangeIt')  # Noncompliant: DES works with 56-bit keys allow attacks via exhaustive search
des2 = pyDes.des('ChangeIt', pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5) # Noncompliant: DES works with 56-bit keys allow attacks via exhaustive search

tdes1 = pyDes.triple_des('ChangeItWithYourKey!!!!!')  # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack
tdes2 = pyDes.triple_des('ChangeItWithYourKey!!!!!', pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5) # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack

# pycrypto library is not maintained and therefore should not be used:

from Crypto.Cipher import *

des3 = DES.new('ChangeIt') # Noncompliant: DES works with 56-bit keys allow attacks via exhaustive search
tdes3 = DES3.new('ChangeItChangeIt') # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack
bf2 = Blowfish.new('ChangeItWithYourKey', Blowfish.MODE_CBC, 'ChangeIt') # Noncompliant: Blowfish use a 64-bit block size makes it
rc21 = ARC2.new('ChangeItWithYourKey', ARC2.MODE_CFB, 'ChangeIt') # Noncompliant: RC2 is vulnerable to a related-key attack
rc41 = ARC4.new('ChangeItWithYourKey') # Noncompliant: vulnerable to several attacks (see https://en.wikipedia.org/wiki/RC4#Security)

### Compliant Solution
# pycryptodomex library:

from Cryptodome.Cipher import AES

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_CCM) # Compliant

# pycryptodome library:

from Crypto.Cipher import AES

key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_CCM) # Compliant

# pyca library:

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = os.urandom(16)
iv = os.urandom(16)

aes2 = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) # Compliant

# pycrypto library is not maintained and therefore should not be used:

from Crypto.Cipher import *

aes1 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456') # Compliant

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    SANS Top 25 - Porous Defenses
'''
'''Cipher Block Chaining IVs should be unpredictable

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 15min

When encrypting data with the Cipher Block Chaining (CBC) mode an Initialization Vector (IV) is used to randomize the encryption, ie under a given key the same plaintext doesn’t always produce the same ciphertext. The IV doesn’t need to be secret but should be unpredictable to avoid "Chosen-Plaintext Attack".

To generate Initialization Vectors, NIST recommends to use a secure random number generator.
Noncompliant Code Example

For PyCryptodome module:'''

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

static_vector = b'x' * AES.block_size
cipher = AES.new(key, AES.MODE_CBC, static_vector)
cipher.encrypt(pad(data, AES.block_size))  # Noncompliant

# For cryptography module:

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

static_vector = b'x' * 16
cipher = Cipher(algorithms.AES(key), modes.CBC(static_vector))
cipher.encryptor()  # Noncompliant

# Compliant Solution
# For PyCryptodome module:

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

random_vector = get_random_bytes(AES.block_size)
cipher = AES.new(key, AES.MODE_CBC, random_vector)
cipher.encrypt(pad(data, AES.block_size))

# For cryptography module:

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

random_vector = urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(random_vector))
cipher.encryptor()

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    Mobile AppSec Verification Standard - Cryptography Requirements
    OWASP Mobile Top 10 2016 Category M5 - Insufficient Cryptography
    MITRE, CWE-329 - Not Using an Unpredictable IV with CBC Mode
    NIST, SP-800-38A - Recommendation for Block Cipher Modes of Operation
'''

'''python:S4426
Cryptographic key generation should be based on strong parameters

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 2min

When generating cryptographic keys (or key pairs), it is important to use strong parameters. Key length, for instance, should provide enough entropy against brute-force attacks.

    For RSA and DSA algorithms key size should be at least 2048 bits long
    For ECC (elliptic curve cryptography) algorithms key size should be at least 224 bits long
    For RSA public key exponent should be at least 65537.

This rule raises an issue when a RSA, DSA or ECC key-pair generator is initialized using weak parameters.

It supports the following libraries:

    cryptography
    PyCrypto
    Cryptodome

Noncompliant Code Example'''

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

dsa.generate_private_key(key_size=1024, backend=backend) # Noncompliant
rsa.generate_private_key(public_exponent=999, key_size=2048, backend=backend) # Noncompliant
ec.generate_private_key(curve=ec.SECT163R2, backend=backend)  # Noncompliant

# Compliant Solution

from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

dsa.generate_private_key(key_size=2048, backend=backend) # Compliant
rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend) # Compliant
ec.generate_private_key(curve=ec.SECT409R1, backend=backend) # Compliant

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    ANSSI RGSv2 - Référentiel Général de Sécurité version 2
    NIST FIPS 186-4 - Digital Signature Standard (DSS)
    MITRE, CWE-326 - Inadequate Encryption Strength
'''

'''Encryption algorithms should be used with secure mode and padding scheme

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 20min

Encryption algorithms should use secure modes and padding schemes where appropriate to guarantee data confidentiality and integrity.

    For block cipher encryption algorithms (like AES):
        The ECB (Electronic Codebook) cipher mode doesn’t provide serious message confidentiality: under a given key any given plaintext block always gets encrypted to the same ciphertext block. This mode should never be used.
        The CBC (Cipher Block Chaining) mode by itself provides only data confidentiality. This cipher mode is also vulnerable to padding oracle attacks when used with padding. Using CBC along with Message Authentication Code can provide data integrity and should prevent such attacks. In practice the implementation has many pitfalls and it’s recommended to avoid CBC with padding completely.
        The GCM (Galois Counter Mode) mode which works internally with zero/no padding scheme, is recommended, as it is designed to provide both data authenticity (integrity) and confidentiality. Other similar modes are CCM, CWC, EAX, IAPM and OCB.
    For RSA encryption algorithm, the recommended padding scheme is OAEP.

Noncompliant Code Example

pycryptodomex library:'''

from Cryptodome.Cipher import AES, PKCS1_OAEP,  PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA

# Example for a symmetric cipher: AES
AES.new(key, AES.MODE_ECB)  # Noncompliant
AES.new(key, AES.MODE_CBC)  # Noncompliant

# Example for a asymmetric cipher: RSA
cipher = PKCS1_v1_5.new(key) # Noncompliant

# pyca library:

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Example for a symmetric cipher: AES
aes = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  # Noncompliant
aes = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())  # Noncompliant

# Example for a asymmetric cipher: RSA
ciphertext = public_key.encrypt(
  message,
  padding.PKCS1v15() # Noncompliant
)

plaintext = private_key.decrypt(
  ciphertext,
  padding.PKCS1v15() # Noncompliant
)

# pydes library:

# For DES cipher
des = pyDes.des('ChangeIt') # Noncompliant
des = pyDes.des('ChangeIt', pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5) # Noncompliant
des = pyDes.des('ChangeIt', pyDes.ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5) # Noncompliant

# pycrypto library is not maintained and therefore should not be used:

# https://pycrypto.readthedocs.io/en/latest/
from Crypto.Cipher import *
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.PublicKey import RSA

# Example for a symmetric cipher: AES
AES.new(key, AES.MODE_ECB)  # Noncompliant
AES.new(key, AES.MODE_CBC, IV=iv)  # Noncompliant

# Example for a asymmetric cipher: RSA
cipher = PKCS1_v1_5.new(key) # Noncompliant

### Compliant Solution
# pycryptodomex library:

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA

# AES is the recommended symmetric cipher with GCM mode
AES.new(key, AES.MODE_GCM)  # Compliant

# RSA is the recommended asymmetric cipher with OAEP padding
cipher = PKCS1_OAEP.new(key) # Compliant

# pyca library:

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# AES is the recommended symmetric cipher with GCM mode
aes = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())  # Compliant

# RSA is the recommended asymmetric cipher with OAEP padding
ciphertext = public_key.encrypt(
  message,
  padding.OAEP( # Compliant
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
  )
)

plaintext = private_key.decrypt(
  ciphertext,
  padding.OAEP( # Compliant
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
  )
)

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    SANS Top 25 - Porous Defenses
'''

'''Hashes should include an unpredictable salt

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 30min

In cryptography, a "salt" is an extra piece of data which is included when hashing a password. This makes rainbow-table attacks more difficult. Using a cryptographic hash function without an unpredictable salt increases the likelihood that an attacker could successfully find the hash value in databases of precomputed hashes (called rainbow-tables).

This rule raises an issue when a hashing function which has been specifically designed for hashing passwords, such as PBKDF2, is used with a non-random, reused or too short salt value. It does not raise an issue on base hashing algorithms such as sha1 or md5 as they should not be used to hash passwords.
Recommended Secure Coding Practices

    Use hashing functions generating their own secure salt or generate a secure random value of at least 16 bytes.
    The salt should be unique by user password.

Noncompliant Code Example

hashlib'''

import crypt
from hashlib import pbkdf2_hmac

hash = pbkdf2_hmac('sha256', password, b'D8VxSmTZt2E2YV454mkqAY5e', 100000)    # Noncompliant: salt is hardcoded

crypt

hash = crypt.crypt(password)         # Noncompliant: salt is not provided

### Compliant Solution
# hashlib

import crypt
from hashlib import pbkdf2_hmac

salt = os.urandom(32)
hash = pbkdf2_hmac('sha256', password, salt, 100000)    # Compliant

crypt

salt = crypt.mksalt(crypt.METHOD_SHA256)
hash = crypt.crypt(password, salt)         # Compliant

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-759 - Use of a One-Way Hash without a Salt
    MITRE, CWE-760 - Use of a One-Way Hash with a Predictable Salt
    SANS Top 25 - Porous Defenses
'''

'''HTML autoescape mechanism should not be globally disabled

Vulnerability
Blocker
Deprecated

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 5min

Template engines have an HTML autoescape mechanism that protects web applications against most common cross-site-scripting (XSS) vulnerabilities.

By default, it automatically replaces HTML special characters in any template variables. This secure by design configuration should not be globally disabled.

Escaping HTML from template variables prevents switching into any execution context, like <script>. Disabling autoescaping forces developers to manually escape each template variable for the application to be safe. A more pragmatic approach is to escape by default and to manually disable escaping when needed.

A successful exploitation of a cross-site-scripting vulnerability by an attacker allow him to execute malicious JavaScript code in a user’s web browser. The most severe XSS attacks involve:

    Forced redirection
    Modify presentation of content
    User accounts takeover after disclosure of sensitive information like session cookies or passwords

This rule supports the following libraries:

    Django Templates
    Jinja2

Noncompliant Code Example'''

from jinja2 import Environment

env = Environment() # Noncompliant; New Jinja2 Environment has autoescape set to false
env = Environment(autoescape=False) # Noncompliant

# Compliant Solution

from jinja2 import Environment
env = Environment(autoescape=True) # Compliant

'''See

    OWASP Cheat Sheet - XSS Prevention Cheat Sheet
    OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
    MITRE, CWE-80 - Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
    MITRE, CWE-81 - Improper Neutralization of Script in an Error Message Web Page
    MITRE, CWE-82 - Improper Neutralization of Script in Attributes of IMG Tags in a Web Page
    MITRE, CWE-83 - Improper Neutralization of Script in Attributes in a Web Page
    MITRE, CWE-84 - Improper Neutralization of Encoded URI Schemes in a Web Page
    MITRE, CWE-85 - Doubled Character XSS Manipulations
    MITRE, CWE-86 - Improper Neutralization of Invalid Characters in Identifiers in Web Pages
    MITRE, CWE-87 - Improper Neutralization of Alternate XSS Syntax
    SANS Top 25 - Insecure Interaction Between Components

Deprecated

This rule is deprecated; use S5247 instead.'''

'''Insecure temporary file creation methods should not be used

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 10min

Creating temporary files using insecure methods exposes the application to race conditions on filenames: a malicious user can try to create a file with a predictable name before the application does. A successful attack can result in other files being accessed, modified, corrupted or deleted. This risk is even higher if the application run with elevated permissions.

In the past, it has led to the following vulnerabilities:

    CVE-2014-1858
    CVE-2014-1932

Noncompliant Code Example'''

import tempfile

filename = tempfile.mktemp() # Noncompliant
tmp_file = open(filename, "w+")

# Compliant Solution

import tempfile

tmp_file1 = tempfile.NamedTemporaryFile(delete=False) # Compliant; Easy replacement to tempfile.mktemp()
tmp_file2 = tempfile.NamedTemporaryFile() # Compliant; Created file will be automatically deleted

'''See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2017 Category A9 - Using Components with Known Vulnerabilities
    MITRE, CWE-377 - Insecure Temporary File
    MITRE, CWE-379 - Creation of Temporary File in Directory with Incorrect Permissions
    OWASP, Insecure Temporary File
    Python tempfile module
    Python 2.7 os module'''

'''python:S5659
JWT should be signed and verified

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 30min

If a JSON Web Token (JWT) is not signed with a strong cipher algorithm (or not signed at all) an attacker can forge it and impersonate user identities.

    Don’t use none algorithm to sign or verify the validity of a token.
    Don’t use a token without verifying its signature before.

Noncompliant Code Example

For pyjwt module:'''

jwt.decode(token, verify = False)  # Noncompliant
jwt.decode(token, key, options={"verify_signature": False})  # Noncompliant

# For python_jwt module:

jwt.process_jwt(token)  # Noncompliant

### Compliant Solution
# For pyjwt module:

jwt.decode(token, key, algo)

# For python_jwt module:

jwt.process_jwt(token)  #  Compliant because followed by verify_jwt()
jwt.verify_jwt(token, key, algo)

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-347 - Improper Verification of Cryptographic Signature'''

'''LDAP connections should be authenticated

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 15min

An LDAP client authenticates to an LDAP server with a "bind request" which provides, among other, a simple authentication method.

Simple authentication in LDAP can be used with three different mechanisms:

    Anonymous Authentication Mechanism by performing a bind request with a username and password value of zero length.
    Unauthenticated Authentication Mechanism by performing a bind request with a password value of zero length.
    Name/Password Authentication Mechanism by performing a bind request with a password value of non-zero length.

Anonymous binds and unauthenticated binds allow access to information in the LDAP directory without providing a password, their use is therefore strongly discouraged.
Noncompliant Code Example'''

import ldap

def init_ldap():
   connect = ldap.initialize('ldap://example:1389')

   connect.simple_bind('cn=root') # Noncompliant
   connect.simple_bind_s('cn=root') # Noncompliant
   connect.bind_s('cn=root', None) # Noncompliant
   connect.bind('cn=root', None) # Noncompliant

# Compliant Solution

import ldap
import os

def init_ldap():
   connect = ldap.initialize('ldap://example:1389')

   connect.simple_bind('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
   connect.simple_bind_s('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
   connect.bind_s('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant
   connect.bind('cn=root', os.environ.get('LDAP_PASSWORD')) # Compliant

'''See

    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A2 - Broken Authentication
    MITRE, CWE-521 - Weak Password Requirements
    ldapwiki.com- Simple Authentication'''

'''Server certificates should be verified during SSL/TLS connections

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 5min

Validation of X.509 certificates is essential to create secure SSL/TLS sessions not vulnerable to man-in-the-middle attacks.

The certificate chain validation includes these steps:

    The certificate is issued by its parent Certificate Authority or the root CA trusted by the system.
    Each CA is allowed to issue certificates.
    Each certificate in the chain is not expired.

It’s not recommended to reinvent the wheel by implementing custom certificate chain validation.

TLS libraries provide built-in certificate validation functions that should be used.
Noncompliant Code Example

psf/requests library:'''

import requests

requests.request('GET', 'https://example.domain', verify=False) # Noncompliant
requests.get('https://example.domain', verify=False) # Noncompliant

# Python ssl standard library:

import ssl

ctx1 = ssl._create_unverified_context() # Noncompliant: by default certificate validation is not done
ctx2 = ssl._create_stdlib_context() # Noncompliant: by default certificate validation is not done

ctx3 = ssl.create_default_context()
ctx3.verify_mode = ssl.CERT_NONE # Noncompliant

# pyca/pyopenssl library:

from OpenSSL import SSL

ctx1 = SSL.Context(SSL.TLSv1_2_METHOD) # Noncompliant: by default certificate validation is not done

ctx2 = SSL.Context(SSL.TLSv1_2_METHOD)
ctx2.set_verify(SSL.VERIFY_NONE, verify_callback) # Noncompliant

# Compliant Solution
# psf/requests library:

import requests

requests.request('GET', 'https://example.domain', verify=True)
requests.request('GET', 'https://example.domain', verify='/path/to/CAbundle')
requests.get(url='https://example.domain') # by default certificate validation is enabled

# Python ssl standard library:

import ssl

ctx = ssl.create_default_context()
ctx.verify_mode = ssl.CERT_REQUIRED

ctx = ssl._create_default_https_context() # by default certificate validation is enabled

# pyca/pyopenssl library:

from OpenSSL import SSL

ctx = SSL.Context(SSL.TLSv1_2_METHOD)
ctx.set_verify(SSL.VERIFY_PEER, verify_callback) # Compliant
ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback) # Compliant
ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT | SSL.VERIFY_CLIENT_ONCE, verify_callback) # Compliant

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    Mobile AppSec Verification Standard - Network Communication Requirements
    OWASP Mobile Top 10 2016 Category M3 - Insecure Communication
    MITRE, CWE-295 - Improper Certificate Validation'''


'''Server hostnames should be verified during SSL/TLS connections

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 5min

To establish a SSL/TLS connection not vulnerable to man-in-the-middle attacks, it’s essential to make sure the server presents the right certificate.

The certificate’s hostname-specific data should match the server hostname.

It’s not recommended to re-invent the wheel by implementing custom hostname verification.

TLS/SSL libraries provide built-in hostname verification functions that should be used.
Noncompliant Code Example

Python ssl standard library:'''

import ssl

ctx = ssl._create_unverified_context() # Noncompliant: by default hostname verification is not done
ctx = ssl._create_stdlib_context() # Noncompliant: by default hostname verification is not done

ctx = ssl.create_default_context()
ctx.check_hostname = False # Noncompliant

ctx = ssl._create_default_https_context()
ctx.check_hostname = False # Noncompliant

# Compliant Solution
# Python ssl standard library:

import ssl

ctx = ssl._create_unverified_context()
ctx.check_hostname = True # Compliant

ctx = ssl._create_stdlib_context()
ctx.check_hostname = True # Compliant

ctx = ssl.create_default_context() # Compliant: by default hostname verification is enabled
ctx = ssl._create_default_https_context() # Compliant: by default hostname verification is enabled

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    Mobile AppSec Verification Standard - Network Communication Requirements
    OWASP Mobile Top 10 2016 Category M3 - Insecure Communication
    MITRE, CWE-297 - Improper Validation of Certificate with Host Mismatch'''


'''Weak SSL/TLS protocols should not be used

Vulnerability
Critical

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 2min

This rule raises an issue when an insecure TLS protocol version (i.e. a protocol different from "TLSv1.2", "TLSv1.3", "DTLSv1.2", or "DTLSv1.3") is used or allowed.

It is recommended to enforce TLS 1.2 as the minimum protocol version and to disallow older versions like TLS 1.0. Failure to do so could open the door to downgrade attacks: a malicious actor who is able to intercept the connection could modify the requested protocol version and downgrade it to a less secure version.

In most cases, using the default system configuration is not compliant. Indeed, an application might get deployed on a wide range of systems with different configurations. While using a system’s default value might be safe on modern up-to-date systems, this might not be the case on older systems. It is therefore recommended to explicitly set a safe configuration in every case.
Noncompliant Code Example'''

from OpenSSL import SSL

SSL.Context(SSL.SSLv3_METHOD)  # Noncompliant

import ssl

ssl.SSLContext(ssl.PROTOCOL_SSLv3) # Noncompliant

# For aws_cdk.aws_apigateway.DomainName:

from aws_cdk.aws_apigateway import DomainName, SecurityPolicy
class ExampleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        DomainName(self, "example",
            domain_name="example.com",
            certificate=certificate,
            security_policy=SecurityPolicy.TLS_1_0 # Noncompliant
        )

# For aws_cdk.aws_opensearchservice.CfnDomain:

from aws_cdk.aws_opensearchservice import CfnDomain, EngineVersion
class ExampleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        CfnDomain(self, "example",
            version=EngineVersion.OPENSEARCH_1_3
        ) # Noncompliant: enables TLS 1.0 which is a deprecated version of the protocol

# Compliant Solution

from OpenSSL import SSL

context = SSL.Context(SSL.TLS_SERVER_METHOD)
context.set_min_proto_version(SSL.TLS1_3_VERSION)

import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3

# For aws_cdk.aws_apigateway.DomainName:

from aws_cdk.aws_apigateway import DomainName, SecurityPolicy
class ExampleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        DomainName(self, "example",
            domain_name="example.com",
            certificate=certificate,
            security_policy=SecurityPolicy.TLS_1_2
        )

# For aws_cdk.aws_opensearchservice.CfnDomain:

from aws_cdk.aws_opensearchservice import CfnDomain, EngineVersion
class ExampleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        CfnDomain(self, "example",
            version=EngineVersion.OPENSEARCH_1_3
            domain_endpoint_options=CfnDomain.DomainEndpointOptionsProperty(
                tls_security_policy="Policy-Min-TLS-1-2-2019-07"
            )
        )

'''See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    Mobile AppSec Verification Standard - Network Communication Requirements
    OWASP Mobile Top 10 2016 Category M3 - Insecure Communication
    MITRE, CWE-327 - Inadequate Encryption Strength
    MITRE, CWE-326 - Use of a Broken or Risky Cryptographic Algorithm
    SANS Top 25 - Porous Defenses
    SSL and TLS Deployment Best Practices - Use secure protocols
    Amazon API Gateway - Choosing a minimum TLS version'''


'''XML parsers should not be vulnerable to XXE attacks

Vulnerability
Blocker

    Available SinceDec 19, 2023
    SonarQube (Python)
    Constant/issue: 15min

XML standard allows the use of entities, declared in the DOCTYPE of the document, which can be internal or external.

When parsing the XML file, the content of the external entities is retrieved from an external storage such as the file system or network, which may lead, if no restrictions are put in place, to arbitrary file disclosures or server-side request forgery (SSRF) vulnerabilities.

Its recommended to limit resolution of external entities by using one of these solutions:

    If DOCTYPE is not necessary, completely disable all DOCTYPE declarations.
    If external entities are not necessary, completely disable their declarations.
    If external entities are necessary then:
        Use XML processor features, if available, to authorize only required protocols (eg: https).
        And use an entity resolver (and optionally an XML Catalog) to resolve only trusted entities.

Noncompliant Code Example

lxml module:

    When parsing XML:'''

parser = etree.XMLParser() # Noncompliant: by default resolve_entities is set to true
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()

parser = etree.XMLParser(resolve_entities=True) # Noncompliant
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()

    # When validating XML:

parser = etree.XMLParser(resolve_entities=True) # Noncompliant
treexsd = etree.parse('ressources/xxe.xsd', parser)
rootxsd = treexsd.getroot()
schema = etree.XMLSchema(rootxsd)

    # When transforming XML:

ac = etree.XSLTAccessControl(read_network=True, write_network=False)  # Noncompliant, read_network is set to true/network access is authorized
transform = etree.XSLT(rootxsl, access_control=ac)

# xml.sax module:

parser = xml.sax.make_parser()
myHandler = MyHandler()
parser.setContentHandler(myHandler)

parser.setFeature(feature_external_ges, True) # Noncompliant
parser.parse("ressources/xxe.xml")

# Compliant Solution
# lxml module:
    # When parsing XML, disable resolve_entities and network access:

parser = etree.XMLParser(resolve_entities=False, no_network=True) # Compliant
tree1 = etree.parse('ressources/xxe.xml', parser)
root1 = tree1.getroot()

    # When validating XML (note that network access cannot be completely disabled when calling XMLSchema):

parser = etree.XMLParser(resolve_entities=False) # Compliant: by default no_network is set to true
treexsd = etree.parse('ressources/xxe.xsd', parser)
rootxsd = treexsd.getroot()
schema = etree.XMLSchema(rootxsd) # Compliant

    # When transforming XML, disable access to network and file system:

parser = etree.XMLParser(resolve_entities=False) # Compliant
treexsl = etree.parse('ressources/xxe.xsl', parser)
rootxsl = treexsl.getroot()

ac = etree.XSLTAccessControl.DENY_ALL  # Compliant
transform = etree.XSLT(rootxsl, access_control=ac) # Compliant

# To prevent xxe attacks with xml.sax module (for other security reasons than XXE, xml.sax is not recommended):

parser = xml.sax.make_parser()
myHandler = MyHandler()
parser.setContentHandler(myHandler)
parser.parse("ressources/xxe.xml") # Compliant: in version 3.7.1: The SAX parser no longer processes general external entities by default

parser.setFeature(feature_external_ges, False) # Compliant
parser.parse("ressources/xxe.xml")

'''See

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2017 Category A4 - XML External Entities (XXE)
    OWASP XXE Prevention Cheat Sheet
    MITRE, CWE-611 - Information Exposure Through XML External Entity Reference
    MITRE, CWE-827 - Improper Control of Document Type Definition
'''
