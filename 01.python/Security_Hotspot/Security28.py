###### Использование протоколов открытого текста является чувствительным к безопасности.
'''
Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

В протоколах открытого текста, таких как ftp, telnet или http, отсутствует шифрование передаваемых данных, а также возможность создания соединения с проверкой подлинности. Это означает, что злоумышленник, способный перехватывать трафик из сети, может прочитать, изменить или повредить транспортируемый контент. Эти протоколы небезопасны, поскольку подвергают приложения широкому спектру рисков:

     раскрытие конфиденциальных данных
     трафик перенаправляется на вредоносную конечную точку
     обновление или установщик программного обеспечения, зараженного вредоносным ПО
     выполнение клиентского кода
     повреждение критической информации

Даже в контексте изолированных сетей, таких как автономные среды или сегментированные облачные среды, существует внутренняя угроза. Таким образом, атаки, связанные с перехватом или подделкой сообщений, все еще могут произойти.

Например, злоумышленники могут успешно скомпрометировать предыдущие уровни безопасности следующим образом:

     обход механизмов изоляции
     компрометация компонента сети
     получение учетных данных внутренней учетной записи IAM (либо от учетной записи службы, либо от реального человека)

В таких случаях шифрование связи уменьшит шансы злоумышленников на успешную утечку данных или кражу учетных данных из других сетевых компонентов. Путем наложения различных методов обеспечения безопасности (например, сегментации и шифрования) приложение будет следовать принципу глубокоэшелонированной защиты.

Обратите внимание, что использование протокола http не поддерживается большинством веб-браузеров.

В прошлом это приводило к следующим уязвимостям:

     CVE-2019-6169
     CVE-2019-12327
     CVE-2019-11065

Исключения

В следующих случаях о проблемах не сообщается, поскольку они не считаются конфиденциальными:

     Небезопасная схема протокола, за которой следуют адреса обратной связи, например 127.0.0.1 или localhost.



###### Спросите себя, есть ли

     Данные приложений должны быть защищены от фальсификаций или утечек при передаче по сети.
     Данные приложения передаются по ненадежной сети.
     Правила соответствия требуют, чтобы служба шифровала данные при передаче.
     Ваше приложение отображает веб-страницы с использованием смягченной политики смешанного содержимого.
     Защита на уровне ОС от открытого текстового трафика деактивирована.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
'''
url = "http://example.com" # Sensitive
url = "ftp://anonymous@example.com" # Sensitive
url = "telnet://anonymous@example.com" # Sensitive

import telnetlib
cnx = telnetlib.Telnet("towel.blinkenlights.nl") # Sensitive

import ftplib
cnx = ftplib.FTP("ftp.example.com") # Sensitive

import smtplib
smtp = smtplib.SMTP("smtp.example.com", port=587) # Sensitive

For aws_cdk.aws_elasticloadbalancingv2.ApplicationLoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

lb = elbv2.ApplicationLoadBalancer(
    self,
    "LB",
    vpc=vpc,
    internet_facing=True
)

lb.add_listener(
    "Listener-default",
    port=80, # Sensitive
    open=True
)
lb.add_listener(
    "Listener-http-explicit",
    protocol=elbv2.ApplicationProtocol.HTTP, # Sensitive
    port=8080,
    open=True
)

# For aws_cdk.aws_elasticloadbalancingv2.ApplicationListener:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

elbv2.ApplicationListener(
    self,
    "listener-http-explicit-const",
    load_balancer=lb,
    protocol=elbv2.ApplicationProtocol.HTTP, # Sensitive
    port=8081,
    open=True
)

# For aws_cdk.aws_elasticloadbalancingv2.NetworkLoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)
lb = elbv2.NetworkLoadBalancer(
    self,
    "LB",
    vpc=vpc,
    internet_facing=True
)

lb.add_listener( # Sensitive
    "Listener-default",
    port=1234
)
lb.add_listener(
    "Listener-TCP-explicit",
    protocol=elbv2.Protocol.TCP, # Sensitive
    port=1337
)

# For aws_cdk.aws_elasticloadbalancingv2.NetworkListener:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

elbv2.NetworkListener(
    self,
    "Listener-TCP-explicit",
    protocol=elbv2.Protocol.TCP, # Sensitive
    port=1338,
    load_balancer=lb
)

# For aws_cdk.aws_elasticloadbalancingv2.CfnListener:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

elbv2.CfnListener(
    self,
    "listener-http",
    default_actions=[application_default_action],
    load_balancer_arn=lb.load_balancer_arn,
    protocol="HTTP", # Sensitive
    port=80
)

elbv2.CfnListener(
    self,
    "listener-tcp",
    default_actions=[network_default_action],
    load_balancer_arn=lb.load_balancer_arn,
    protocol="TCP", # Sensitive
    port=1000
)

# For aws_cdk.aws_elasticloadbalancing.LoadBalancerListener:

from aws_cdk import (
    aws_elasticloadbalancing as elb,
)

elb.LoadBalancerListener(
    external_port=10000,
    external_protocol=elb.LoadBalancingProtocol.TCP, # Sensitive
    internal_port=10000
)

elb.LoadBalancerListener(
    external_port=10080,
    external_protocol=elb.LoadBalancingProtocol.HTTP, # Sensitive
    internal_port=10080
)

# For aws_cdk.aws_elasticloadbalancing.CfnLoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancing as elb
)

elb.CfnLoadBalancer(
    self,
    "elb-tcp",
    listeners=[
        elb.CfnLoadBalancer.ListenersProperty(
            instance_port="10000",
            load_balancer_port="10000",
            protocol="tcp" # Sensitive
        )
    ],
    subnets=vpc.select_subnets().subnet_ids
)

elb.CfnLoadBalancer(
    self,
    "elb-http-dict",
    listeners=[
        {
            "instancePort":"10000",
            "loadBalancerPort":"10000",
            "protocol":"http" # Sensitive
        }
    ],
    subnets=vpc.select_subnets().subnet_ids
)

For aws_cdk.aws_elasticloadbalancing.LoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancing as elb,
)

elb.LoadBalancer(
    self,
    "elb-tcp-dict",
    vpc=vpc,
    listeners=[
        {
            "externalPort":10000,
            "externalProtocol":elb.LoadBalancingProtocol.TCP, # Sensitive
            "internalPort":10000
        }
    ]
)

loadBalancer.add_listener(
    external_port=10081,
    external_protocol=elb.LoadBalancingProtocol.HTTP, # Sensitive
    internal_port=10081
)
loadBalancer.add_listener(
    external_port=10001,
    external_protocol=elb.LoadBalancingProtocol.TCP, # Sensitive
    internal_port=10001
)

For aws_cdk.aws_elasticache.CfnReplicationGroup:

from aws_cdk import (
    aws_elasticache as elasticache
)

elasticache.CfnReplicationGroup(
    self,
    "unencrypted-explicit",
    replication_group_description="a replication group",
    automatic_failover_enabled=False,
    transit_encryption_enabled=False, # Sensitive
    cache_subnet_group_name="test",
    engine="redis",
    engine_version="3.2.6",
    num_cache_clusters=1,
    cache_node_type="cache.t2.micro"
)

elasticache.CfnReplicationGroup( # Sensitive, encryption is disabled by default
    self,
    "unencrypted-implicit",
    replication_group_description="a test replication group",
    automatic_failover_enabled=False,
    cache_subnet_group_name="test",
    engine="redis",
    engine_version="3.2.6",
    num_cache_clusters=1,
    cache_node_type="cache.t2.micro"
)

For aws_cdk.aws_kinesis.CfnStream:

from aws_cdk import (
    aws_kinesis as kinesis,
)

kinesis.CfnStream( # Sensitive, encryption is disabled by default for CfnStreams
    self,
    "cfnstream-implicit-unencrytped",
    shard_count=1
)

kinesis.CfnStream(self,
    "cfnstream-explicit-unencrytped",
    shard_count=1,
    stream_encryption=None # Sensitive
)

For aws_cdk.aws_kinesis.Stream:

from aws_cdk import (
    aws_kinesis as kinesis,
)

stream = kinesis.Stream(self,
    "stream-explicit-unencrypted",
    shard_count=1,
    encryption=kinesis.StreamEncryption.UNENCRYPTED # Sensitive
)




### Рекомендуемые методы безопасного кодирования
'''
     Обеспечьте передачу данных приложений по безопасному, аутентифицированному и зашифрованному протоколу, например TLS или SSH. Вот несколько альтернатив наиболее распространенным протоколам открытого текста:
         Используйте ssh как альтернативу telnet.
         Используйте sftp, scp или ftps вместо ftp.
         Используйте https вместо http.
         Используйте SMTP через SSL/TLS или SMTP с STARTTLS вместо открытого текстового SMTP.
     Включайте шифрование связи облачных компонентов, когда это возможно.
     Настройте свое приложение для блокировки смешанного содержимого при рендеринге веб-страниц.
     Если возможно, принудительно отключите на уровне ОС весь трафик в виде открытого текста.

Рекомендуется защищать все транспортные каналы, даже в локальных сетях, поскольку одно незащищенное соединение может поставить под угрозу все приложение или систему.
Соответствующее решение'''

url = "https://example.com"
url = "sftp://anonymous@example.com"
url = "ssh://anonymous@example.com"

import ftplib
cnx = ftplib.FTP_TLS("ftp.example.com")

import smtplib
smtp = smtplib.SMTP("smtp.example.com", port=587)
smtp.starttls(context=context)

smtp_ssl = smtplib.SMTP_SSL("smtp.gmail.com", port=465)

# For aws_cdk.aws_elasticloadbalancingv2.ApplicationLoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

lb = elbv2.ApplicationLoadBalancer(
    self,
    "LB",
    vpc=vpc,
    internet_facing=True
)

lb.add_listener(
    "Listener-https-explicit",
    protocol=elbv2.ApplicationProtocol.HTTPS,
    certificates=[elbv2.ListenerCertificate("certificateARN")],
    port=443,
    open=True
)

lb.add_listener(
    "Listener-https-implicit",
    certificates=[elbv2.ListenerCertificate("certificateARN")],
    port=8443,
    open=True
)

# For aws_cdk.aws_elasticloadbalancingv2.ApplicationListener:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

elbv2.ApplicationListener(
    self,
    "listener-https-explicit-const",
    load_balancer=lb,
    protocol=elbv2.ApplicationProtocol.HTTPS,
    certificates=[elbv2.ListenerCertificate("certificateARN")],
    port=444,
    open=True
)

# For aws_cdk.aws_elasticloadbalancingv2.NetworkLoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)
lb = elbv2.NetworkLoadBalancer(
    self,
    "LB",
    vpc=vpc,
    internet_facing=True
)

lb.add_listener(
    "Listener-TLS-explicit",
    protocol=elbv2.Protocol.TLS,
    certificates=[elbv2.ListenerCertificate("certificateARN")],
    port=443
)
lb.add_listener(
    "Listener-TLS-implicit",
    certificates=[elbv2.ListenerCertificate("certificateARN")],
    port=1024
)

# For aws_cdk.aws_elasticloadbalancingv2.NetworkListener:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

elbv2.NetworkListener(
    self,
    "Listener-TLS-explicit",
    protocol=elbv2.Protocol.TLS,
    certificates=[elbv2.ListenerCertificate("certificateARN")],
    port=443,
    load_balancer=lb
)

# For aws_cdk.aws_elasticloadbalancingv2.CfnListener:

from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)

elbv2.CfnListener(
    self,
    "listener-https",
    default_actions=[application_default_action],
    load_balancer_arn=lb.load_balancer_arn,
    protocol="HTTPS",
    port=443,
    certificates=[elbv2.CfnListener.CertificateProperty(
        certificate_arn="certificateARN"
    )]
)

elbv2.CfnListener(
    self,
    "listener-tls",
    default_actions=[network_default_action],
    load_balancer_arn=lb.load_balancer_arn,
    protocol="TLS",
    port=1001,
    certificates=[elbv2.CfnListener.CertificateProperty(
        certificate_arn="certificateARN"
    )]
)

# For aws_cdk.aws_elasticloadbalancing.LoadBalancerListener:

from aws_cdk import (
    aws_elasticloadbalancing as elb,
)

elb.LoadBalancerListener(
    external_port=10043,
    external_protocol=elb.LoadBalancingProtocol.SSL,
    internal_port=10043,
    ssl_certificate_arn="certificateARN"
)

elb.LoadBalancerListener(
    external_port=10443,
    external_protocol=elb.LoadBalancingProtocol.HTTPS,
    internal_port=10443,
    ssl_certificate_arn="certificateARN"
)

# For aws_cdk.aws_elasticloadbalancing.CfnLoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancing as elb,
)

elb.CfnLoadBalancer(
    self,
    "elb-ssl",
    listeners=[
        elb.CfnLoadBalancer.ListenersProperty(
            instance_port="10043",
            load_balancer_port="10043",
            protocol="ssl",
            ssl_certificate_id=CERTIFICATE_ARN
        )
    ],
    subnets=vpc.select_subnets().subnet_ids
)

elb.CfnLoadBalancer(
    self,
    "elb-https-dict",
    listeners=[
        {
            "instancePort":"10443",
            "loadBalancerPort":"10443",
            "protocol":"https",
            "sslCertificateId":CERTIFICATE_ARN
        }
    ],
    subnets=vpc.select_subnets().subnet_ids
)

# For aws_cdk.aws_elasticloadbalancing.LoadBalancer:

from aws_cdk import (
    aws_elasticloadbalancing as elb,
)

elb.LoadBalancer(
    self,
    "elb-ssl",
    vpc=vpc,
    listeners=[
        {
            "externalPort":10044,
            "externalProtocol":elb.LoadBalancingProtocol.SSL,
            "internalPort":10044,
            "sslCertificateArn":"certificateARN"
        },
        {
            "externalPort":10444,
            "externalProtocol":elb.LoadBalancingProtocol.HTTPS,
            "internalPort":10444,
            "sslCertificateArn":"certificateARN"
        }
    ]
)

loadBalancer = elb.LoadBalancer(
        self,
        "elb-multi-listener",
        vpc=vpc
)
loadBalancer.add_listener(
    external_port=10045,
    external_protocol=elb.LoadBalancingProtocol.SSL,
    internal_port=10045,
    ssl_certificate_arn="certificateARN"
)
loadBalancer.add_listener(
    external_port=10445,
    external_protocol=elb.LoadBalancingProtocol.HTTPS,
    internal_port=10445,
    ssl_certificate_arn="certificateARN"
)

# For aws_cdk.aws_elasticache.CfnReplicationGroup:

from aws_cdk import (
    aws_elasticache as elasticache
)

elasticache.CfnReplicationGroup(
    self,
    "encrypted-explicit",
    replication_group_description="a test replication group",
    automatic_failover_enabled=False,
    transit_encryption_enabled=True,
    cache_subnet_group_name="test",
    engine="redis",
    engine_version="3.2.6",
    num_cache_clusters=1,
    cache_node_type="cache.t2.micro"
)

# For aws_cdk.aws_kinesis.CfnStream:

from aws_cdk import (
    aws_kinesis as kinesis,
)

kinesis.CfnStream(
    self,
    "cfnstream-explicit-encrytped",
    shard_count=1,
    stream_encryption=kinesis.CfnStream.StreamEncryptionProperty(
        encryption_type="KMS",
        key_id="alias/aws/kinesis"
    )
)

stream = kinesis.CfnStream(
    self,
    "cfnstream-explicit-encrytped-dict",
    shard_count=1,
    stream_encryption={
        "encryptionType": "KMS",
        "keyId": "alias/aws/kinesis"
    }
)

# For aws_cdk.aws_kinesis.Stream:

from aws_cdk import (
    aws_kinesis as kinesis,
    aws_kms as kms
)

stream = kinesis.Stream( # Encryption is enabled by default for Streams
    self,
    "stream-implicit-encrypted",
    shard_count=1
)

stream = kinesis.Stream(
    self,
    "stream-explicit-encrypted-managed",
    shard_count=1,
    encryption=kinesis.StreamEncryption.MANAGED
)

key = kms.Key(self, "managed_key")
stream = kinesis.Stream(
    self,
    "stream-explicit-encrypted-selfmanaged",
    shard_count=1,
    encryption=kinesis.StreamEncryption.KMS,
    encryption_key=key
)
'''
See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    Mobile AppSec Verification Standard - Network Communication Requirements
    OWASP Mobile Top 10 2016 Category M3 - Insecure Communication
    MITRE, CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor
    MITRE, CWE-319 - Cleartext Transmission of Sensitive Information
    Google, Moving towards more secure web
    Mozilla, Deprecating non secure http
    AWS Documentation - Listeners for your Application Load Balancers
    AWS Documentation - Stream Encryption'''

