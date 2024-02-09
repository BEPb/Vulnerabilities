###### Разрешение неограниченной исходящей связи очень важно для безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/выпуск: 1 час

Разрешение неограниченной исходящей связи может привести к утечке данных.

Ограничительная группа безопасности — это дополнительный уровень защиты, который может предотвратить злоупотребление или эксплуатацию ресурса. Например, это усложняет кражу данных в случае успешно использованной уязвимости.

Принимая решение о том, следует ли ограничить исходящие соединения, учтите, что ограничение соединений приведет к дополнительным работам по администрированию и обслуживанию.


###### Спросите себя, есть ли

     Ресурс имеет доступ к конфиденциальным данным.
     Ресурс является частью частной сети.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_ec2.SecurityGroup:

from aws_cdk import (
    aws_ec2 as ec2
)

ec2.SecurityGroup(  # Sensitive; allow_all_outbound is enabled by default
    self,
    "example",
    vpc=vpc
)


### Рекомендуемые методы безопасного кодирования

Рекомендуется ограничить исходящие соединения набором доверенных пунктов назначения.
Соответствующее решение

For aws_cdk.aws_ec2.SecurityGroup:

from aws_cdk import (
    aws_ec2 as ec2
)

sg = ec2.SecurityGroup(
    self,
    "example",
    vpc=vpc,
    allow_all_outbound=False
)

sg.add_egress_rule(
    peer=ec2.Peer.ipv4("203.0.113.127/32"),
    connection=ec2.Port.tcp(443)
)

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    AWS Documentation - Control traffic to resources using security groups
    MITRE, CWE-284 - Improper Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control




