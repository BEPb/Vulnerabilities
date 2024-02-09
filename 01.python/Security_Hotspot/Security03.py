###### питон: S6329
Разрешение доступа общедоступной сети к облачным ресурсам важно с точки зрения безопасности.

Точка доступа безопасности
Блокатор

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

Включение доступа общедоступной сети к облачным ресурсам может повлиять на способность организации защищать свои данные или внутренние операции от кражи или нарушения работы данных.

В зависимости от компонента входящий доступ из Интернета может быть включен через:

     логическое значение, которое явно разрешает доступ к общедоступной сети.
     присвоение общедоступного IP-адреса.
     правила брандмауэра базы данных, которые разрешают общедоступные диапазоны IP-адресов.

Решение разрешить публичный доступ может быть принято по разным причинам, например, для быстрого обслуживания, экономии времени или случайно.

Данное решение повышает вероятность атак на организацию, таких как:

     утечки данных.
     вторжения в инфраструктуру с целью перманентной кражи из нее.
     и различный вредоносный трафик, например DDoS-атаки.


###### Спросите себя, есть ли

Этот облачный ресурс:

     должна быть общедоступной для любого пользователя Интернета.
     для правильной работы требуется входящий трафик из Интернета.

Существует риск, если вы ответили «нет» хотя бы на один из этих вопросов.
Пример конфиденциального кода

Для aws_cdk.aws_ec2.Instance и подобных конструкций:

from aws_cdk import aws_ec2 as ec2

ec2.Instance(
    self,
    "vpc_subnet_public",
    instance_type=nano_t2,
    machine_image=ec2.MachineImage.latest_amazon_linux(),
    vpc=vpc,
    vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC) # Sensitive
)

For aws_cdk.aws_ec2.CfnInstance:

from aws_cdk import aws_ec2 as ec2

ec2.CfnInstance(
    self,
    "cfn_public_exposed",
    instance_type="t2.micro",
    image_id="ami-0ea0f26a6d50850c5",
    network_interfaces=[
        ec2.CfnInstance.NetworkInterfaceProperty(
            device_index="0",
            associate_public_ip_address=True, # Sensitive
            delete_on_termination=True,
            subnet_id=vpc.select_subnets(subnet_type=ec2.SubnetType.PUBLIC).subnet_ids[0]
        )
    ]
)

For aws_cdk.aws_dms.CfnReplicationInstance:

from aws_cdk import aws_dms as dms

rep_instance = dms.CfnReplicationInstance(
    self,
    "explicit_public",
    replication_instance_class="dms.t2.micro",
    allocated_storage=5,
    publicly_accessible=True, # Sensitive
    replication_subnet_group_identifier=subnet_group.replication_subnet_group_identifier,
    vpc_security_group_ids=[vpc.vpc_default_security_group]
)

For aws_cdk.aws_rds.CfnDBInstance:

from aws_cdk import aws_rds as rds
from aws_cdk import aws_ec2 as ec2

rds_subnet_group_public = rds.CfnDBSubnetGroup(
    self,
    "public_subnet",
    db_subnet_group_description="Subnets",
    subnet_ids=vpc.select_subnets(
        subnet_type=ec2.SubnetType.PUBLIC
    ).subnet_ids
)

rds.CfnDBInstance(
    self,
    "public-public-subnet",
    engine="postgres",
    master_username="foobar",
    master_user_password="12345678",
    db_instance_class="db.r5.large",
    allocated_storage="200",
    iops=1000,
    db_subnet_group_name=rds_subnet_group_public.ref,
    publicly_accessible=True, # Sensitive
    vpc_security_groups=[sg.security_group_id]
)



### Рекомендуемые методы безопасного кодирования

Избегайте публикации облачных сервисов в Интернете, если они не предназначены для публичного доступа, например, на клиентских порталах или сайтах электронной коммерции.

Используйте частные сети (и связанные с ними частные IP-адреса), а также пиринг VPC или другие безопасные коммуникационные туннели для связи с другими облачными компонентами.

Цель состоит в том, чтобы предотвратить перехват компонентом трафика, поступающего через общедоступный IP-адрес. Если облачный ресурс не поддерживает отсутствие общедоступного IP-адреса, назначьте ему общедоступный IP-адрес, но не создавайте прослушиватели для общедоступного IP-адреса.


Соответствующее решение

For aws_cdk.aws_ec2.Instance:

from aws_cdk import aws_ec2 as ec2

ec2.Instance(
    self,
    "vpc_subnet_private",
    instance_type=nano_t2,
    machine_image=ec2.MachineImage.latest_amazon_linux(),
    vpc=vpc,
    vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT)
)

For aws_cdk.aws_ec2.CfnInstance:

from aws_cdk import aws_ec2 as ec2

ec2.CfnInstance(
    self,
    "cfn_private",
    instance_type="t2.micro",
    image_id="ami-0ea0f26a6d50850c5",
    network_interfaces=[
        ec2.CfnInstance.NetworkInterfaceProperty(
            device_index="0",
            associate_public_ip_address=False, # Compliant
            delete_on_termination=True,
            subnet_id=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT).subnet_ids[0]
        )
    ]
)

For aws_cdk.aws_dms.CfnReplicationInstance:

from aws_cdk import aws_dms as dms

rep_instance = dms.CfnReplicationInstance(
    self,
    "explicit_private",
    replication_instance_class="dms.t2.micro",
    allocated_storage=5,
    publicly_accessible=False,
    replication_subnet_group_identifier=subnet_group.replication_subnet_group_identifier,
    vpc_security_group_ids=[vpc.vpc_default_security_group]
)

For aws_cdk.aws_rds.CfnDBInstance:

from aws_cdk import aws_rds as rds
from aws_cdk import aws_ec2 as ec2

rds_subnet_group_private = rds.CfnDBSubnetGroup(
    self,
    "private_subnet",
    db_subnet_group_description="Subnets",
    subnet_ids=vpc.select_subnets(
        subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT
    ).subnet_ids
)

rds.CfnDBInstance(
    self,
    "private-private-subnet",
    engine="postgres",
    master_username="foobar",
    master_user_password="12345678",
    db_instance_class="db.r5.large",
    allocated_storage="200",
    iops=1000,
    db_subnet_group_name=rds_subnet_group_private.ref,
    publicly_accessible=False,
    vpc_security_groups=[sg.security_group_id]
)

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    AWS Documentation - Amazon EC2 instance IP addressing
    AWS Documentation - Public and private replication instances
    AWS Documentation - VPC Peering
    MITRE, CWE-284 - Improper Access Control
    MITRE, CWE-668 - Exposure of Resource to Wrong Sphere
    OWASP Top 10 2017 Category A5 - Broken Access Control




