###### Использование незашифрованных ресурсов базы данных RDS чувствительно к безопасности.

'''Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Использование незашифрованных ресурсов БД RDS подвергает данные несанкционированному доступу к базовому хранилищу.
Сюда входят данные базы данных, журналы, автоматическое резервное копирование, реплики чтения, снимки и метаданные кластера.

Такая ситуация может возникнуть по разным сценариям, например:

     злонамеренный инсайдер, работающий в облачном провайдере, получает физический доступ к устройству хранения данных и похищает данные.
     неизвестные злоумышленники проникают в логическую инфраструктуру и системы облачного провайдера с целью вымогательства.

Неактивное шифрование, управляемое AWS, снижает этот риск с помощью простого переключения.


###### Спросите себя, есть ли

     База данных содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_rds.DatabaseCluster and aws_cdk.aws_rds.DatabaseInstance:'''

from aws_cdk import (
    aws_rds as rds
)

class DatabaseStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        rds.DatabaseCluster( # Sensitive, unencrypted by default
            self,
            "example"
        )

# For aws_cdk.aws_rds.CfnDBCluster and aws_cdk.aws_rds.CfnDBInstance:

from aws_cdk import (
    aws_rds as rds
)

class DatabaseStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        rds.CfnDBCluster( # Sensitive, unencrypted by default
            self,
            "example"
        )





### Рекомендуемые методы безопасного кодирования

'''Рекомендуется включать шифрование неактивных данных для любого ресурса БД RDS, независимо от механизма.
В любом случае дальнейшее обслуживание не требуется, поскольку шифрование хранящихся данных полностью контролируется AWS.
Соответствующее решение

For aws_cdk.aws_rds.DatabaseCluster and aws_cdk.aws_rds.DatabaseInstance:'''

from aws_cdk import (
    aws_rds as rds
)

class DatabaseStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        rds.DatabaseCluster(
            self,
            "example",
            storage_encrypted=True
        )

# For aws_cdk.aws_rds.CfnDBCluster and aws_cdk.aws_rds.CfnDBInstance:

from aws_cdk import (
    aws_rds as rds
)

class DatabaseStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        rds.CfnDBCluster(
            self,
            "example",
            storage_encrypted=True
        )

'''See

    AWS Documentation - Encrypting Amazon RDS resources
    MITRE, CWE-311 - Missing Encryption of Sensitive Data'''


