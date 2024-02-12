###### Использование незашифрованных томов EBS чувствительно к безопасности.

'''Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

Amazon Elastic Block Store (EBS) — это сервис блочного хранилища для Amazon Elastic Compute Cloud (EC2). Тома EBS можно зашифровать, обеспечивая безопасность как хранящихся, так и передаваемых данных между экземпляром и подключенным к нему хранилищем EBS. В случае, если злоумышленники получают физический доступ к носителю данных, они не смогут получить доступ к данным. Шифрование можно включить для определенных томов или для всех новых томов и снимков. Тома, созданные из снимков, наследуют свою конфигурацию шифрования. Том, созданный из зашифрованного снимка, также будет зашифрован по умолчанию.

###### Спросите себя, есть ли

     Диск содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_ec2.Volume:'''

from aws_cdk.aws_ec2 import Volume

class EBSVolumeStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        Volume(self,
            "unencrypted-explicit",
            availability_zone="eu-west-1a",
            size=Size.gibibytes(1),
            encrypted=False  # Sensitive
        )

from aws_cdk.aws_ec2 import Volume

class EBSVolumeStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        Volume(self,
            "unencrypted-implicit",
            availability_zone="eu-west-1a",
            size=Size.gibibytes(1)
        ) # Sensitive as encryption is disabled by default




### Рекомендуемые методы безопасного кодирования

'''Рекомендуется шифровать тома EBS, содержащие конфиденциальную информацию. Шифрование и дешифрование прозрачно выполняются EC2, поэтому дальнейшие изменения приложения не требуются. Вместо включения шифрования для каждого тома также можно включить глобальное шифрование для определенного региона. Хотя создание томов из зашифрованных снимков приведет к их шифрованию, явное включение этого параметра безопасности предотвратит любое неожиданное понижение уровня безопасности в будущем.
Соответствующее решение


For aws_cdk.aws_ec2.Volume:'''

from aws_cdk.aws_ec2 import Volume

class EBSVolumeStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        Volume(self,
            "encrypted-explicit",
            availability_zone="eu-west-1a",
            size=Size.gibibytes(1),
            encrypted=True
        )

'''See

    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    Amazon EBS encryption
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data'''


