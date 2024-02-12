###### Использование незашифрованных доменов OpenSearch очень важно для безопасности.

'''Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Amazon OpenSearch Service — это управляемый сервис для размещения экземпляров OpenSearch. Он заменяет службу Elasticsearch, которая устарела.

Чтобы защитить данные домена (кластера) в случае несанкционированного доступа, OpenSearch обеспечивает шифрование хранящихся данных, если используется механизм OpenSearch (любая версия) или Elasticsearch версии 5.1 или выше. Включение шифрования неактивных данных поможет защитить:

     индексы
     журналы
     файлы подкачки
     данные в каталоге приложения
     автоматические снимки

Таким образом, злоумышленники не смогут получить доступ к данным, если они получат физический доступ к носителю данных.

###### Спросите себя, есть ли

     База данных содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_opensearchservice.Domain:'''

from aws_cdk.aws_opensearchservice import Domain, EngineVersion

class DomainStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        Domain(self, "Sensitive",
            version=EngineVersion.OPENSEARCH_1_3
        ) # Sensitive, encryption is disabled by default

# For aws_cdk.aws_opensearchservice.CfnDomain:

from aws_cdk.aws_opensearchservice import CfnDomain

class CfnDomainStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        CfnDomain(self, "Sensitive") # Sensitive, encryption is disabled by default




### Рекомендуемые методы безопасного кодирования
'''
Рекомендуется шифровать домены OpenSearch, содержащие конфиденциальную информацию.

OpenSearch прозрачно осуществляет шифрование и дешифрование, поэтому дальнейшие изменения приложения не требуются.
Соответствующее решение

For aws_cdk.aws_opensearchservice.Domain:'''

from aws_cdk.aws_opensearchservice import Domain, EncryptionAtRestOptions, EngineVersion

class DomainStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        Domain(self, "Compliant",
            version=EngineVersion.OPENSEARCH_1_3,
            encryption_at_rest=EncryptionAtRestOptions(
                enabled=True
            )
        )

# For aws_cdk.aws_opensearchservice.CfnDomain:

from aws_cdk.aws_opensearchservice import CfnDomain

class CfnDomainStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        CfnDomain(self, "Compliant",
            encryption_at_rest_options=CfnDomain.EncryptionAtRestOptionsProperty(
                enabled=True
            )
        )
'''
See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    AWS Documentation - Encryption of data at rest for Amazon OpenSearch Service
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data'''



