###### Использование незашифрованных тем в социальных сетях важно для безопасности.
'''
Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Amazon Simple Notification Service (SNS) — это управляемая служба обмена сообщениями для связи между приложениями (A2A) и между приложениями (A2P). Темы SNS позволяют системам издателей рассылать сообщения большому количеству систем подписчиков. Amazon SNS позволяет шифровать сообщения при их получении. В случае, если злоумышленники получают физический доступ к носителю данных или иным образом сливают сообщение, они не могут получить доступ к данным.


###### Спросите себя, есть ли

     Тема содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_sns.Topic:'''

from aws_cdk import (
    aws_sns as sns
)

class TopicStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        sns.Topic( # Sensitive, unencrypted by default
            self,
            "example"
        )

# For aws_cdk.aws_sns.CfnTopic:

from aws_cdk import (
    aws_sns as sns
)

class TopicStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        sns.CfnTopic( # Sensitive, unencrypted by default
            self,
            "example"
        )



### Рекомендуемые методы безопасного кодирования
'''
Рекомендуется шифровать темы в социальных сетях, содержащие конфиденциальную информацию. Шифрование и дешифрование выполняются SNS прозрачно, поэтому никаких дополнительных изменений в приложении не требуется.
Соответствующее решение


For aws_cdk.aws_sns.Topic:'''

from aws_cdk import (
    aws_sns as sns
)

class TopicStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        my_key = kms.Key(self, "key")
        sns.Topic(
            self,
            "example",
            master_key=my_key
        )

# For aws_cdk.aws_sns.CfnTopic:

from aws_cdk import (
    aws_sns as sns
)

class TopicStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        my_key = kms.Key(self, "key")
        sns.CfnTopic(
            self,
            "example",
            kms_master_key_id=my_key.key_id
        )
'''
See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    AWS Documentation - Encryption at rest
    Encrypting messages published to Amazon SNS with AWS KMS
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data'''



