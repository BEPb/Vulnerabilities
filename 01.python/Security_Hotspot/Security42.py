###### Использование незашифрованных очередей SQS важно для безопасности.
'''
Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Amazon Simple Queue Service (SQS) — это управляемая служба очередей сообщений для связи между приложениями (A2A). Amazon SQS может хранить сообщения в зашифрованном виде сразу после их получения. В случае, если злоумышленники получают физический доступ к носителю данных или иным образом сливают сообщение из файловой системы, например, через уязвимость в службе, они не смогут получить доступ к данным.

###### Спросите себя, есть ли

     Очередь содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_sqs.Queue:'''

from aws_cdk import (
    aws_sqs as sqs
)

class QueueStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        sqs.Queue( # Sensitive, unencrypted by default
            self,
            "example"
        )

# For aws_cdk.aws_sqs.CfnQueue:

from aws_cdk import (
    aws_sqs as sqs
)

class CfnQueueStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        sqs.CfnQueue( # Sensitive, unencrypted by default
            self,
            "example"
        )



### Рекомендуемые методы безопасного кодирования
'''
Рекомендуется шифровать очереди SQS, содержащие конфиденциальную информацию. Шифрование и дешифрование прозрачно выполняются SQS, поэтому дальнейшие изменения приложения не требуются.
Соответствующее решение

For aws_cdk.aws_sqs.Queue:'''

from aws_cdk import (
    aws_sqs as sqs
)

class QueueStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        sqs.Queue(
            self,
            "example",
            encryption=sqs.QueueEncryption.KMS_MANAGED
        )

# For aws_cdk.aws_sqs.CfnQueue:

from aws_cdk import (
    aws_sqs as sqs
)

class CfnQueueStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        my_key = kms.Key(self, "key")
        sqs.CfnQueue(
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
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data'''




