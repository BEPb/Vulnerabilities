###### питон: S6319
'''Использование незашифрованных экземпляров блокнотов SageMaker важно для безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Amazon SageMaker — это управляемый сервис машинного обучения в размещенной рабочей среде. Для обучения моделей машинного обучения экземпляры SageMaker могут обрабатывать потенциально конфиденциальные данные, например личную информацию, которую не следует хранить в незашифрованном виде. В случае физического доступа злоумышленников к носителю данных они не смогут расшифровать зашифрованные данные.



###### Спросите себя, есть ли

     Экземпляр содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_sagemaker.CfnNotebookInstance:'''

from aws_cdk import (
    aws_sagemaker as sagemaker
)

class CfnSagemakerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        sagemaker.CfnNotebookInstance(
            self, "Sensitive",
            instance_type="instanceType",
            role_arn="roleArn"
        )  # Sensitive, no KMS key is set by default; thus, encryption is disabled




### Рекомендуемые методы безопасного кодирования

'''Рекомендуется шифровать экземпляры блокнотов SageMaker, содержащие конфиденциальную информацию. Шифрование и дешифрование выполняются SageMaker прозрачно, поэтому никаких дополнительных изменений в приложении не требуется.
Соответствующее решение
For aws_cdk.aws_sagemaker.CfnNotebookInstance:'''

from aws_cdk import (
    aws_sagemaker as sagemaker,
    aws_kms as kms
)

class CfnSagemakerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        my_key = kms.Key(self, "Key")
        sagemaker.CfnNotebookInstance(
            self, "Compliant",
            instance_type="instanceType",
            role_arn="roleArn",
            kms_key_id=my_key.key_id
        )
'''
See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    Protect Data at Rest Using Encryption
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data'''



