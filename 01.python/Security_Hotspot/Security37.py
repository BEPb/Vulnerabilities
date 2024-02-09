###### Использование незашифрованных файловых систем EFS важно для безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Amazon Elastic File System (EFS) — это бессерверная файловая система, не требующая выделения ресурсов или управления хранилищем. Сохраненные файлы могут быть автоматически зашифрованы службой. В случае, если злоумышленники получают физический доступ к носителю данных или иным образом сливают сообщение, они не могут получить доступ к данным.

###### Спросите себя, есть ли

     Файловая система содержит конфиденциальные данные, утечка которых может причинить вред.
     К службе хранения данных в зашифрованном виде предъявляются требования соответствия.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_efs.FileSystem and aws_cdk.aws_efs.CfnFileSystem:

from aws_cdk import (
    aws_efs as efs
)

efs.FileSystem(
    self,
    "example",
    encrypted=False  # Sensitive
)




### Рекомендуемые методы безопасного кодирования

Рекомендуется шифровать файловые системы EFS, содержащие конфиденциальную информацию. Шифрование и дешифрование прозрачно выполняются EFS, поэтому дальнейшие изменения приложения не требуются.
Соответствующее решение


For aws_cdk.aws_efs.FileSystem and aws_cdk.aws_efs.CfnFileSystem:

from aws_cdk import (
    aws_efs as efs
)

efs.FileSystem(
    self,
    "example",
    encrypted=True
)

See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    AWS Documentation - Data encryption in Amazon EFS
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-311 - Missing Encryption of Sensitive Data


