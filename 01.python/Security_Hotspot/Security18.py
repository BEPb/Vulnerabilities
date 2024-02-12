###### питон: S6265
'''Предоставление доступа к корзинам S3 всем или прошедшим проверку подлинности пользователям важно с точки зрения безопасности.

Точка доступа безопасности
Блокатор

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

Предопределенные разрешения, также известные как стандартные списки ACL, — это простой способ предоставить большие привилегии заранее определенным группам или пользователям.

Следующие стандартные списки ACL чувствительны к безопасности:

     PUBLIC_READ, PUBLIC_READ_WRITE предоставляют соответственно права «чтения» и «чтения и записи» всем в мире (группа AllUsers).
     AUTHENTICATED_READ предоставляет право чтения всем аутентифицированным пользователям (группа AuthenticatedUsers).


###### AСпросите себя, есть ли

     В корзине S3 хранятся конфиденциальные данные.
     Корзина S3 не используется для хранения статических ресурсов веб-сайтов (изображений, CSS…​).

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

All users (ie: anyone in the world authenticated or not) have read and write permissions with the PUBLIC_READ_WRITE access control:'''

bucket = s3.Bucket(self, "bucket",
    access_control=s3.BucketAccessControl.PUBLIC_READ_WRITE     # Sensitive
)

s3deploy.BucketDeployment(self, "DeployWebsite",
    access_control=s3.BucketAccessControl.PUBLIC_READ_WRITE     # Sensitive
)





### Рекомендуемые методы безопасного кодирования

'''Рекомендуется реализовать политику наименьших привилегий, то есть предоставлять необходимые разрешения только пользователям для выполнения их необходимых задач. В контексте стандартного ACL установите для него значение PRIVATE (по умолчанию), а если требуется большая степень детализации, используйте соответствующую политику S3.
Соответствующее решение

При использовании ЧАСТНОГО контроля доступа (по умолчанию) только владелец корзины имеет разрешения на чтение/запись для корзин и их ACL.'''

bucket = s3.Bucket(self, "bucket",
    access_control=s3.BucketAccessControl.PRIVATE       # Compliant
)

# Another example
s3deploy.BucketDeployment(self, "DeployWebsite",
    access_control=s3.BucketAccessControl.PRIVATE       # Compliant
)


'''Видеть

     Топ-10 OWASP 2021 г., категория A1 — нарушенный контроль доступа
     Документация AWS — обзор списка контроля доступа (ACL) (стандартные ACL)
     Документация AWS. Управление доступом к корзине с помощью пользовательских политик
     MITRE, CWE-732 — неправильное назначение разрешений для критического ресурса
     MITRE, CWE-284 — Неправильный контроль доступа
     Топ-10 OWASP 2017 г., категория A5 — нарушенный контроль доступа
     AWS CDK версии 2 — сегмент классов (конструкция)

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    AWS Documentation - Access control list (ACL) overview (canned ACLs)
    AWS Documentation - Controlling access to a bucket with user policies
    MITRE, CWE-732 - Incorrect Permission Assignment for Critical Resource
    MITRE, CWE-284 - Improper Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control
    AWS CDK version 2 - Class Bucket (construct)'''









