###### Политики, разрешающие публичный доступ к ресурсам, чувствительны к безопасности.

'''Точка доступа безопасности
Блокатор

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

Ресурсные политики, предоставляющие доступ всем пользователям, могут привести к утечке информации.

###### Спросите себя, есть ли

     Ресурс AWS хранит или обрабатывает конфиденциальные данные.
     Ресурс AWS спроектирован как частный.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

This policy allows all users, including anonymous ones, to access an S3 bucket:'''

from aws_cdk.aws_iam import PolicyStatement, AnyPrincipal, Effect
from aws_cdk.aws_s3 import Bucket

bucket = Bucket(self, "ExampleBucket")

bucket.add_to_resource_policy(PolicyStatement(
  effect=Effect.ALLOW,
  actions=["s3:*"],
  resources=[bucket.arn_for_objects("*")],
  principals=[AnyPrincipal()] # Sensitive
))

### Рекомендуемые методы безопасного кодирования

'''Рекомендуется реализовать принцип наименьших привилегий, то есть предоставлять необходимые разрешения только пользователям для выполнения их необходимых задач. В контексте политик на основе ресурсов составьте список участников, которым необходим доступ, и предоставьте им только необходимые привилегии.
Соответствующее решение

Эта политика позволяет только авторизованным пользователям:'''


from aws_cdk.aws_iam import PolicyStatement, AccountRootPrincipal, Effect
from aws_cdk.aws_s3 import Bucket

bucket = Bucket(self, "ExampleBucket")

bucket.add_to_resource_policy(PolicyStatement(
  effect=Effect.ALLOW,
  actions=["s3:*"],
  resources=[bucket.arn_for_objects("*")],
  principals=[AccountRootPrincipal()]
))

'''See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    AWS Documentation - Grant least privilege
    MITRE, CWE-732 - Incorrect Permission Assignment for Critical Resource
    MITRE, CWE-284 - Improper Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control'''

