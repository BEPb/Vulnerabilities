###### Разрешение общедоступных списков управления доступом или политик в корзине S3 важно для безопасности.

Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

По умолчанию корзины S3 являются частными, то есть только владелец корзины может получить к ней доступ.

Этот контроль доступа можно ослабить с помощью списков ACL или политик.

Чтобы запретить установку разрешительных политик в сегменте S3, можно включить следующие логические параметры:

     block_public_acls: блокировать или запретить общедоступные списки ACL, которые будут установлены для корзины S3.
     ignore_public_acls: учитывать или нет существующие общедоступные списки ACL, установленные для корзины S3.
     block_public_policy: блокировать или нет общедоступные политики, которые будут установлены для корзины S3.
     Ограничить_public_buckets: ограничить или запретить доступ к конечным точкам S3 общедоступных политик для участников в учетной записи владельца корзины.

Другой атрибут BlockPublicAccess.BLOCK_ACLS включает только Block_public_acls и ignore_public_acls. Государственная политика по-прежнему может влиять на сегмент S3.

Однако все эти параметры можно включить, установив для свойства Block_public_access корзины S3 значение BlockPublicAccess.BLOCK_ALL.

###### Спросите себя, есть ли

     В корзине S3 хранятся конфиденциальные данные.
     Корзина S3 не используется для хранения статических ресурсов веб-сайтов (изображений, CSS…​).
     Многие пользователи имеют разрешение устанавливать ACL или политику для корзины S3.
     Для этих настроек еще не установлено значение true на уровне учетной записи.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

По умолчанию, если он не установлен, block_public_access полностью деактивирован (ничего не блокируется):


bucket = s3.Bucket(self,
    "bucket"        # Sensitive
)

This block_public_access allows public ACL to be set:

bucket = s3.Bucket(self,
    "bucket",
    block_public_access=s3.BlockPublicAccess(
        block_public_acls=False,       # Sensitive
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
)

The attribute BLOCK_ACLS only blocks and ignores public ACLs:

bucket = s3.Bucket(self,
    "bucket",
    block_public_access=s3.BlockPublicAccess.BLOCK_ACLS     # Sensitive
)




### Рекомендуемые методы безопасного кодирования

Рекомендуется настроить:

     block_public_acls в True, чтобы заблокировать новые попытки установить общедоступные списки ACL.
     ignore_public_acls в True, чтобы заблокировать существующие общедоступные списки ACL.
     Для параметра block_public_policy установите значение True, чтобы заблокировать новые попытки установить публичные политики.
     Ограничить_public_buckets значением True, чтобы ограничить существующие общедоступные политики.

Соответствующее решение

Этот блок_public_access блокирует общедоступные списки управления доступом и политики, игнорирует существующие общедоступные списки контроля доступа и ограничивает существующие общедоступные политики:

bucket = s3.Bucket(self,
    "bucket",
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL # Compliant
)

A similar configuration to the one above can obtained by setting all parameters of the block_public_access

bucket = s3.Bucket(self, "bucket",
    block_public_access=s3.BlockPublicAccess(       # Compliant
        block_public_acls=True,
        ignore_public_acls=True,
        block_public_policy=True,
        restrict_public_buckets=True
    )
)

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    AWS Documentation - Blocking public access to your Amazon S3 storage
    MITRE, CWE-284 - Improper Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control
    AWS CDK version 2 - Bucket



