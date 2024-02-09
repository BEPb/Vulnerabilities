###### Использование слабых алгоритмов хеширования чувствительно к безопасности.

Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

Криптографические алгоритмы хеширования, такие как MD2, MD4, MD5, MD6, HAVAL-128, HMAC-MD5, DSA (использующий SHA-1), RIPEMD, RIPEMD-128, RIPEMD-160, HMACRIPEMD160 и SHA-1, больше не считаются безопасными. , потому что возможны коллизии (достаточно небольших вычислительных усилий, чтобы найти два или более разных входных данных, которые создают один и тот же хэш).

###### Спросите себя, есть ли

Хэшированное значение используется в контексте безопасности, например:

     Хранилище паролей пользователя.
     Генерация токена безопасности (используется для подтверждения электронной почты при регистрации на сайте, сброса пароля и т. д.).
     Чтобы вычислить некоторую целостность сообщения.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

import hashlib
m = hashlib.md5() // Sensitive

import hashlib
m = hashlib.sha1() // Sensitive

import md5 // Sensitive and deprecated since Python 2.5; use the hashlib module instead.
m = md5.new()

import sha // Sensitive and deprecated since Python 2.5; use the hashlib module instead.
m = sha.new()



### Рекомендуемые методы безопасного кодирования

Рекомендуется использовать более безопасные альтернативы, такие как SHA-256, SHA-512, SHA-3, а для хеширования паролей даже лучше использовать алгоритмы, которые не вычисляются слишком «быстро», например bcrypt, scrypt, argon2 или pbkdf2, поскольку они замедляют работу. отражать атаки грубой силы.
Соответствующее решение

import hashlib
m = hashlib.sha512() // Compliant

See

    OWASP Top 10 2021 Category A2 - Cryptographic Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    Mobile AppSec Verification Standard - Cryptography Requirements
    OWASP Mobile Top 10 2016 Category M5 - Insufficient Cryptography
    MITRE, CWE-1240 - Use of a Risky Cryptographic Primitive
    SANS Top 25 - Porous Defenses




