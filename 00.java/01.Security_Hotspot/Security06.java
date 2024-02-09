###### Разрешение неаутентифицированным пользователям использовать ключи в Android KeyStore важно с точки зрения безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКьюб (Java)
     Постоянно/проблема: 5 минут

Android KeyStore — это безопасный контейнер для хранения материалов ключей, в частности он предотвращает извлечение материалов ключей, т. е. когда процесс приложения скомпрометирован, злоумышленник не может извлечь ключи, но все равно может их использовать. Можно включить функцию безопасности Android, аутентификацию пользователя, чтобы ограничить использование ключей только аутентифицированными пользователями. Экран блокировки необходимо разблокировать с помощью определенных учетных данных (шаблон/PIN-код/пароль, биометрические данные).


###### спроси себя, есть ли

     Приложение требует запретить использование ключей в случае компрометации процесса приложения.
     Ключевой материал используется в контексте высокочувствительного приложения, такого как мобильное приложение для электронного банкинга.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример несовместимого кода

Any user can use the key:

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

KeyGenParameterSpec builder = new KeyGenParameterSpec.Builder("test_secret_key_noncompliant", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) // Noncompliant
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build();

keyGenerator.init(builder);



######## Рекомендуемые методы безопасного кодирования

Рекомендуется включить аутентификацию пользователя (установив для setUserAuthenticationRequired значение true во время генерации ключа), чтобы использовать ключи в течение ограниченного периода времени (путем установки соответствующих значений для setUserAuthenticationValidityDurationSeconds), после чего пользователь должен повторно пройти аутентификацию.
Соответствующее решение

Использование ключа ограничено аутентифицированными пользователями (в течение периода времени, определенного в 60 секунд):

KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

KeyGenParameterSpec builder = new KeyGenParameterSpec.Builder("test_secret_key", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters (60, KeyProperties.AUTH_DEVICE_CREDENTIAL)
    .build();

keyGenerator.init(builder)

See

    OWASP Top 10 2021 Category A4 - Insecure Design
    developer.android.com - Android keystore system
    developer.android.com - Require user authentication for key use
    Mobile AppSec Verification Standard - Authentication and Session Management Requirements
    OWASP Mobile Top 10 2016 Category M4 - Insecure Authentication
    MITRE, CWE-522 - Insufficiently Protected Credentials







