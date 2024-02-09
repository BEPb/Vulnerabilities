###### Разрешение десериализации объектов LDAP важно для безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКьюб (Java)
     Постоянно/проблема: 2 мин.

JNDI поддерживает десериализацию объектов из каталогов LDAP, что может привести к удаленному выполнению кода.

Это правило вызывает проблему, когда поисковый запрос LDAP выполняется с элементами управления SearchControls, настроенными на разрешение десериализации.


###### Спросите себя, есть ли

     Приложение подключается к недоверенному каталогу LDAP.
     Объекты, управляемые пользователем, могут храниться в каталоге LDAP.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

DirContext ctx = new InitialDirContext();
// ...
ctx.search(query, filter,
        new SearchControls(scope, countLimit, timeLimit, attributes,
            true, // Noncompliant; allows deserialization
            deref));





###### Рекомендуемые методы безопасного кодирования

Рекомендуется отключить десериализацию объектов LDAP.


Compliant Solution

DirContext ctx = new InitialDirContext();
// ...
ctx.search(query, filter,
        new SearchControls(scope, countLimit, timeLimit, attributes,
            false, // Compliant
            deref));

See

    OWASP Top 10 2021 Category A8 - Software and Data Integrity Failures
    MITRE, CWE-502 - Deserialization of Untrusted Data
    OWASP Top 10 2017 Category A8 - Insecure Deserialization
    BlackHat presentation
    Derived from FindSecBugs rule LDAP_ENTRY_POISONING


