###### Создание файлов cookie без флага «HttpOnly» является чувствительным к безопасности.

Точка доступа безопасности
Незначительный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Если файл cookie настроен с атрибутом HttpOnly, установленным в значение true, браузер гарантирует, что ни один клиентский сценарий не сможет его прочитать. В большинстве случаев при создании файла cookie значение HttpOnly по умолчанию равно false, и разработчик должен решить, может ли содержимое файла cookie быть прочитано клиентским сценарием. Поскольку большинство атак с использованием межсайтового скриптинга (XSS) направлены на кражу файлов cookie сеанса, атрибут HttpOnly может помочь уменьшить их воздействие, поскольку будет невозможно использовать уязвимость XSS для кражи файлов cookie сеанса.

###### Спросите себя, есть ли

     файл cookie чувствителен и используется для аутентификации пользователя, например сеансовый файл cookie
     Атрибут HttpOnly обеспечивает дополнительную защиту (например, это не касается файла cookie XSRF-TOKEN/токена CSRF)

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

Flask:

from flask import Response

@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value') # Sensitive
    return response



### Рекомендуемые методы безопасного кодирования

     По умолчанию флаг HttpOnly должен быть установлен в значение true для большинства файлов cookie и является обязательным для файлов cookie сеанса или конфиденциальной безопасности.

Соответствующее решение

Flask:

from flask import Response

@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value', httponly=True) # Compliant
    return response

See

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP HttpOnly
    OWASP Top 10 2017 Category A7 - Cross-Site Scripting (XSS)
    MITRE, CWE-1004 - Sensitive Cookie Without 'HttpOnly' Flag
    SANS Top 25 - Insecure Interaction Between Components
    Derived from FindSecBugs rule HTTPONLY_COOKIE





