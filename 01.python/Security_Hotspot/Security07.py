###### Создание файлов cookie без флага «безопасно» является чувствительным к безопасности.

'''Точка доступа безопасности
Незначительный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

Если файл cookie защищен атрибутом Secure, для которого установлено значение true, он не будет отправлен браузером по незашифрованному HTTP-запросу и, следовательно, не сможет быть обнаружен посторонним лицом во время атаки «человек посередине».

###### Спросите себя, есть ли

     например, файл cookie представляет собой сеансовый файл cookie, не предназначенный для отправки по каналу связи, отличному от HTTPS.
     не уверен, содержит ли сайт смешанный контент или нет (т.е. везде HTTPS или нет)

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

Flask
'''
from flask import Response

@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value') # Sensitive
    return response


### Рекомендуемые методы безопасного кодирования
'''
     Рекомендуется везде использовать HTTP, поэтому установка флага безопасности в значение true должна быть поведением по умолчанию при создании файлов cookie.
     Установите для флага безопасности значение true для файлов cookie сеанса.

Соответствующее решение

Flask'''

from flask import Response

@app.route('/')
def index():
    response = Response()
    response.set_cookie('key', 'value', secure=True) # Compliant
    return response

'''See

    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-311 - Missing Encryption of Sensitive Data
    MITRE, CWE-315 - Cleartext Storage of Sensitive Information in a Cookie
    MITRE, CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    SANS Top 25 - Porous Defenses
'''





