###### Доставка кода в производство с активированными функциями отладки важна для безопасности.

Точка доступа безопасности
Незначительный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 1 минута

Доставка кода в рабочую среду с активированными функциями отладки важна с точки зрения безопасности. В прошлом это приводило к следующим уязвимостям:

     CVE-2018-1999007
     CVE-2015-5306
     CVE-2013-2006

Функции отладки приложения позволяют разработчикам легче находить ошибки и, таким образом, облегчают работу злоумышленников. Часто это дает доступ к подробной информации как о системе, на которой работает приложение, так и о пользователях.

###### Спросите себя, есть ли

     Код или конфигурация, обеспечивающие функции отладки приложения, развертываются на рабочих серверах или распространяются среди конечных пользователей.
     Приложение запускается по умолчанию с активированными функциями отладки.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

from django.conf import settings

settings.configure(DEBUG=True)  # Sensitive when set to True
settings.configure(DEBUG_PROPAGATE_EXCEPTIONS=True)  # Sensitive when set to True

def custom_config(config):
    settings.configure(default_settings=config, DEBUG=True)  # Sensitive

Django’s "settings.py" or "global_settings.py" configuration file:

# NOTE: The following code raises issues only if the file is named "settings.py" or "global_settings.py". This is the default
# name of Django configuration file

DEBUG = True  # Sensitive
DEBUG_PROPAGATE_EXCEPTIONS = True  # Sensitive

### Рекомендуемые методы безопасного кодирования

Не включайте функции отладки на рабочих серверах или в приложениях, распространяемых конечным пользователям.
Видеть

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    MITRE, CWE-489 - Active Debug Code
    MITRE, CWE-215 - Information Exposure Through Debug Information







