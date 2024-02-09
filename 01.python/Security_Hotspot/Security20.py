###### Наличие разрешительной политики совместного использования ресурсов между источниками является чувствительным к безопасности.

Точка доступа безопасности
Незначительный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

Наличие разрешительной политики совместного использования ресурсов между источниками является чувствительным к безопасности. В прошлом это приводило к следующим уязвимостям:

     CVE-2018-0269
     CVE-2017-14460

Политика одинакового происхождения в браузерах по умолчанию и по соображениям безопасности запрещает интерфейсу Javascript выполнять HTTP-запрос между источниками к ресурсу, который имеет другое происхождение (домен, протокол или порт) от его собственного. Запрошенная цель может добавлять в ответ дополнительные HTTP-заголовки, называемые CORS, которые действуют как директивы для браузера и изменяют политику управления доступом/ослабляют ту же политику происхождения.


###### Спросите себя, есть ли

     Вы не доверяете указанному источнику, например: Access-Control-Allow-Origin: untrustedwebsite.com.
     Политика контроля доступа полностью отключена: Access-Control-Allow-Origin: *
     Ваша политика контроля доступа динамически определяется пользователем, например, исходным заголовком.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

Django:

CORS_ORIGIN_ALLOW_ALL = True # Sensitive

Flask:

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "send_wildcard": "True"}}) # Sensitive

User-controlled origin:

origin = request.headers['ORIGIN']
resp = Response()
resp.headers['Access-Control-Allow-Origin'] = origin # Sensitive


### Рекомендуемые методы безопасного кодирования

     Заголовок Access-Control-Allow-Origin следует устанавливать только для доверенного источника и для определенных ресурсов.
     Разрешить только выбранные доверенные домены в заголовке Access-Control-Allow-Origin. Предпочитайте внесение доменов в белый список, а не внесение в черный список или разрешение любого домена (не используйте подстановочный знак * и не возвращайте вслепую содержимое заголовка Origin без каких-либо проверок).

Соответствующее решение

Django:

CORS_ORIGIN_ALLOW_ALL = False # Compliant

Flask:

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "send_wildcard": "False"}}) # Compliant

User-controlled origin validated with an allow-list:

origin = request.headers['ORIGIN']
resp = Response()
if origin in TRUSTED_ORIGINS:
   resp.headers['Access-Control-Allow-Origin'] = origin

See

Топ-10 OWASP 2021 г., категория A5 — неправильная конфигурация безопасности
     Топ-10 OWASP 2021 г., Категория A7 — Сбои идентификации и аутентификации
     Developer.mozilla.org — CORS
     Developer.mozilla.org — та же политика происхождения
     Топ-10 OWASP 2017 г., категория A6 — неправильная конфигурация безопасности
     Памятка по безопасности OWASP HTML5 — совместное использование ресурсов между источниками
     MITRE, CWE-346 — Ошибка проверки происхождения
     MITRE, CWE-942 — слишком разрешительный междоменный белый список
     SANS Top 25 — пористая защита

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    OWASP Top 10 2021 Category A7 - Identification and Authentication Failures
    developer.mozilla.org - CORS
    developer.mozilla.org - Same origin policy
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    OWASP HTML5 Security Cheat Sheet - Cross Origin Resource Sharing
    MITRE, CWE-346 - Origin Validation Error
    MITRE, CWE-942 - Overly Permissive Cross-domain Whitelist
    SANS Top 25 - Porous Defenses


