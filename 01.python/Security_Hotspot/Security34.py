###### Использование регулярных выражений важно для безопасности.

Точка доступа безопасности
Критический
Устарело

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

Использование регулярных выражений чувствительно к безопасности. В прошлом это приводило к следующим уязвимостям:

     CVE-2017-16021
     CVE-2018-13863

Оценка регулярных выражений по входным строкам потенциально является чрезвычайно ресурсоемкой задачей. Специально созданным регулярным выражениям, таким как (a+)+s, потребуется несколько секунд для вычисления входной строки aaaaaaaaaaaaaaaaaaaaaaaaaaaaabs. Проблема в том, что с каждым дополнительным символом, добавляемым во входные данные, время, необходимое для вычисления регулярного выражения, удваивается. Однако эквивалентное регулярное выражение a+s (без группировки) эффективно оценивается за миллисекунды и линейно масштабируется в зависимости от размера входных данных.

Оценка таких регулярных выражений открывает возможности для атак типа «отказ в обслуживании» (ReDoS) с использованием регулярных выражений. В контексте веб-приложения злоумышленники могут заставить веб-сервер потратить все свои ресурсы на оценку регулярных выражений, тем самым делая службу недоступной для подлинных пользователей.

Это правило помечает любое выполнение жестко закодированного регулярного выражения, которое содержит не менее 3 символов и не менее двух экземпляров любого из следующих символов: *+{.

Пример: (а+)*
Исключения

Некоторые регулярные выражения в крайнем случае не вызовут проблем, даже если они могут быть уязвимыми. Например: (а|аа)+, (а|а?)+.

Хорошей идеей будет проверить регулярное выражение, имеет ли оно одинаковый шаблон по обе стороны от знака «|».
Устарело

Это правило устарело; вместо этого используйте S2631.


###### Спросите себя, есть ли

     выполненное регулярное выражение является чувствительным, и пользователь может предоставить строку, которая будет анализироваться с помощью этого регулярного выражения.
     Производительность вашего механизма регулярных выражений снижается из-за специально созданных входных данных и регулярных выражений.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

Django

from django.core.validators import RegexValidator
from django.urls import re_path

RegexValidator('(a*)*b')  # Sensitive

def define_http_endpoint(view):
    re_path(r'^(a*)*b/$', view)  # Sensitive

re module

import re
from re import compile, match, search, fullmatch, split, findall, finditer, sub, subn


input = 'input string'
replacement = 'replacement'

re.compile('(a*)*b')  # Sensitive
re.match('(a*)*b', input)  # Sensitive
re.search('(a*)*b', input)  # Sensitive
re.fullmatch('(a*)*b', input)  # Sensitive
re.split('(a*)*b', input)  # Sensitive
re.findall('(a*)*b', input)  # Sensitive
re.finditer('(a*)*b',input)  # Sensitive
re.sub('(a*)*b', replacement, input)  # Sensitive
re.subn('(a*)*b', replacement, input)  # Sensitive

regex module

import regex
from regex import compile, match, search, fullmatch, split, findall, finditer, sub, subn, subf, subfn, splititer

input = 'input string'
replacement = 'replacement'

regex.subf('(a*)*b', replacement, input)  # Sensitive
regex.subfn('(a*)*b', replacement, input)  # Sensitive
regex.splititer('(a*)*b', input)  # Sensitive

regex.compile('(a*)*b')  # Sensitive
regex.match('(a*)*b', input)  # Sensitive
regex.search('(a*)*b', input)  # Sensitive
regex.fullmatch('(a*)*b', input)  # Sensitive
regex.split('(a*)*b', input)  # Sensitive
regex.findall('(a*)*b', input)  # Sensitive
regex.finditer('(a*)*b',input)  # Sensitive
regex.sub('(a*)*b', replacement, input)  # Sensitive
regex.subn('(a*)*b', replacement, input)  # Sensitive



### Рекомендуемые методы безопасного кодирования

Проверьте, есть ли в вашей системе регулярных выражений (алгоритме, выполняющем регулярное выражение) какие-либо известные уязвимости. Найдите отчеты об уязвимостях, в которых упоминается тот движок, который вы используете.

Если возможно, используйте библиотеку, которая не уязвима для атак Redos, например Google Re2.

Помните также, что атака ReDos возможна, если выполняется предоставленное пользователем регулярное выражение. Это правило не обнаружит такого рода внедрение.
Видеть

     Топ-10 OWASP 2017 г. Категория A1 – Инъекции
     MITRE, CWE-624 — ошибка исполняемого регулярного выражения
     Отказ в обслуживании с помощью регулярных выражений OWASP — ReDoS