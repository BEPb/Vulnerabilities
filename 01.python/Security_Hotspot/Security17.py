###### Форматирование SQL-запросов чувствительно к безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/выпуск: 20 мин.

Форматированные SQL-запросы могут быть сложны в обслуживании и отладке, а также могут увеличить риск внедрения SQL-кода при объединении в запрос ненадежных значений. Однако это правило не обнаруживает SQL-инъекции (в отличие от правила S3649), его цель — только выделить сложные/форматированные запросы.


###### Спросите себя, есть ли

     Некоторые части запроса берутся из ненадежных значений (например, вводимых пользователем данных).
     Запрос повторяется/дублируется в других частях кода.
     Приложение должно поддерживать разные типы реляционных баз данных.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

from django.db import models
from django.db import connection
from django.db import connections
from django.db.models.expressions import RawSQL

value = input()


class MyUser(models.Model):
    name = models.CharField(max_length=200)


def query_my_user(request, params, value):
    with connection.cursor() as cursor:
        cursor.execute("{0}".format(value))  # Sensitive

    # https://docs.djangoproject.com/en/2.1/ref/models/expressions/#raw-sql-expressions

    RawSQL("select col from %s where mycol = %s and othercol = " + value, ("test",))  # Sensitive

    # https://docs.djangoproject.com/en/2.1/ref/models/querysets/#extra

    MyUser.objects.extra(
        select={
            'mycol':  "select col from sometable here mycol = %s and othercol = " + value}, # Sensitive
           select_params=(someparam,),
        },
    )







### Рекомендуемые методы безопасного кодирования

     Используйте параметризованные запросы, подготовленные операторы или хранимые процедуры и привязывайте переменные к параметрам запроса SQL.
     Рассмотрите возможность использования фреймворков ORM, если вам необходим абстрактный уровень для доступа к данным.

Соответствующее решение

cursor = connection.cursor(prepared=True)
sql_insert_query = """ select col from sometable here mycol = %s and othercol = %s """

select_tuple = (1, value)

cursor.execute(sql_insert_query, select_tuple) # Compliant, the query is parameterized
connection.commit()

See

    OWASP Top 10 2021 Category A3 - Injection
    OWASP Top 10 2017 Category A1 - Injection
    MITRE, CWE-20 - Improper Input Validation
    MITRE, CWE-89 - Improper Neutralization of Special Elements used in an SQL Command
    SANS Top 25 - Insecure Interaction Between Components
    Derived from FindSecBugs rules Potential SQL/JPQL Injection (JPA), Potential SQL/JDOQL Injection (JDO), Potential SQL/HQL Injection (Hibernate)










