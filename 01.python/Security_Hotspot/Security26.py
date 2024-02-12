###### Установка свободных прав доступа к файлам POSIX важна для безопасности.
'''
Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

В Unix класс «другие» относится ко всем пользователям, кроме владельца файла и членов группы, назначенной этому файлу.

Предоставление разрешений этой группе может привести к непреднамеренному доступу к файлам.


###### Спросите себя, есть ли

     Приложение предназначено для работы в многопользовательской среде.
     Соответствующие файлы и каталоги могут содержать конфиденциальную информацию.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For os.umask:'''

os.umask(0)  # Sensitive

# For os.chmod, os.lchmod, and os.fchmod:

os.chmod("/tmp/fs", stat.S_IRWXO)   # Sensitive
os.lchmod("/tmp/fs", stat.S_IRWXO)  # Sensitive
os.fchmod(fd, stat.S_IRWXO)         # Sensitive






### Рекомендуемые методы безопасного кодирования
'''
Файлам и каталогам следует назначать максимально строгие разрешения.
Соответствующее решение
For os.umask:'''

os.umask(0o777)

# For os.chmod, os.lchmod, and os.fchmod:

os.chmod("/tmp/fs", stat.S_IRWXU)
os.lchmod("/tmp/fs", stat.S_IRWXU)
os.fchmod(fd, stat.S_IRWXU)
'''
See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2017 Category A5 - Broken Access Control
    OWASP File Permission
    MITRE, CWE-732 - Incorrect Permission Assignment for Critical Resource
    MITRE, CWE-266 - Incorrect Privilege Assignment
    SANS Top 25 - Porous Defenses'''
