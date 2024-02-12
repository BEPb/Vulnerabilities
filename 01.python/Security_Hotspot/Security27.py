###### Процессы сигнализации чувствительны к безопасности
'''
Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

Процессы сигнализации или группы процессов могут серьезно повлиять на стабильность этого приложения или других приложений в той же системе.

Случайная установка неправильного PID или сигнала или разрешение ненадежным источникам присваивать произвольные значения этим параметрам может привести к отказу в обслуживании.

Кроме того, система обрабатывает сигнал по-разному, если PID назначения меньше или равен 0. Такое другое поведение может повлиять на несколько процессов с одинаковым (E)UID одновременно, если вызов останется неконтролируемым.


###### Спросите себя, есть ли

     Параметры pid и sig не являются доверенными (они поступают из внешнего источника).
     Эта функция активируется лицами, не являющимися администраторами.
     Обработчики сигналов целевых процессов останавливают важные функции.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода'''

import os

@app.route("/kill-pid/<pid>")
def send_signal(pid):
    os.kill(pid, 9)  # Sensitive

@app.route("/kill-pgid/<pgid>")
def send_signal(pgid):
    os.killpg(pgid, 9)  # Sensitive



### Рекомендуемые методы безопасного кодирования
'''
     Для приложений с отслеживанием состояния и управлением пользователями убедитесь, что этот код запускают только администраторы.
     Прежде чем использовать их, убедитесь, что параметры pid и sig верны.
     Убедитесь, что процесс отправки сигналов выполняется с как можно меньшим количеством привилегий ОС.
     Изолируйте процесс в системе на основе его (E)UID.
     Убедитесь, что сигнал не прерывает какие-либо важные функции при перехвате обработчиками сигнала цели.

Соответствующее решение
'''
import os

@app.route("/kill-pid/<pid>")
def send_signal(pid):
    # Validate the untrusted PID,
    # With a pre-approved list or authorization checks
    if is_valid_pid(pid):
        os.kill(pid, 9)

@app.route("/kill-pgid/<pgid>")
def send_signal(pgid):
    # Validate the untrusted PGID,
    # With a pre-approved list or authorization checks
    if is_valid_pgid(pgid):
        os.kill(pgid, 9)
'''
See

    MITRE, CWE-283 - Unverified Ownership
    kill(1) — Linux manual page
    kill(2) — Linux manual page
'''
