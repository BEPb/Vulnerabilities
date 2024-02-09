###### Чтение стандартного ввода чувствительно к безопасности.

Точка доступа безопасности
Критический
Устарело

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)

Чтение стандартного ввода чувствительно к безопасности. В прошлом это приводило к следующим уязвимостям:

     CVE-2005-2337
     CVE-2017-11449

Злоумышленники обычно создают входные данные, позволяющие им использовать уязвимости программного обеспечения. Таким образом, любые данные, считанные со стандартного ввода (stdin), могут быть опасными и должны быть проверены.

Это правило помечает код, считывающий со стандартного ввода.
Устарело

Это правило устарело и со временем будет удалено.


###### Спросите себя, есть ли

     данные, считанные со стандартного ввода, не очищаются перед использованием.

Вы находитесь в группе риска, если ответили утвердительно на этот вопрос.
Пример конфиденциального кода

Python 2 and Python 3

import sys
from sys import stdin, __stdin__

# Any reference to sys.stdin or sys.__stdin__ without a method call is Sensitive
sys.stdin  # Sensitive

for line in sys.stdin:  # Sensitive
    print(line)

it = iter(sys.stdin)  # Sensitive
line = next(it)

# Calling the following methods on stdin or __stdin__ is sensitive
sys.stdin.read()  # Sensitive
sys.stdin.readline()  # Sensitive
sys.stdin.readlines()  # Sensitive

# Calling other methods on stdin or __stdin__ does not require a review, thus it is not Sensitive
sys.stdin.seekable()  # Ok
# ...

Python 2 only

raw_input('What is your password?')  # Sensitive

Python 3 only

input('What is your password?')  # Sensitive

Function fileinput.input and class fileinput.FileInput read the standard input when the list of files is empty.

for line in fileinput.input():  # Sensitive
    print(line)

for line in fileinput.FileInput():  # Sensitive
    print(line)

for line in fileinput.input(['setup.py']):  # Ok
    print(line)

for line in fileinput.FileInput(['setup.py']):  # Ok
    print(line)




### Рекомендуемые методы безопасного кодирования

Очистите все данные, считанные со стандартного ввода, перед их использованием.
Видеть

     MITRE, CWE-20 — неправильная проверка ввода

