###### Использование генераторов псевдослучайных чисел (PRNG) чувствительно к безопасности.

'''Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянная/проблема: 10 мин.

Использование генераторов псевдослучайных чисел (PRNG) чувствительно к безопасности. Например, в прошлом это приводило к следующим уязвимостям:

     CVE-2013-6386
     CVE-2006-3419
     CVE-2008-4102

Когда программное обеспечение генерирует предсказуемые значения в контексте, требующем непредсказуемости, злоумышленник может угадать следующее значение, которое будет сгенерировано, и использовать это предположение, чтобы выдать себя за другого пользователя или получить доступ к конфиденциальной информации.



###### Спросите себя, есть ли

     код, использующий сгенерированное значение, требует, чтобы оно было непредсказуемым. Это относится ко всем механизмам шифрования или к хешированию секретного значения, например пароля.
     используемая вами функция генерирует значение, которое можно предсказать (псевдослучайное).
     сгенерированное значение используется несколько раз.
     злоумышленник может получить доступ к сгенерированному значению.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода'''

import random

random.getrandbits(1) # Sensitive
random.randint(0,9) # Sensitive
random.random()  # Sensitive

# the following functions are sadly used to generate salt by selecting characters in a string ex: "abcdefghijk"...
random.sample(['a', 'b'], 1)  # Sensitive
random.choice(['a', 'b'])  # Sensitive
random.choices(['a', 'b'])  # Sensitive



### Рекомендуемые методы безопасного кодирования
'''
     Используйте только генераторы случайных чисел, рекомендованные OWASP или любой другой доверенной организацией.
     Используйте сгенерированные случайные значения только один раз.
     Вы не должны раскрывать сгенерированное случайное значение. Если вам необходимо сохранить его, убедитесь, что база данных или файл защищены.

Видеть

     Топ-10 OWASP 2021 г., категория A2 — криптографические сбои
     Топ-10 OWASP 2017 г., категория A3 — раскрытие конфиденциальных данных
     Стандарт проверки Mobile AppSec — требования к криптографии
     Топ-10 OWASP Mobile 2016 г., категория M5 – Недостаточная криптография
     MITRE, CWE-338 — Использование криптографически слабого генератора псевдослучайных чисел (PRNG)
     MITRE, CWE-330 — Использование недостаточно случайных значений
     MITRE, CWE-326 — недостаточная надежность шифрования
     MITRE, CWE-1241 — Использование предсказуемого алгоритма в генераторе случайных чисел
     Получено на основе правила FindSecBugs. Генератор предсказуемых псевдослучайных чисел.'''


