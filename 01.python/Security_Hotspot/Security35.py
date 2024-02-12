###### Использование интерпретатора оболочки при выполнении команд ОС важно с точки зрения безопасности.

'''Точка доступа безопасности
Главный
Устарело

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/выпуск: 30 мин.

Уязвимости внедрения произвольных команд ОС более вероятны, когда создается оболочка, а не новый процесс, действительно, метасимволы оболочки могут использоваться (например, когда параметры контролируются пользователем) для внедрения команд ОС.
Устарело

Это правило устарело и со временем будет удалено.


###### Спросите себя, есть ли

     Имя или параметры команды ОС контролируются пользователем.

Существует риск, если вы ответили утвердительно на этот вопрос.
Пример конфиденциального кода

Python 3'''

subprocess.run(cmd, shell=True)  # Sensitive
subprocess.Popen(cmd, shell=True)  # Sensitive
subprocess.call(cmd, shell=True)  # Sensitive
subprocess.check_call(cmd, shell=True)  # Sensitive
subprocess.check_output(cmd, shell=True)  # Sensitive
os.system(cmd)  # Sensitive: a shell is always spawn

# Python 2

cmd = "when a string is passed through these function, a shell is spawn"
(_, child_stdout, _) = os.popen2(cmd)  # Sensitive
(_, child_stdout, _) = os.popen3(cmd)  # Sensitive
(_, child_stdout) = os.popen4(cmd)  # Sensitive


(child_stdout, _) = popen2.popen2(cmd)  # Sensitive
(child_stdout, _, _) = popen2.popen3(cmd)  # Sensitive
(child_stdout, _) = popen2.popen4(cmd)  # Sensitive


### Рекомендуемые методы безопасного кодирования

'''Используйте функции, которые не создают оболочку.
Соответствующее решение

Python 3'''

# by default shell=False, a shell is not spawn
subprocess.run(cmd)  # Compliant
subprocess.Popen(cmd)  # Compliant
subprocess.call(cmd)  # Compliant
subprocess.check_call(cmd)  # Compliant
subprocess.check_output(cmd)  # Compliant

# always in a subprocess:
os.spawnl(mode, path, *cmd)  # Compliant
os.spawnle(mode, path, *cmd, env)  # Compliant
os.spawnlp(mode, file, *cmd)  # Compliant
os.spawnlpe(mode, file, *cmd, env)  # Compliant
os.spawnv(mode, path, cmd)  # Compliant
os.spawnve(mode, path, cmd, env)  # Compliant
os.spawnvp(mode, file, cmd)  # Compliant
os.spawnvpe(mode, file, cmd, env)  # Compliant

(child_stdout) = os.popen(cmd, mode, 1)  # Compliant
(_, output) = subprocess.getstatusoutput(cmd)  # Compliant
out = subprocess.getoutput(cmd)  # Compliant
os.startfile(path)  # Compliant
os.execl(path, *cmd)  # Compliant
os.execle(path, *cmd, env)  # Compliant
os.execlp(file, *cmd)  # Compliant
os.execlpe(file, *cmd, env)  # Compliant
os.execv(path, cmd)  # Compliant
os.execve(path, cmd, env)  # Compliant
os.execvp(file, cmd)  # Compliant
os.execvpe(file, cmd, env)  # Compliant

# Python 2

cmdsargs = ("use", "a", "sequence", "to", "directly", "start", "a", "subprocess")

(_, child_stdout) = os.popen2(cmdsargs)  # Compliant
(_, child_stdout, _) = os.popen3(cmdsargs)  # Compliant
(_, child_stdout) = os.popen4(cmdsargs)  # Compliant

(child_stdout, _) = popen2.popen2(cmdsargs)  # Compliant
(child_stdout, _, _) = popen2.popen3(cmdsargs)  # Compliant
(child_stdout, _) = popen2.popen4(cmdsargs)  # Compliant

'''See

    OWASP Top 10 2021 Category A3 - Injection
    OWASP Top 10 2017 Category A1 - Injection
    MITRE, CWE-78 - Improper Neutralization of Special Elements used in an OS Command
    SANS Top 25 - Insecure Interaction Between Components'''

