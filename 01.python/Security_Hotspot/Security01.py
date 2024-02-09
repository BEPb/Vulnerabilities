Метод HTTP безопасен, если используется для выполнения операции только для чтения, например получения информации. Напротив, небезопасный метод HTTP используется для изменения состояния приложения, например, для обновления профиля пользователя в веб-приложении.

Распространенными безопасными методами HTTP являются GET, HEAD или OPTIONS.

Распространенными небезопасными методами HTTP являются POST, PUT и DELETE.

Разрешение как безопасным, так и небезопасным методам HTTP выполнять определенную операцию в веб-приложении может повлиять на его безопасность, например, защита CSRF в большинстве случаев защищает только операции, выполняемые небезопасными методами HTTP.

Спросите себя, есть ли

     Методы HTTP вообще не определены для маршрута/контроллера приложения.
     Безопасные методы HTTP определяются и используются для маршрута/контроллера, который может изменять состояние приложения.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.

For Django:

# No method restriction
def view(request):  # Sensitive
    return HttpResponse("...")

@require_http_methods(["GET", "POST"])  # Sensitive
def view(request):
    return HttpResponse("...")

For Flask:

@methods.route('/sensitive', methods=['GET', 'POST'])  # Sensitive
def view():
    return Response("...", 200)



### Рекомендуемые методы безопасного кодирования

Для всех маршрутов/контроллеров приложения авторизованные методы HTTP должны быть явно определены, а безопасные методы HTTP должны использоваться только для выполнения операций только для чтения.


For Django:

@require_http_methods(["POST"])
def view(request):
    return HttpResponse("...")

@require_POST
def view(request):
    return HttpResponse("...")

@require_GET
def view(request):
    return HttpResponse("...")

@require_safe
def view(request):
    return HttpResponse("...")

For Flask:

@methods.route('/compliant1')
def view():
    return Response("...", 200)

@methods.route('/compliant2', methods=['GET'])
def view():
    return Response("...", 200)

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2021 Category A4 - Insecure Design
    OWASP Top 10 2017 Category A5 - Broken Access Control
    MITRE, CWE-352 - Cross-Site Request Forgery (CSRF)
    OWASP: Cross-Site Request Forgery
    SANS Top 25 - Insecure Interaction Between Components
    Django - Allowed HTTP Methods
    Flask - HTTP Methods


