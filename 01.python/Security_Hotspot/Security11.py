###### Отключение защиты CSRF чувствительно к безопасности.

'''Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

Атака подделки межсайтовых запросов (CSRF) происходит, когда злоумышленник может заставить доверенного пользователя веб-приложения выполнить конфиденциальные действия, которые он не намеревался, например обновление своего профиля или отправку сообщения, в более общем смысле. все, что может изменить состояние приложения.

Злоумышленник может обманом заставить пользователя/жертву щелкнуть ссылку, соответствующую привилегированному действию, или посетить вредоносный веб-сайт, в который встроен скрытый веб-запрос, а поскольку веб-браузеры автоматически включают файлы cookie, действия могут быть аутентифицированы и конфиденциальны.

###### Спросите себя, есть ли

     Веб-приложение использует файлы cookie для аутентификации пользователей.
     В веб-приложении существуют конфиденциальные операции, которые можно выполнять после аутентификации пользователя.
     Состояние/ресурсы веб-приложения можно изменить, например, выполнив запросы HTTP POST или HTTP DELETE.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For a Django application, the code is sensitive when,

    django.middleware.csrf.CsrfViewMiddleware is not used in the Django settings:'''

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
] # Sensitive: django.middleware.csrf.CsrfViewMiddleware is missing

    # the CSRF protection is disabled on a view:

@csrf_exempt # Sensitive
def example(request):
    return HttpResponse("default")

'''For a Flask application, the code is sensitive when,

    the WTF_CSRF_ENABLED setting is set to false:'''

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False # Sensitive

    the application doesn’t use the CSRFProtect module:

app = Flask(__name__) # Sensitive: CSRFProtect is missing

@app.route('/')
def hello_world():
    return 'Hello, World!'

    the CSRF protection is disabled on a view:

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app)

@app.route('/example/', methods=['POST'])
@csrf.exempt # Sensitive
def example():
    return 'example '

    the CSRF protection is disabled on a form:

class unprotectedForm(FlaskForm):
    class Meta:
        csrf = False # Sensitive

    name = TextField('name')
    submit = SubmitField('submit')



### Рекомендуемые методы безопасного кодирования

    ''' Настоятельно рекомендуется защита от атак CSRF:
         будет активирован по умолчанию для всех небезопасных методов HTTP.
         реализовано, например, с помощью неугадываемого токена CSRF
     Конечно, все конфиденциальные операции не следует выполнять с помощью безопасных методов HTTP, таких как GET, которые предназначены только для поиска информации.

Соответствующее решение

For a Django application,

    it is recommended to protect all the views with django.middleware.csrf.CsrfViewMiddleware:'''

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware', # Compliant
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

    # and to not disable the CSRF protection on specific views:

def example(request): # Compliant
    return HttpResponse("default")

'''For a Flask application,

    the CSRFProtect module should be used (and not disabled further with WTF_CSRF_ENABLED set to false):'''

app = Flask(__name__)
csrf = CSRFProtect()
csrf.init_app(app) # Compliant

    # and it is recommended to not disable the CSRF protection on specific views or forms:

@app.route('/example/', methods=['POST']) # Compliant
def example():
    return 'example '

class unprotectedForm(FlaskForm):
    class Meta:
        csrf = True # Compliant

    name = TextField('name')
    submit = SubmitField('submit')

'''See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    MITRE, CWE-352 - Cross-Site Request Forgery (CSRF)
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    OWASP: Cross-Site Request Forgery
    SANS Top 25 - Insecure Interaction Between Components'''








