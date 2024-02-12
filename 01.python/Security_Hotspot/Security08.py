###### Создание общедоступных API чувствительно к безопасности.

'''Точка доступа безопасности
Блокатор

     Доступно с 19 декабря 2023 г.
     СонарКуб (Python)
     Постоянно/проблема: 5 минут

Публичный API, который может быть запрошен любыми аутентифицированными или неаутентифицированными пользователями, может привести к несанкционированным действиям и раскрытию информации.

###### Спросите себя, есть ли

Публичный API:

     раскрывает конфиденциальные данные, такие как личная информация.
     может использоваться для выполнения чувствительных операций.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

For aws_cdk.aws_apigateway.Resource:
'''
from aws_cdk import (
    aws_apigateway as apigateway
)

resource = api.root.add_resource("example")
resource.add_method(
    "GET",
    authorization_type=apigateway.AuthorizationType.NONE  # Sensitive
)

# For aws_cdk.aws_apigatewayv2.CfnRoute:

from aws_cdk import (
    aws_apigatewayv2 as apigateway
)

apigateway.CfnRoute(
    self,
    "no-auth",
    api_id=api.ref,
    route_key="GET /test",
    authorization_type="NONE"  # Sensitive
)


### RРекомендуемые методы безопасного кодирования

# Рекомендуется ограничить доступ к API авторизованным лицам, за исключением случаев, когда API предлагает неконфиденциальную услугу, предназначенную для публичного использования.
# Соответствующее решение
#
# For aws_cdk.aws_apigateway.Resource:

from aws_cdk import (
    aws_apigateway as apigateway
)

opts = apigateway.MethodOptions(
    authorization_type=apigateway.AuthorizationType.IAM
)
resource = api.root.add_resource(
    "example",
    default_method_options=opts
)
resource.add_method(
    "POST",
    authorization_type=apigateway.AuthorizationType.IAM
)
resource.add_method(  # authorization_type is inherited from the Resource's configured default_method_options
    "POST"
)

# For aws_cdk.aws_apigatewayv2.CfnRoute:

from aws_cdk import (
    aws_apigatewayv2 as apigateway
)

apigateway.CfnRoute(
    self,
    "auth",
    api_id=api.ref,
    route_key="GET /test",
    authorization_type="AWS_IAM"
)

'''See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    AWS Documentation - Controlling and managing access to a REST API in API Gateway
    MITRE, CWE-284 - Improper Access Control
    OWASP Top 10 2017 Category A5 - Broken Access Control'''






