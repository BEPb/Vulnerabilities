###### Разрешение запросов с чрезмерной длиной содержимого важно для безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКьюб (Java)
     Постоянно/проблема: 5 минут

Отклонение запросов со значительной длиной контента — хорошая практика для контроля интенсивности сетевого трафика и, следовательно, потребления ресурсов, чтобы предотвратить DoS-атаки.

Спросите себя, есть ли

     ограничения размера не определены для различных ресурсов веб-приложения.
     веб-приложение не защищено функциями ограничения скорости.
     инфраструктура веб-приложений имеет ограниченные ресурсы.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

With default limit value of 8388608 (8MB).

A 100 MB file is allowed to be uploaded:

@Bean(name = "multipartResolver")
public CommonsMultipartResolver multipartResolver() {
  CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver();
  multipartResolver.setMaxUploadSize(104857600); // Sensitive (100MB)
  return multipartResolver;
}

@Bean(name = "multipartResolver")
public CommonsMultipartResolver multipartResolver() {
  CommonsMultipartResolver multipartResolver = new CommonsMultipartResolver(); // Sensitive, by default if maxUploadSize property is not defined, there is no limit and thus it's insecure
  return multipartResolver;
}

@Bean
public MultipartConfigElement multipartConfigElement() {
  MultipartConfigFactory factory = new MultipartConfigFactory(); // Sensitive, no limit by default
  return factory.createMultipartConfig();
}



###### Рекомендуемые методы безопасного кодирования

     Для большинства функций приложения рекомендуется ограничить размер запросов следующими значениями:
         меньше или равно 8 МБ для загрузки файлов.
         меньше или равно 2 МБ для других запросов.

Рекомендуется настроить правило, указав предельные значения, соответствующие веб-приложению.
Соответствующее решение


File upload size is limited to 8 MB:

@Bean(name = "multipartResolver")
public CommonsMultipartResolver multipartResolver() {
  multipartResolver.setMaxUploadSize(8388608); // Compliant (8 MB)
  return multipartResolver;
}

See

    OWASP Top 10 2021 Category A5 - Security Misconfiguration
    Owasp Cheat Sheet - Owasp Denial of Service Cheat Sheet
    OWASP Top 10 2017 Category A6 - Security Misconfiguration
    MITRE, CWE-770 - Allocation of Resources Without Limits or Throttling
    MITRE, CWE-400 - Uncontrolled Resource Consumption

