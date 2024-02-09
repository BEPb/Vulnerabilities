###### Разрешение перечисления пользователей важно для безопасности.

Точка доступа безопасности
Главный

     Доступно с 19 декабря 2023 г.
     СонарКьюб (Java)
     Постоянная/проблема: 10 мин.

Перечисление пользователей означает возможность угадывать существующие имена пользователей в базе данных веб-приложения. Это может произойти, например, при использовании функций веб-сайта «вход/регистрация/забыли пароль».

Когда пользователь пытается «войти» на веб-сайт с неправильным именем пользователя/логином, веб-приложение не должно сообщать о том, что имя пользователя не существует, с сообщением, похожим на «это имя пользователя неверно», вместо этого должно отображаться общее сообщение. использоваться как «неверные учетные данные», таким образом невозможно угадать, были ли имя пользователя или пароль неправильными во время аутентификации.

Если функция управления пользователями раскрывает информацию о существовании имени пользователя, злоумышленники могут использовать атаки грубой силы для получения большого количества действительных имен пользователей, что повлияет на конфиденциальность соответствующих пользователей и облегчит другие атаки (фишинг, подбор пароля и т. д.) .



###### Спросите себя, есть ли

     Приложение сообщает, что имя пользователя существует в его базе данных: в большинстве случаев можно избежать утечки такого рода, за исключением части веб-сайта «регистрация/вход», поскольку в этом случае пользователь должен выбрать действительное имя пользователя (не уже занято другим пользователем).
     Для запросов с использованием имени пользователя не существует ограничения скорости и защиты CAPTCHA.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

In a Spring-security web application the username leaks when:

    The string used as argument of loadUserByUsername method is used in an exception message:

public String authenticate(String username, String password) {
  // ....
  MyUserDetailsService s1 = new MyUserDetailsService();
  MyUserPrincipal u1 = s1.loadUserByUsername(username);

  if(u1 == null) {
    throw new BadCredentialsException(username+" doesn't exist in our database"); // Sensitive
  }
  // ....
}

    UsernameNotFoundException is thrown (except when it is in the loadUserByUsername method):

public String authenticate(String username, String password) {
  // ....
  if(user == null) {
      throw new UsernameNotFoundException("user not found"); // Sensitive
  }
  // ....
}

    HideUserNotFoundExceptions is set to false:

DaoAuthenticationProvider daoauth = new DaoAuthenticationProvider();
daoauth.setUserDetailsService(new MyUserDetailsService());
daoauth.setPasswordEncoder(new BCryptPasswordEncoder());
daoauth.setHideUserNotFoundExceptions(false); // Sensitive
builder.authenticationProvider(daoauth);


######## Рекомендуемые методы безопасного кодирования

Когда пользователь выполняет запрос, включающий имя пользователя, не должно быть возможности обнаружить различия между действительным и неправильным именем пользователя:

     Сообщения об ошибках должны быть общими и не раскрывать, действительно ли имя пользователя или нет.
     Время ответа должно быть одинаковым для действительного имени пользователя или нет.
     Необходимо внедрить CAPTCHA и другие решения по ограничению скорости.

Соответствующее решение

In a Spring-security web application:

    the same message should be used regardless of whether it is the wrong user or password:

public String authenticate(String username, String password) throws AuthenticationException {
  Details user = null;
  try {
    user = loadUserByUsername(username);
  } catch (UsernameNotFoundException | DataAccessException e) {
    // Hide this exception reason to not disclose that the username doesn't exist
  }
  if (user == null || !user.isPasswordCorrect(password)) {
     // User should not be able to guess if the bad credentials message is related to the username or the password
    throw new BadCredentialsException("Bad credentials");
  }
}

    HideUserNotFoundExceptions should be set to true:

DaoAuthenticationProvider daoauth = new DaoAuthenticationProvider();
daoauth.setUserDetailsService(new MyUserDetailsService());
daoauth.setPasswordEncoder(new BCryptPasswordEncoder());
daoauth.setHideUserNotFoundExceptions(true); // Compliant
builder.authenticationProvider(daoauth);

See

    OWASP Top 10 2021 Category A1 - Broken Access Control
    OWASP Top 10 2017 Category A2 - Broken Authentication
    MITRE, CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor






