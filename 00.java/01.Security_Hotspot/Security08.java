###### Настройка регистраторов важна для безопасности

Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКьюб (Java)

Настройка регистраторов важна для безопасности. В прошлом это приводило к следующим уязвимостям:

     CVE-2018-0285
     CVE-2000-1127
     CVE-2017-15113
     CVE-2015-5742

Журналы полезны до, во время и после инцидента безопасности.

     Злоумышленники в большинстве случаев начинают свою гнусную работу с проверки системы на наличие уязвимостей. Мониторинг этой активности и ее прекращение — это первый шаг к предотвращению атаки.
     В случае успешной атаки журналы должны содержать достаточно информации, чтобы понять, какой ущерб мог нанести злоумышленник.

Журналы также являются целью злоумышленников, поскольку они могут содержать конфиденциальную информацию. Настройка регистраторов влияет на тип регистрируемой информации и способ ее регистрации.

Это правило помечает код проверки, который инициирует настройку средств ведения журнала. Целью является проведение проверок кода безопасности.
Исключения

Log4J 1.x не распространяется, поскольку срок его эксплуатации истек.

###### Спросите себя, есть ли

     неавторизованные пользователи могут иметь доступ к журналам либо потому, что они хранятся в незащищенном месте, либо потому, что приложение предоставляет к ним доступ.
     журналы содержат конфиденциальную информацию на рабочем сервере. Это может произойти, когда регистратор находится в режиме отладки.
     журнал может расти без ограничений. Это может произойти, когда дополнительная информация записывается в журналы каждый раз, когда пользователь выполняет действие, и пользователь может выполнять это действие столько раз, сколько пожелает.
     журналы не содержат достаточно информации, чтобы понять, какой ущерб мог нанести злоумышленник. Режим регистраторов (информация, предупреждение, ошибка) может отфильтровывать важную информацию. Они могут не печатать контекстную информацию, такую как точное время событий или имя хоста сервера.
     журналы хранятся только локально, а не для резервного копирования или репликации.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода


This rule supports the following libraries: Log4J, java.util.logging and Logback

// === Log4J 2 ===
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.*;
import org.apache.logging.log4j.core.config.*;

// Sensitive: creating a new custom configuration
abstract class CustomConfigFactory extends ConfigurationFactory {
    // ...
}

class A {
    void foo(Configuration config, LoggerContext context, java.util.Map<String, Level> levelMap,
            Appender appender, java.io.InputStream stream, java.net.URI uri,
            java.io.File file, java.net.URL url, String source, ClassLoader loader, Level level, Filter filter)
            throws java.io.IOException {
        // Creating a new custom configuration
        ConfigurationBuilderFactory.newConfigurationBuilder();  // Sensitive

        // Setting loggers level can result in writing sensitive information in production
        Configurator.setAllLevels("com.example", Level.DEBUG);  // Sensitive
        Configurator.setLevel("com.example", Level.DEBUG);  // Sensitive
        Configurator.setLevel(levelMap);  // Sensitive
        Configurator.setRootLevel(Level.DEBUG);  // Sensitive

        config.addAppender(appender); // Sensitive: this modifies the configuration

        LoggerConfig loggerConfig = config.getRootLogger();
        loggerConfig.addAppender(appender, level, filter); // Sensitive
        loggerConfig.setLevel(level); // Sensitive

        context.setConfigLocation(uri); // Sensitive

        // Load the configuration from a stream or file
        new ConfigurationSource(stream);  // Sensitive
        new ConfigurationSource(stream, file);  // Sensitive
        new ConfigurationSource(stream, url);  // Sensitive
        ConfigurationSource.fromResource(source, loader);  // Sensitive
        ConfigurationSource.fromUri(uri);  // Sensitive
    }
}

// === java.util.logging ===
import java.util.logging.*;

class M {
    void foo(LogManager logManager, Logger logger, java.io.InputStream is, Handler handler)
            throws SecurityException, java.io.IOException {
        logManager.readConfiguration(is); // Sensitive

        logger.setLevel(Level.FINEST); // Sensitive
        logger.addHandler(handler); // Sensitive
    }
}

// === Logback ===
import ch.qos.logback.classic.util.ContextInitializer;
import ch.qos.logback.core.Appender;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.*;

class M {
    void foo(Logger logger, Appender<ILoggingEvent> fileAppender) {
        System.setProperty(ContextInitializer.CONFIG_FILE_PROPERTY, "config.xml"); // Sensitive
        JoranConfigurator configurator = new JoranConfigurator(); // Sensitive

        logger.addAppender(fileAppender); // Sensitive
        logger.setLevel(Level.DEBUG); // Sensitive
    }
}



######## Рекомендуемые методы безопасного кодирования

     Убедитесь, что в вашем производственном развертывании средства ведения журнала не находятся в режиме «отладки», поскольку они могут записывать в журналы конфиденциальную информацию.
     Производственные журналы должны храниться в безопасном месте, доступном только системным администраторам.
     Настройте регистраторы для отображения всех предупреждений, информации и сообщений об ошибках. Запишите соответствующую информацию, такую как точное время событий и имя хоста.
     Выберите формат журнала, который легко анализировать и обрабатывать автоматически. В случае атаки важно быстро обрабатывать журналы, чтобы последствия были известны и ограничены.
     Проверьте правильность разрешений файлов журналов. Если вы индексируете журналы в каком-либо другом сервисе, убедитесь, что передача и сервис также безопасны.
     Добавьте ограничения на размер логов и убедитесь, что ни один пользователь не сможет заполнить логами диск. Это может произойти, даже если пользователь не контролирует регистрируемую информацию. Злоумышленник может просто повторить записанное действие много раз.

Помните, что правильная настройка логгеров не делает их надежными. Вот список рекомендаций, объясняющих, как использовать журналы:

     Не регистрируйте конфиденциальную информацию. Сюда, очевидно, входят пароли и номера кредитных карт, а также любая личная информация, такая как имена пользователей, местоположение и т. д. Обычно любая информация, которая защищена законом, является хорошим кандидатом на удаление.
     Очистите все вводимые пользователем данные перед записью их в журналы. Это включает в себя проверку его размера, содержимого, кодировки, синтаксиса и т. д. Что касается любого пользовательского ввода, по возможности проверяйте его с помощью белых списков. Предоставление пользователям возможности записывать в ваши журналы то, что они хотят, может иметь множество последствий. Например, он может использовать все ваше пространство для хранения или поставить под угрозу вашу службу индексирования журналов.
     Записывайте достаточно информации, чтобы отслеживать подозрительные действия и оценивать влияние, которое злоумышленник может оказать на ваши системы. Регистрируйте такие события, как неудачные входы в систему, успешные входы в систему, ошибки проверки ввода на стороне сервера, отказы в доступе и любые важные транзакции.
     Отслеживайте журналы на предмет любой подозрительной активности.
See

    OWASP Top 10 2021 Category A9 - Security Logging and Monitoring Failures
    OWASP Top 10 2017 Category A3 - Sensitive Data Exposure
    OWASP Top 10 2017 Category A10 - Insufficient Logging & Monitoring
    MITRE, CWE-117 - Improper Output Neutralization for Logs
    MITRE, CWE-532 - Information Exposure Through Log Files
    SANS Top 25 - Porous Defenses
