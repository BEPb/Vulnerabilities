###### Намерения вещания чувствительны к безопасности

Точка доступа безопасности
Критический

     Доступно с 19 декабря 2023 г.
     СонарКьюб (Java)

В приложениях Android намерения широковещания чувствительны к безопасности. Например, в прошлом это приводило к следующей уязвимости:

     CVE-2018-9489

По умолчанию широковещательные намерения видны каждому приложению, раскрывая всю содержащуюся в них конфиденциальную информацию.

Это правило создает проблему, когда намерение передается без указания какого-либо «разрешения получателя».


###### Спросите себя, есть ли

     Намерение содержит конфиденциальную информацию.
     Прием намерений не ограничен.

Существует риск, если вы ответили утвердительно на любой из этих вопросов.
Пример конфиденциального кода

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.UserHandle;
import android.support.annotation.RequiresApi;

public class MyIntentBroadcast {
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR1)
    public void broadcast(Intent intent, Context context, UserHandle user,
                          BroadcastReceiver resultReceiver, Handler scheduler, int initialCode,
                          String initialData, Bundle initialExtras,
                          String broadcastPermission) {
        context.sendBroadcast(intent); // Sensitive
        context.sendBroadcastAsUser(intent, user); // Sensitive

        // Broadcasting intent with "null" for receiverPermission
        context.sendBroadcast(intent, null); // Sensitive
        context.sendBroadcastAsUser(intent, user, null); // Sensitive
        context.sendOrderedBroadcast(intent, null); // Sensitive
        context.sendOrderedBroadcastAsUser(intent, user, null, resultReceiver,
                scheduler, initialCode, initialData, initialExtras); // Sensitive
    }
}





######## Рекомендуемые методы безопасного кодирования

Ограничить доступ к транслируемым намерениям. Дополнительную информацию см. в документации Android.
Соответствующее решение

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.UserHandle;
import android.support.annotation.RequiresApi;

public class MyIntentBroadcast {
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR1)
    public void broadcast(Intent intent, Context context, UserHandle user,
                          BroadcastReceiver resultReceiver, Handler scheduler, int initialCode,
                          String initialData, Bundle initialExtras,
                          String broadcastPermission) {

        context.sendBroadcast(intent, broadcastPermission);
        context.sendBroadcastAsUser(intent, user, broadcastPermission);
        context.sendOrderedBroadcast(intent, broadcastPermission);
        context.sendOrderedBroadcastAsUser(intent, user,broadcastPermission, resultReceiver,
                scheduler, initialCode, initialData, initialExtras);
    }
}

See

    OWASP Top 10 2021 Category A4 - Insecure Design
    Mobile AppSec Verification Standard - Platform Interaction Requirements
    OWASP Mobile Top 10 2016 Category M1 - Improper Platform Usage
    MITRE, CWE-927 - Use of Implicit Intent for Sensitive Communication
    Android documentation - Broadcast Overview - Security considerations and best practices


