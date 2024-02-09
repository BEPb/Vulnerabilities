###### Receiving intents is security-sensitive

Security Hotspot
Critical

    Available SinceDec 19, 2023
    SonarQube (Java)

Android applications can receive broadcasts from the system or other applications. Receiving intents is security-sensitive. For example, it has led in the past to the following vulnerabilities:

    CVE-2019-1677
    CVE-2015-1275

Receivers can be declared in the manifest or in the code to make them context specific. If the receiver is declared in the manifest Android will start the application if it is not already running once a matching broadcast is received. The receiver is an entry point into the application.

Other applications can send potentially malicious broadcasts, so it is important to consider broadcasts as untrusted and to limit the applications that can send broadcasts to the receiver.

Permissions can be specified to restrict broadcasts to authorized applications. Restrictions can be enforced by both the sender and receiver of a broadcast. If permissions are specified when registering a broadcast receiver, then only broadcasters who were granted this permission can send a message to the receiver.

This rule raises an issue when a receiver is registered without specifying any "broadcast permission".

###### Ask Yourself Whether

    The data extracted from intents is not sanitized.
    Intents broadcast is not restricted.

There is a risk if you answered yes to any of those questions.
Sensitive Code Example

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.support.annotation.RequiresApi;

public class MyIntentReceiver {

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void register(Context context, BroadcastReceiver receiver,
                         IntentFilter filter,
                         String broadcastPermission,
                         Handler scheduler,
                         int flags) {
        context.registerReceiver(receiver, filter); // Sensitive
        context.registerReceiver(receiver, filter, flags); // Sensitive

        // Broadcasting intent with "null" for broadcastPermission
        context.registerReceiver(receiver, filter, null, scheduler); // Sensitive
        context.registerReceiver(receiver, filter, null, scheduler, flags); // Sensitive
    }
}




######## Recommended Secure Coding Practices

Restrict the access to broadcasted intents. See Android documentation for more information.
Compliant Solution

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.support.annotation.RequiresApi;

public class MyIntentReceiver {

    @RequiresApi(api = Build.VERSION_CODES.O)
    public void register(Context context, BroadcastReceiver receiver,
                         IntentFilter filter,
                         String broadcastPermission,
                         Handler scheduler,
                         int flags) {

        context.registerReceiver(receiver, filter, broadcastPermission, scheduler);
        context.registerReceiver(receiver, filter, broadcastPermission, scheduler, flags);
    }
}

See

    Mobile AppSec Verification Standard - Platform Interaction Requirements
    OWASP Mobile Top 10 2016 Category M1 - Improper Platform Usage
    MITRE, CWE-925 - Improper Verification of Intent by Broadcast Receiver
    MITRE, CWE-926 - Improper Export of Android Application Components
    SANS Top 25 - Insecure Interaction Between Components
    Android documentation - Broadcast Overview - Security considerations and best practices


