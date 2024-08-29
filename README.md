# FrameworkPatch

Modify framework.jar to build a valid certificate chain.

## WARNING

**This is for advanced users, if you don't know about Java and Smali modding, this is not for you. No support will be provided.**

## Tutorial

First, we have to add the hooks into framework.jar

Pull framework.jar from your device:

```
adb pull /system/framework/framework.jar
```

Decompile framework.jar as you like, either [APKTool](https://github.com/iBotPeaches/Apktool) or [Google's Smali](https://github.com/google/smali)

Once the framework is decompiled, we have to edit three files.

- AndroidKeyStoreSpi.smali:

Search for the "engineGetCertificateChain" method, you should find this code snippet:

```
const/4 v4, 0x0

aput-object v2, v3, v4

return-object v3
```

In this example:

register v2 -> leaf cert

register v3 -> certificate chain

register v4 -> the value "0", the position to insert the leaf cert in certificate chain.

It may be different in your .smali file. Do not copy and paste.

After aput operation, you must add this:

```
invoke-static {XX}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;

move-result-object XX
```

Where XX is your leaf certificate register.

So the final code (in this example) should be this:

```
const/4 v4, 0x0

aput-object v2, v3, v4

invoke-static {v3}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;

move-result-object v3

return-object v3
```

- Instrumentation.smali:

Search for the "newApplication" method, you should find this code snippet:

```
check-cast v0, Landroid/app/Application;

invoke-virtual {v0, p1}, Landroid/app/Application;->attach(Landroid/content/Context;)V

return-object v0
```

In this example:

register v0 -> instance

register p1 -> context

Before the return operation, add this:

```
invoke-static {XX}, Lcom/android/internal/util/framework/Android;->newApplication(Landroid/content/Context;)V
```

Where XX is your Context register.

- ApplicationPackageManager.smali

Search for "hasSystemFeature" method, you should find this code snippet:

```
const/4 v0, 0x0

invoke-virtual {p0, p1, v0}, Landroid/app/ApplicationPackageManager;->hasSystemFeature(Ljava/lang/String;I)Z

move-result v0

return v0
```

In this example:

register p0: context

register p1: feature

register v0: the value "0"

Before the return, add this call:

```
invoke-static {XX, YY}, Lcom/android/internal/util/framework/Android;->hasSystemFeature(ZLjava/lang/String;)Z

move-result v0
```

Where XX is the value "0", and YY is the feature.

By default this project has fingerprint and keybox that are working as of 29.08.2024, you can change these in Fingerprint.java and Android.java.

**You also have to change the OS Version and OS Patch level in Android.java**

Now compile this project in Android Studio, then decompile it. In the first smali folder you should have com/android/internal/util/framework with a lot of obfuscated files.

To compile the project, you have to use [modified android.jar](https://github.com/Reginer/aosp-android-jar) for the SystemProperties class

Copy all those files to any smali folder in your framework.jar, I used smali_classes6. 

After this, compile and zipalign your framework.jar, push it to your system and reboot.

## Troubleshooting

If you are not passing neither DEVICE nor STRONG, verify that:

- Your fingerprint is not banned

- Your keybox is not banned

- You set the correct OS Version

- You set the correct OS Patch Level

- You set the correct properties (look at PlayIntegrityFork in script-only mode)
