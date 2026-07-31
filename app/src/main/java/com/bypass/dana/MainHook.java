package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

public class MainHook implements IXposedHookLoadPackage {

    private static final String[] ROOT_KEYS = {
        "rootDetected","hookDetected","tamperDetected","emulatorDetected","isRooted","jailbroken"
    };

    private static final Set<String> hooked = new HashSet<>();

    private static void onClassLoaded(String name, Class<?> cls) {
        if (cls == null || hooked.contains(name)) return;
        switch (name) {
            case "defpackage.bglq": hookBglqDirect(cls); hooked.add(name); break;
            case "defpackage.bglz": hookBglzDirect(cls); hooked.add(name); break;
            case "defpackage.bgls": hookBglsDirect(cls); hooked.add(name); break;
            case "defpackage.bglb": hookBglbDirect(cls); hooked.add(name); break;
            case "com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack":
                hookScanAttackDirect(cls); hooked.add(name); break;
        }
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] START");

        // Standard hooks
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);
        hookFalse("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hookFalse("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hookFalse("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hookFalse("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);
        hookFalse("com.google.firebase.crashlytics.internal.common.CommonUtils", "isRooted", lpparam);

        // SSL
        hookVoid("com.alipay.imobile.network.sslpinning.SSLPinningManager", "validateCertificates", lpparam);
        try { XposedHelpers.findAndHookMethod("android.security.net.config.NetworkSecurityTrustManager", lpparam.classLoader, "checkPins", java.util.List.class, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.security.net.config.RootTrustManager", lpparam.classLoader, "checkServerTrusted", java.security.cert.X509Certificate[].class, String.class, java.net.Socket.class, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("com.android.okhttp.CertificatePinner", lpparam.classLoader, "check", String.class, java.util.List.class, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
        try {
            Class<?> reqClass = XposedHelpers.findClass("com.alipay.imobile.network.quake.Request", lpparam.classLoader);
            XposedHelpers.findAndHookMethod("com.alipay.imobile.network.quake.transport.http.UrlTransport", lpparam.classLoader, "a", java.net.HttpURLConnection.class, reqClass, new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    try { XposedBridge.invokeOriginalMethod(param.method, param.thisObject, param.args); }
                    catch (Throwable e) { String m = e.getMessage()!=null?e.getMessage():""; if(!m.contains("pinning")&&!m.contains("certificate")&&!m.contains("SSL")) throw e; }
                    param.setResult(null);
                }
            });
        } catch (Throwable e) {}

        // ScanAttack sudah load di startup
        try {
            Class<?> sa = lpparam.classLoader.loadClass("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack");
            hookScanAttackDirect(sa);
        } catch (Throwable e) {}

        // RC OOM suppress
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity", lpparam.classLoader, "init", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] RC.init..."); }
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable()) {
                        Throwable t = param.getThrowable();
                        if (t instanceof OutOfMemoryError || t instanceof ArrayIndexOutOfBoundsException || t instanceof NullPointerException) {
                            XposedBridge.log("[DanaBypass] RC " + t.getClass().getSimpleName() + " SUPPRESSED!");
                            param.setResult(null);
                        }
                    } else { XposedBridge.log("[DanaBypass] RC.init OK"); }
                }
            });
        } catch (Throwable e) {}

        // JSON intercept
        XC_MethodHook jsonHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (!(param.args[0] instanceof String)) return;
                String key = (String) param.args[0];
                for (String rk : ROOT_KEYS) {
                    if (rk.equals(key)) { param.args[1] = false; XposedBridge.log("[DanaBypass] JSON "+key+"->false"); break; }
                }
            }
        };
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, boolean.class, jsonHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, Object.class, jsonHook); } catch (Throwable e) {}

        // Block exit
        try { XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader, "exit", int.class, new XC_MethodHook() { @Override protected void beforeHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] exit blocked"); p.setResult(null); } }); } catch (Throwable e) {}

        // Hook KEDUA overload loadClass + findClass
        XC_MethodHook watcherHook = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                try {
                    String name = (String) param.args[0];
                    Object result = param.getResult();
                    if (result instanceof Class) {
                        onClassLoaded(name, (Class<?>) result);
                    }
                } catch (Throwable e) {}
            }
        };

        try {
            // loadClass(String)
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, watcherHook);
            // loadClass(String, boolean) - protected, internal Android call
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, watcherHook);
            XposedBridge.log("[DanaBypass] loadClass watchers OK");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] watcher err: " + e.getMessage()); }

        // Hook BaseDexClassLoader.findClass sebagai backup
        try {
            XposedHelpers.findAndHookMethod("dalvik.system.BaseDexClassLoader", lpparam.classLoader,
                "findClass", String.class, watcherHook);
            XposedBridge.log("[DanaBypass] BaseDexClassLoader.findClass OK");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] findClass: " + e.getMessage()); }

        XposedBridge.log("[DanaBypass] ALL DONE!");
    }

    private static void hookBglqDirect(Class<?> cls) {
        int n = 0;
        for (Method m : cls.getDeclaredMethods())
            if (m.getReturnType() == boolean.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)); n++; } catch (Throwable e) {}
        XposedBridge.log("[DanaBypass] bglq hooked: " + n);
    }

    private static void hookBglzDirect(Class<?> cls) {
        int s = 0, g = 0;
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getReturnType() == void.class && m.getParameterTypes().length == 0) {
                try { XposedBridge.hookMethod(m, new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam p) {
                        XposedBridge.log("[DanaBypass] bglz."+p.method.getName()+" BLOCKED"); return null;
                    }
                }); s++; } catch (Throwable e) {}
            } else if (m.getReturnType() == Boolean.class && m.getParameterTypes().length == 0) {
                try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Boolean.FALSE)); g++; } catch (Throwable e) {}
            }
        }
        XposedBridge.log("[DanaBypass] bglz setters=" + s + " getters=" + g);
    }

    private static void hookBglsDirect(Class<?> cls) {
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals("b") && m.getParameterTypes().length >= 5) {
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam p) {
                            for (int i = 0; i < p.args.length; i++) if (p.args[i] instanceof Boolean) p.args[i] = Boolean.FALSE;
                            XposedBridge.log("[DanaBypass] bgls.b -> false!");
                        }
                    });
                    XposedBridge.log("[DanaBypass] bgls.b HOOKED!");
                } catch (Throwable e) {} break;
            }
        }
    }

    private static void hookBglbDirect(Class<?> cls) {
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals("b") && m.getParameterTypes().length == 1) {
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object r = param.getResult();
                                if (r instanceof org.json.JSONObject) {
                                    org.json.JSONObject j = (org.json.JSONObject) r;
                                    for (String k : ROOT_KEYS) try { j.put(k, false); } catch (Throwable e) {}
                                    XposedBridge.log("[DanaBypass] bglb.b -> all false!");
                                }
                            } catch (Throwable e) {}
                        }
                    });
                    XposedBridge.log("[DanaBypass] bglb.b HOOKED!");
                } catch (Throwable e) {} break;
            }
        }
    }

    private static void hookScanAttackDirect(Class<?> cls) {
        if (hooked.contains("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack")) return;
        int n = 0;
        for (Method m : cls.getDeclaredMethods()) {
            Class<?> ret = m.getReturnType();
            try {
                if (ret == boolean.class) { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)); n++; }
                else if (ret == String.class) {
                    if ("vir1".equals(m.getName())) XposedBridge.hookMethod(m, new XC_MethodReplacement() {
                        @Override protected Object replaceHookedMethod(MethodHookParam p) {
                            try { return ((android.content.Context)p.args[0]).getFilesDir().getAbsolutePath(); } catch (Throwable e) { return "/data/data/id.dana/files"; }
                        }
                    });
                    else XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null));
                    n++;
                } else if ("methodToNative".equals(m.getName())) {
                    XposedBridge.hookMethod(m, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return new org.json.JSONArray(); } });
                    n++;
                }
            } catch (Throwable e) {}
        }
        hooked.add("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack");
        XposedBridge.log("[DanaBypass] ScanAttack HOOKED: " + n);
    }

    private void hookFalse(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, XC_MethodReplacement.returnConstant(false)); XposedBridge.log("[DanaBypass] " + cls.substring(cls.lastIndexOf('.')+1) + "." + method + " OK"); } catch (Throwable e) {}
    }
    private void hookVoid(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
    }
}
