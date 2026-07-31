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

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] START v8");

        // =========================================
        // KUNCI UTAMA: Block UnsafeDeviceActivity!
        // Hook startActivity untuk cegah launch sama sekali
        // =========================================

        // 1. Hook Activity.startActivity(Intent)
        try {
            XposedHelpers.findAndHookMethod(
                "android.app.Activity", lpparam.classLoader,
                "startActivity", android.content.Intent.class,
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        android.content.Intent intent = (android.content.Intent) param.args[0];
                        if (intent != null) {
                            android.content.ComponentName cn = intent.getComponent();
                            if (cn != null && cn.getClassName().contains("UnsafeDevice")) {
                                XposedBridge.log("[DanaBypass] startActivity UnsafeDevice BLOCKED!");
                                param.setResult(null);
                            }
                        }
                    }
                });
            XposedBridge.log("[DanaBypass] startActivity watcher OK ✅");
        } catch (Throwable e) {}

        // 2. Hook Context.startActivity juga
        try {
            XposedHelpers.findAndHookMethod(
                "android.content.ContextWrapper", lpparam.classLoader,
                "startActivity", android.content.Intent.class,
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        android.content.Intent intent = (android.content.Intent) param.args[0];
                        if (intent != null) {
                            android.content.ComponentName cn = intent.getComponent();
                            if (cn != null && cn.getClassName().contains("UnsafeDevice")) {
                                XposedBridge.log("[DanaBypass] Context.startActivity UnsafeDevice BLOCKED!");
                                param.setResult(null);
                            }
                        }
                    }
                });
        } catch (Throwable e) {}

        // 3. Backup: Hook onCreate dan langsung finish TANPA call original
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.onboarding.unsafe.UnsafeDeviceActivity",
                lpparam.classLoader, "onCreate",
                android.os.Bundle.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] UnsafeDeviceActivity.onCreate REPLACED!");
                        try {
                            // Hanya call Activity.onCreate (super paling atas)
                            XposedHelpers.callMethod(param.thisObject, "finish");
                        } catch (Throwable e) {}
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] UnsafeDeviceActivity.onCreate BLOCKED! ✅");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] UnsafeDevice: " + e.getMessage());
        }

        // ScanAttack - di classes3.dex
        try {
            Class<?> sa = XposedHelpers.findClass(
                "com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack", lpparam.classLoader);
            hookScanAttackDirect(sa);
        } catch (Throwable e) {}

        // SecuritySignalsInfo getter hooks
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);

        // SecuritySignalsInfo constructor
        try {
            XposedHelpers.findAndHookConstructor(
                "id.dana.telemetrysdk.model.SecuritySignalsInfo",
                lpparam.classLoader,
                boolean.class, boolean.class, boolean.class, boolean.class,
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam param) {
                        param.args[0] = false;
                        param.args[1] = false;
                        param.args[2] = false;
                        param.args[3] = false;
                        XposedBridge.log("[DanaBypass] SSI constructor -> all false!");
                    }
                });
        } catch (Throwable e) {}

        // Device isRooted
        hookFalse("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hookFalse("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hookFalse("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hookFalse("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);
        hookFalse("com.google.firebase.crashlytics.internal.common.CommonUtils", "isRooted", lpparam);

        // SSL Pinning
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

        // RC OOM suppress
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity", lpparam.classLoader, "init", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] RC.init..."); }
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable()) {
                        Throwable t = param.getThrowable();
                        if (t instanceof OutOfMemoryError || t instanceof ArrayIndexOutOfBoundsException || t instanceof NullPointerException) {
                            XposedBridge.log("[DanaBypass] RC SUPPRESSED!");
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

        // ClassLoader watcher untuk lazy classes
        XC_MethodHook watcherHook = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                try {
                    String name = (String) param.args[0];
                    Object result = param.getResult();
                    if (!(result instanceof Class) || hooked.contains(name)) return;
                    Class<?> cls = (Class<?>) result;
                    switch (name) {
                        case "defpackage.bglq": hookBglqDirect(cls); hooked.add(name); break;
                        case "defpackage.bglz": hookBglzDirect(cls); hooked.add(name); break;
                        case "defpackage.bglb": hookBglbDirect(cls); hooked.add(name); break;
                        case "defpackage.bgls": hookBglsDirect(cls); hooked.add(name); break;
                        case "defpackage.uvc": hookUvcDirect(cls); hooked.add(name); break;
                    }
                } catch (Throwable e) {}
            }
        };
        try { XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, watcherHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, watcherHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("dalvik.system.BaseDexClassLoader", lpparam.classLoader, "findClass", String.class, watcherHook); } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] ALL DONE! v8 ✅");
    }

    private static void hookUvcDirect(Class<?> cls) {
        for (Method m : cls.getDeclaredMethods()) {
            // Block method yang call bgls.b dengan detection results
            if (m.getName().equals("d") && m.getParameterTypes().length == 1) {
                try {
                    XposedBridge.hookMethod(m, new XC_MethodReplacement() {
                        @Override protected Object replaceHookedMethod(MethodHookParam p) {
                            XposedBridge.log("[DanaBypass] uvc.d BLOCKED!");
                            return null;
                        }
                    });
                    XposedBridge.log("[DanaBypass] uvc.d hooked!");
                } catch (Throwable e) {}
            }
        }
    }

    private static void hookBglqDirect(Class<?> cls) {
        int n = 0;
        for (Method m : cls.getDeclaredMethods())
            if (m.getReturnType() == boolean.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)); n++; } catch (Throwable e) {}
        XposedBridge.log("[DanaBypass] bglq: " + n);
    }

    private static void hookBglzDirect(Class<?> cls) {
        int s = 0, g = 0;
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getReturnType() == void.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] bglz."+p.method.getName()+" BLOCKED"); return null; } }); s++; } catch (Throwable e) {}
            else if (m.getReturnType() == Boolean.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Boolean.FALSE)); g++; } catch (Throwable e) {}
        }
        XposedBridge.log("[DanaBypass] bglz s=" + s + " g=" + g);
    }

    private static void hookBglsDirect(Class<?> cls) {
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getName().equals("b") && m.getParameterTypes().length == 8) {
                try {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam p) {
                            for (int i = 1; i <= 5; i++) if (p.args[i] instanceof Boolean) p.args[i] = Boolean.FALSE;
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
                                    String[] keys = {"rootDetected","hookDetected","tamperDetected","emulatorDetected","isRooted"};
                                    for (String k : keys) try { j.put(k, false); } catch (Throwable e) {}
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
        XposedBridge.log("[DanaBypass] ScanAttack: " + n);
    }

    private void hookFalse(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, XC_MethodReplacement.returnConstant(false)); XposedBridge.log("[DanaBypass] " + cls.substring(cls.lastIndexOf('.')+1) + "." + method + " OK"); } catch (Throwable e) {}
    }
    private void hookVoid(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
    }
}
