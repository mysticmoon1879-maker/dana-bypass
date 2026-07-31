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
        XposedBridge.log("[DanaBypass] START v10");

        // Block UnsafeDeviceActivity di semua level
        XC_MethodHook unsafeBlocker = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                android.content.Intent intent = (android.content.Intent) param.args[0];
                if (isUnsafeIntent(intent)) {
                    XposedBridge.log("[DanaBypass] startActivity UnsafeDevice BLOCKED!");
                    param.setResult(null);
                }
            }
        };
        try { XposedHelpers.findAndHookMethod("android.app.ContextImpl", lpparam.classLoader, "startActivity", android.content.Intent.class, android.os.Bundle.class, new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                android.content.Intent intent = (android.content.Intent) param.args[0];
                if (isUnsafeIntent(intent)) { XposedBridge.log("[DanaBypass] ContextImpl BLOCKED!"); param.setResult(null); }
            }
        }); XposedBridge.log("[DanaBypass] ContextImpl.startActivity hooked"); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader, "startActivity", android.content.Intent.class, unsafeBlocker); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.app.Activity", lpparam.classLoader, "startActivity", android.content.Intent.class, unsafeBlocker); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.app.Application", lpparam.classLoader, "startActivity", android.content.Intent.class, unsafeBlocker); } catch (Throwable e) {}

        // UnsafeDeviceActivity backup
        try {
            XposedHelpers.findAndHookMethod("id.dana.onboarding.unsafe.UnsafeDeviceActivity", lpparam.classLoader, "onCreate", android.os.Bundle.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] UnsafeDevice.onCreate blocked");
                        try { ((android.app.Activity)param.thisObject).finish(); } catch (Throwable e) {}
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] UnsafeDevice blocked");
        } catch (Throwable e) {}

        // ROOT CAUSE FIX: TncSummaryActivity.aueHbkmutZ - method yang launch UnsafeDevice
        // saat registrasi. Setelah kita block UnsafeDevice, kode lanjut ke
        // uvc.class.getField("b") → ClassNotFoundException → CRASH karena tidak di-catch!
        // Solusi: block method ini sepenuhnya
        try {
            XposedHelpers.findAndHookMethod("id.dana.tncsummary.TncSummaryActivity",
                lpparam.classLoader, "aueHbkmutZ", long.class, long.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] TncSummary.aueHbkmutZ BLOCKED!");
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] TncSummary.aueHbkmutZ hooked!");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] TncSummary err: " + e.getMessage()); }

        // suv dan yqg inner class $$a - sama tapi di kelas lain
        // Hook semua inner class yang punya method $$a(long, long)
        try {
            Class<?> suvCls = lpparam.classLoader.loadClass("defpackage.suv");
            for (Class<?> inner : suvCls.getDeclaredClasses()) {
                try {
                    Method ma = inner.getDeclaredMethod("$$a", long.class, long.class);
                    XposedBridge.hookMethod(ma, new XC_MethodReplacement() {
                        @Override protected Object replaceHookedMethod(MethodHookParam p) {
                            XposedBridge.log("[DanaBypass] suv.$$a BLOCKED!");
                            return null;
                        }
                    });
                    XposedBridge.log("[DanaBypass] suv.$$a hooked!");
                } catch (Throwable e) {}
            }
        } catch (Throwable e) {}

        // RC initComponent - SEBELUM init() yang OOM
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "initComponent",
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] RC.initComponent → setResult(OK) + finish!");
                        try {
                            android.app.Activity rc = (android.app.Activity) param.thisObject;
                            rc.setResult(-1);
                            rc.finish();
                        } catch (Throwable e) {}
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] RC.initComponent hooked!");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] RC err: " + e.getMessage()); }

        // ScanAttack
        try { hookScanAttackDirect(lpparam.classLoader.loadClass("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack")); } catch (Throwable e) {}

        // SecuritySignalsInfo
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);
        try {
            XposedHelpers.findAndHookConstructor("id.dana.telemetrysdk.model.SecuritySignalsInfo", lpparam.classLoader,
                boolean.class, boolean.class, boolean.class, boolean.class,
                new XC_MethodHook() {
                    @Override protected void beforeHookedMethod(MethodHookParam p) {
                        p.args[0] = false; p.args[1] = false; p.args[2] = false; p.args[3] = false;
                    }
                });
        } catch (Throwable e) {}

        // Device detection
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

        // JSON
        XC_MethodHook jsonHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (!(param.args[0] instanceof String)) return;
                String key = (String) param.args[0];
                for (String rk : ROOT_KEYS) if (rk.equals(key)) { param.args[1] = false; break; }
            }
        };
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, boolean.class, jsonHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, Object.class, jsonHook); } catch (Throwable e) {}

        // Block exit
        try { XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader, "exit", int.class, new XC_MethodHook() { @Override protected void beforeHookedMethod(MethodHookParam p) { p.setResult(null); } }); } catch (Throwable e) {}

        // ClassLoader watcher
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
                    }
                } catch (Throwable e) {}
            }
        };
        try { XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, watcherHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, watcherHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("dalvik.system.BaseDexClassLoader", lpparam.classLoader, "findClass", String.class, watcherHook); } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] ALL DONE! v10");
    }

    private static boolean isUnsafeIntent(android.content.Intent intent) {
        if (intent == null) return false;
        android.content.ComponentName cn = intent.getComponent();
        return cn != null && cn.getClassName().contains("UnsafeDevice");
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
                try { XposedBridge.hookMethod(m, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); s++; } catch (Throwable e) {}
            else if (m.getReturnType() == Boolean.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Boolean.FALSE)); g++; } catch (Throwable e) {}
        }
        XposedBridge.log("[DanaBypass] bglz s=" + s + " g=" + g);
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
                                }
                            } catch (Throwable e) {}
                        }
                    });
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
