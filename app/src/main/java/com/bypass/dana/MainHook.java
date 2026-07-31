package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String[] ROOT_KEYS = {
        "rootDetected","hookDetected","tamperDetected","emulatorDetected","isRooted","jailbroken"
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] START");

        // === SUMBER ROOT DETECTION YANG BENAR ===
        // bglq.w() = rootDetected, bglq.x() = emulatorDetected
        hookAllBoolean("defpackage.bglq", lpparam);

        // bglz.g() = hookDetected, bglz.f() = tamperDetected
        hookAllBoolean("defpackage.bglz", lpparam);

        // atnv.isRooted() = DeviceInfo.isRooted
        hookFalse("defpackage.atnv", "isRooted", lpparam);

        // SecuritySignalsInfo (backup)
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);

        // Device model
        hookFalse("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hookFalse("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hookFalse("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hookFalse("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);
        hookFalse("com.google.firebase.crashlytics.internal.common.CommonUtils", "isRooted", lpparam);

        // SSL PINNING
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

        // RISK CHALLENGE - suppress OOM
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity", lpparam.classLoader, "init", new XC_MethodHook() {
                @Override protected void beforeHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] RC.init..."); }
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (param.hasThrowable()) {
                        Throwable t = param.getThrowable();
                        if (t instanceof OutOfMemoryError || t instanceof ArrayIndexOutOfBoundsException || t instanceof NullPointerException) {
                            XposedBridge.log("[DanaBypass] RC.init " + t.getClass().getSimpleName() + " SUPPRESSED!");
                            param.setResult(null);
                        }
                    } else { XposedBridge.log("[DanaBypass] RC.init OK"); }
                }
            });
        } catch (Throwable e) {}

        // JSONObject intercept - semua overload
        XC_MethodHook jsonHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (!(param.args[0] instanceof String)) return;
                String key = (String) param.args[0];
                for (String rk : ROOT_KEYS) {
                    if (rk.equals(key)) {
                        param.args[1] = false;
                        XposedBridge.log("[DanaBypass] JSON " + key + "->false");
                        break;
                    }
                }
            }
        };
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, boolean.class, jsonHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, Object.class, jsonHook); } catch (Throwable e) {}

        // bglb lazy hook
        hookBglbLazy(lpparam);

        // Block exit
        try { XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader, "exit", int.class, new XC_MethodHook() { @Override protected void beforeHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] exit blocked"); p.setResult(null); } }); } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] ALL DONE!");
    }

    // Hook semua method boolean di class obfuscated
    private void hookAllBoolean(String cls, XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, lpparam.classLoader);
            java.lang.reflect.Method[] methods = c.getDeclaredMethods();
            int count = 0;
            for (java.lang.reflect.Method m : methods) {
                if (m.getReturnType() == boolean.class && m.getParameterTypes().length == 0) {
                    try {
                        XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false));
                        count++;
                    } catch (Throwable e) {}
                }
            }
            XposedBridge.log("[DanaBypass] " + cls + " -> " + count + " boolean methods hooked");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] " + cls + " not found: " + e.getMessage());
        }
    }

    private void hookBglbLazy(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (tryHookBglb(lpparam)) return;
        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, new XC_MethodHook() {
                private boolean done = false;
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    if (done) return;
                    if ("defpackage.bglb".equals(param.args[0])) { done = true; tryHookBglb(lpparam); }
                }
            });
        } catch (Throwable e) {}
    }

    private boolean tryHookBglb(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> bglb = XposedHelpers.findClass("defpackage.bglb", lpparam.classLoader);
            for (java.lang.reflect.Method m : bglb.getDeclaredMethods()) {
                if (m.getName().equals("b") && m.getParameterTypes().length == 1) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object r = param.getResult();
                                if (r instanceof org.json.JSONObject) {
                                    org.json.JSONObject j = (org.json.JSONObject) r;
                                    for (String key : ROOT_KEYS) { try { j.put(key, false); } catch (Throwable e) {} }
                                    XposedBridge.log("[DanaBypass] bglb.b -> all false!");
                                }
                            } catch (Throwable e) {}
                        }
                    });
                    XposedBridge.log("[DanaBypass] bglb.b HOOKED!");
                    return true;
                }
            }
        } catch (Throwable e) {}
        return false;
    }

    private void hookFalse(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, XC_MethodReplacement.returnConstant(false)); XposedBridge.log("[DanaBypass] " + cls.substring(cls.lastIndexOf('.')+1) + "." + method + " OK"); } catch (Throwable e) {}
    }

    private void hookVoid(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
    }
}
