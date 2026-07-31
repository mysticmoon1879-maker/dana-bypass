package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.lang.reflect.Method;

public class MainHook implements IXposedHookLoadPackage {

    private static final String[] ROOT_KEYS = {
        "rootDetected","hookDetected","tamperDetected","emulatorDetected","isRooted","jailbroken"
    };
    private XC_LoadPackage.LoadPackageParam lp;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        this.lp = lpparam;
        XposedBridge.log("[DanaBypass] START");

        // Standard root detection
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);
        hookFalse("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hookFalse("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hookFalse("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hookFalse("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);
        hookFalse("com.google.firebase.crashlytics.internal.common.CommonUtils", "isRooted", lpparam);

        // Hook bglq (isRooted source)
        hookBglq(lpparam);

        // KRITIS: Hook bglz SETTERS agar flag tidak ter-set true
        hookBglzSetters(lpparam);

        // KRITIS: Hook bglz GETTERS (return Boolean nullable, bukan boolean)
        hookBglzGetters(lpparam);

        // Hook ScanAttack
        hookScanAttack(lpparam);

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

        // KRITIS: Hook bgls.b() - entry point yang set semua flags
        try {
            Class<?> bgls = XposedHelpers.findClass("defpackage.bgls", lpparam.classLoader);
            for (Method m : bgls.getDeclaredMethods()) {
                if (m.getName().equals("b") && m.getParameterTypes().length >= 5) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override protected void beforeHookedMethod(MethodHookParam param) {
                            // Set semua Boolean params ke null/false agar tidak trigger bglz setters
                            for (int i = 0; i < param.args.length; i++) {
                                if (param.args[i] instanceof Boolean) {
                                    param.args[i] = Boolean.FALSE;
                                }
                            }
                            XposedBridge.log("[DanaBypass] bgls.b -> all false!");
                        }
                    });
                    XposedBridge.log("[DanaBypass] bgls.b hooked!");
                    break;
                }
            }
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] bgls: " + e.getMessage()); }

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

        // bglb lazy hook
        hookBglbLazy(lpparam);

        // Block exit
        try { XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader, "exit", int.class, new XC_MethodHook() { @Override protected void beforeHookedMethod(MethodHookParam p) { XposedBridge.log("[DanaBypass] exit blocked"); p.setResult(null); } }); } catch (Throwable e) {}

        // ClassLoader watcher
        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, new XC_MethodHook() {
                @Override protected void afterHookedMethod(MethodHookParam param) {
                    String name = (String) param.args[0];
                    if ("defpackage.bglq".equals(name)) hookBglq(lp);
                    if ("defpackage.bglz".equals(name)) { hookBglzSetters(lp); hookBglzGetters(lp); }
                    if ("defpackage.bglb".equals(name)) hookBglbLazy(lp);
                    if ("defpackage.bgls".equals(name)) {
                        try {
                            Class<?> bgls = XposedHelpers.findClass("defpackage.bgls", lp.classLoader);
                            for (Method m : bgls.getDeclaredMethods()) {
                                if (m.getName().equals("b") && m.getParameterTypes().length >= 5) {
                                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                                        @Override protected void beforeHookedMethod(MethodHookParam p) {
                                            for (int i = 0; i < p.args.length; i++) if (p.args[i] instanceof Boolean) p.args[i] = Boolean.FALSE;
                                            XposedBridge.log("[DanaBypass] bgls.b -> false (lazy)");
                                        }
                                    });
                                    break;
                                }
                            }
                        } catch (Throwable e) {}
                    }
                    if ("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack".equals(name)) hookScanAttack(lp);
                }
            });
            XposedBridge.log("[DanaBypass] ClassLoader watcher OK");
        } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] ALL DONE!");
    }

    private void hookBglq(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> c = XposedHelpers.findClass("defpackage.bglq", lpparam.classLoader);
            int count = 0;
            for (Method m : c.getDeclaredMethods()) {
                // Hook method w() - rootDetected, x() - emulatorDetected, y() - isRooted
                if (m.getReturnType() == boolean.class && m.getParameterTypes().length == 0) {
                    try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false)); count++; } catch (Throwable e) {}
                }
            }
            XposedBridge.log("[DanaBypass] bglq hooked: " + count + " methods");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] bglq: " + e.getMessage()); }
    }

    private void hookBglzSetters(XC_LoadPackage.LoadPackageParam lpparam) {
        // Hook void methods h,g,f,j,i yang SET flags ke true
        try {
            Class<?> c = XposedHelpers.findClass("defpackage.bglz", lpparam.classLoader);
            int count = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (m.getReturnType() == void.class && m.getParameterTypes().length == 0) {
                    try {
                        XposedBridge.hookMethod(m, new XC_MethodReplacement() {
                            @Override protected Object replaceHookedMethod(MethodHookParam p) {
                                XposedBridge.log("[DanaBypass] bglz." + p.method.getName() + "() BLOCKED");
                                return null;
                            }
                        });
                        count++;
                    } catch (Throwable e) {}
                }
            }
            XposedBridge.log("[DanaBypass] bglz setters blocked: " + count);
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] bglzSetters: " + e.getMessage()); }
    }

    private void hookBglzGetters(XC_LoadPackage.LoadPackageParam lpparam) {
        // Hook Boolean (boxed) getters c,a,d,b,e - return Boolean.FALSE
        try {
            Class<?> c = XposedHelpers.findClass("defpackage.bglz", lpparam.classLoader);
            int count = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (m.getReturnType() == Boolean.class && m.getParameterTypes().length == 0) {
                    try {
                        XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Boolean.FALSE));
                        count++;
                    } catch (Throwable e) {}
                }
            }
            XposedBridge.log("[DanaBypass] bglz getters: " + count + " hooked");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] bglzGetters: " + e.getMessage()); }
    }

    private void hookScanAttack(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> atk = XposedHelpers.findClass("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack", lpparam.classLoader);
            int count = 0;
            for (Method m : atk.getDeclaredMethods()) {
                Class<?> ret = m.getReturnType();
                String name = m.getName();
                try {
                    if (ret == boolean.class) {
                        // xp1,xp2,xp5,xp6,cy1,cy2,cy3 -> false
                        XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(false));
                        count++;
                    } else if (ret == String.class) {
                        // xp3,xp4 -> null, vir1 -> return path without "^^^"
                        if ("vir1".equals(name)) {
                            XposedBridge.hookMethod(m, new XC_MethodReplacement() {
                                @Override protected Object replaceHookedMethod(MethodHookParam p) {
                                    // Return context filesDir path tanpa prefix "^^^"
                                    try {
                                        android.content.Context ctx = (android.content.Context) p.args[0];
                                        return ctx.getFilesDir().getAbsolutePath();
                                    } catch (Throwable e) { return "/data/data/id.dana/files"; }
                                }
                            });
                        } else {
                            XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(null));
                        }
                        count++;
                    } else if (name.equals("methodToNative")) {
                        XposedBridge.hookMethod(m, new XC_MethodReplacement() {
                            @Override protected Object replaceHookedMethod(MethodHookParam p) {
                                return new org.json.JSONArray();
                            }
                        });
                        count++;
                    }
                } catch (Throwable e) {}
            }
            XposedBridge.log("[DanaBypass] ScanAttack HOOKED: " + count + " methods");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] ScanAttack: " + e.getMessage()); }
    }

    private void hookBglbLazy(final XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> bglb = XposedHelpers.findClass("defpackage.bglb", lpparam.classLoader);
            for (Method m : bglb.getDeclaredMethods()) {
                if (m.getName().equals("b") && m.getParameterTypes().length == 1) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                Object r = param.getResult();
                                if (r instanceof org.json.JSONObject) {
                                    org.json.JSONObject j = (org.json.JSONObject) r;
                                    for (String k : ROOT_KEYS) { try { j.put(k, false); } catch (Throwable e) {} }
                                    XposedBridge.log("[DanaBypass] bglb.b -> all false!");
                                }
                            } catch (Throwable e) {}
                        }
                    });
                    XposedBridge.log("[DanaBypass] bglb.b HOOKED!");
                    return;
                }
            }
        } catch (Throwable e) {}
    }

    private void hookFalse(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, XC_MethodReplacement.returnConstant(false)); XposedBridge.log("[DanaBypass] " + cls.substring(cls.lastIndexOf('.')+1) + "." + method + " OK"); } catch (Throwable e) {}
    }
    private void hookVoid(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try { XposedHelpers.findAndHookMethod(cls, l.classLoader, method, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
    }
}
