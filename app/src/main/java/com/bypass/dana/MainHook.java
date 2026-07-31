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

    // Semua method yang launch UnsafeDeviceActivity (dari source code analysis)
    // Format: className | methodName | DEX
    // suv inner class    | $$a(long,long) | classes.dex
    // yqg                | $$a(long,long) | classes5.dex
    // PaylaterBillDetailV2HeaderView inner | $$a(long,long) | classes5.dex
    // SelectContactBridgeBottomSheet inner | $$a(long,long) | classes2.dex
    // PlayStoreReviewActivity | aMBvRjvNlI(long,long) | classes11.dex
    // TncSummaryActivity | aueHbkmutZ(long,long) | classes3.dex
    // ErrorStateCardView inner | $$a(long,long) | classes7.dex

    private static final XC_MethodReplacement BLOCK = new XC_MethodReplacement() {
        @Override protected Object replaceHookedMethod(MethodHookParam p) {
            XposedBridge.log("[DanaBypass] BLOCKED: " + p.method.getDeclaringClass().getSimpleName() + "." + p.method.getName());
            return null;
        }
    };

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] START v11");

        // === LAYER 1: Block semua startActivity ke UnsafeDeviceActivity ===
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
                if (isUnsafeIntent((android.content.Intent)param.args[0])) { XposedBridge.log("[DanaBypass] ContextImpl BLOCKED!"); param.setResult(null); }
            }
        }); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.content.ContextWrapper", lpparam.classLoader, "startActivity", android.content.Intent.class, unsafeBlocker); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.app.Activity", lpparam.classLoader, "startActivity", android.content.Intent.class, unsafeBlocker); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("android.app.Application", lpparam.classLoader, "startActivity", android.content.Intent.class, unsafeBlocker); } catch (Throwable e) {}
        XposedBridge.log("[DanaBypass] startActivity hooks OK");

        // === LAYER 2: Block UnsafeDeviceActivity.onCreate (backup) ===
        try {
            XposedHelpers.findAndHookMethod("id.dana.onboarding.unsafe.UnsafeDeviceActivity", lpparam.classLoader, "onCreate", android.os.Bundle.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] UnsafeDevice.onCreate BLOCKED");
                        try { ((android.app.Activity)param.thisObject).finish(); } catch (Throwable e) {}
                        return null;
                    }
                });
        } catch (Throwable e) {}

        // === LAYER 3: Block SEMUA method yang trigger UnsafeDeviceActivity ===
        // Dari source code analysis - 7 entry points lengkap:

        // 1. TncSummaryActivity.aueHbkmutZ - classes3.dex (PALING PENTING untuk registrasi)
        blockMethod("id.dana.tncsummary.TncSummaryActivity", "aueHbkmutZ", lpparam);

        // 2. PlayStoreReviewActivity.aMBvRjvNlI - classes11.dex
        blockMethod("id.dana.playstorereview.PlayStoreReviewActivity", "aMBvRjvNlI", lpparam);

        // 3. suv inner class $$a - classes.dex
        blockInnerClass$$a("defpackage.suv", lpparam);

        // 4. SelectContactBridgeBottomSheet inner class $$a - classes2.dex
        blockInnerClass$$a("id.dana.contactbridge.SelectContactBridgeBottomSheet", lpparam);

        // 5. yqg $$a - classes5.dex (via ClassLoader watcher karena split APK)
        // 6. PaylaterBillDetailV2HeaderView inner $$a - classes5.dex
        // 7. ErrorStateCardView inner $$a - classes7.dex
        // → ditangani ClassLoader watcher di bawah

        // === LAYER 4: RC - hook KEDUA method ===
        // finish() tidak stop execution! Urutan: initComponent() → init() → configToolbar()
        // Kita hook keduanya: initComponent setResult+finish, init() skip OOM
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
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] RC.initComponent err: " + e.getMessage()); }

        // RC.init() - dipanggil SETELAH initComponent(), finish() belum stop execution
        // Tanpa hook ini → OOM di init() → crash
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "init",
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] RC.init → skip!");
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] RC.init hooked!");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] RC.init err: " + e.getMessage()); }

        // RC.onResume() - punya anti-tamper (throws Throwable)
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "onResume",
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] RC.onResume → skip!");
                        return null; // RC sudah finishing, tidak perlu lifecycle lanjut
                    }
                });
            XposedBridge.log("[DanaBypass] RC.onResume hooked!");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] RC.onResume err: " + e.getMessage()); }

        // RC.onPause() - juga punya anti-tamper (319 instructions)
        try {
            XposedHelpers.findAndHookMethod("id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "onPause",
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] RC.onPause → skip!");
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] RC.onPause hooked!");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] RC.onPause err: " + e.getMessage()); }
        try { hookScanAttackDirect(lpparam.classLoader.loadClass("com.alipay.alipaysecuritysdk.apdid.attack.x.ScanAttack")); } catch (Throwable e) {}

        // === LAYER 6: SecuritySignalsInfo ===
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

        // === LAYER 7: isRooted checks ===
        hookFalse("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hookFalse("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hookFalse("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hookFalse("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);
        hookFalse("com.google.firebase.crashlytics.internal.common.CommonUtils", "isRooted", lpparam);

        // === LAYER 8: SSL Pinning ===
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

        // === LAYER 9: JSON & misc ===
        XC_MethodHook jsonHook = new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                if (!(param.args[0] instanceof String)) return;
                String key = (String) param.args[0];
                for (String rk : ROOT_KEYS) if (rk.equals(key)) { param.args[1] = false; break; }
            }
        };
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, boolean.class, jsonHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("org.json.JSONObject", lpparam.classLoader, "put", String.class, Object.class, jsonHook); } catch (Throwable e) {}
        try { XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader, "exit", int.class, new XC_MethodHook() { @Override protected void beforeHookedMethod(MethodHookParam p) { p.setResult(null); } }); } catch (Throwable e) {}

        // === ClassLoader watcher untuk split APK (classes5, classes7, classes11) ===
        XC_MethodHook watcherHook = new XC_MethodHook() {
            @Override protected void afterHookedMethod(MethodHookParam param) {
                try {
                    String name = (String) param.args[0];
                    Object result = param.getResult();
                    if (!(result instanceof Class) || hooked.contains(name)) return;
                    Class<?> cls = (Class<?>) result;
                    switch (name) {
                        // Split APK detection triggers
                        case "defpackage.yqg":
                            blockInnerClass$$aDirect(cls); hooked.add(name); break;
                        case "id.dana.cashier.view.PaylaterBillDetailV2HeaderView":
                            blockInnerClass$$aDirect(cls); hooked.add(name); break;
                        case "id.dana.wallet_v3.view.walletcardview.ErrorStateCardView":
                            blockInnerClass$$aDirect(cls); hooked.add(name); break;
                        // Telemetry
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

        XposedBridge.log("[DanaBypass] ALL DONE! v11");
    }

    // Block method bernama tertentu di outer class
    private void blockMethod(String className, String methodName, XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(className, lpparam.classLoader, methodName, long.class, long.class, BLOCK);
            XposedBridge.log("[DanaBypass] " + className.substring(className.lastIndexOf('.')+1) + "." + methodName + " BLOCKED!");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] " + methodName + " err: " + e.getMessage()); }
    }

    // Block $$a di semua inner class dari suatu outer class
    private void blockInnerClass$$a(String outerClass, XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> outer = lpparam.classLoader.loadClass(outerClass);
            blockInnerClass$$aDirect(outer);
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] " + outerClass + " inner err: " + e.getMessage()); }
    }

    private static void blockInnerClass$$aDirect(Class<?> outer) {
        for (Class<?> inner : outer.getDeclaredClasses()) {
            try {
                Method ma = inner.getDeclaredMethod("$$a", long.class, long.class);
                XposedBridge.hookMethod(ma, BLOCK);
                XposedBridge.log("[DanaBypass] " + outer.getSimpleName() + "$" + inner.getSimpleName() + ".$$a BLOCKED!");
            } catch (Throwable e) {}
        }
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
        for (Method m : cls.getDeclaredMethods()) {
            if (m.getReturnType() == void.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, new XC_MethodReplacement() { @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; } }); } catch (Throwable e) {}
            else if (m.getReturnType() == Boolean.class && m.getParameterTypes().length == 0)
                try { XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Boolean.FALSE)); } catch (Throwable e) {}
        }
        XposedBridge.log("[DanaBypass] bglz hooked");
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
