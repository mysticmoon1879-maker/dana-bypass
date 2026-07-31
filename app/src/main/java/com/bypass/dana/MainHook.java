package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] START");

        // ROOT DETECTION
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hookFalse("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);
        hookFalse("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hookFalse("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hookFalse("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hookFalse("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);
        hookFalse("com.google.firebase.crashlytics.internal.common.CommonUtils", "isRooted", lpparam);

        // SSL PINNING
        hookVoid("com.alipay.imobile.network.sslpinning.SSLPinningManager", "validateCertificates", lpparam);
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.NetworkSecurityTrustManager",
                lpparam.classLoader, "checkPins", java.util.List.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; }
                });
        } catch (Throwable e) {}
        try {
            XposedHelpers.findAndHookMethod(
                "android.security.net.config.RootTrustManager",
                lpparam.classLoader, "checkServerTrusted",
                java.security.cert.X509Certificate[].class, String.class, java.net.Socket.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; }
                });
        } catch (Throwable e) {}
        try {
            XposedHelpers.findAndHookMethod(
                "com.android.okhttp.CertificatePinner",
                lpparam.classLoader, "check",
                String.class, java.util.List.class,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; }
                });
        } catch (Throwable e) {}

        // UrlTransport - call original, ignore SSL errors only
        try {
            Class<?> reqClass = XposedHelpers.findClass(
                "com.alipay.imobile.network.quake.Request", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(
                "com.alipay.imobile.network.quake.transport.http.UrlTransport",
                lpparam.classLoader, "a",
                java.net.HttpURLConnection.class, reqClass,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            XposedBridge.invokeOriginalMethod(param.method, param.thisObject, param.args);
                        } catch (Throwable e) {
                            String msg = e.getMessage() != null ? e.getMessage() : "";
                            if (msg.contains("pinning") || msg.contains("certificate") || msg.contains("SSL")) {
                                XposedBridge.log("[DanaBypass] SSL ignored");
                            } else {
                                throw e;
                            }
                        }
                        param.setResult(null);
                    }
                });
            XposedBridge.log("[DanaBypass] UrlTransport OK");
        } catch (Throwable e) {}

        // RISK CHALLENGE - biarkan RC.init JALAN (agar Akamai challenge selesai)
        // Hanya tangkap crash jika terjadi
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "init",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // Biarkan jalan normal - jangan di-block!
                        XposedBridge.log("[DanaBypass] RC.init running normally...");
                    }
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        XposedBridge.log("[DanaBypass] RC.init completed!");
                    }
                });
            XposedBridge.log("[DanaBypass] RiskChallenge monitored (not blocked)");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] RC: " + e.getMessage());
        }

        // OOM block - hanya untuk alokasi tidak wajar
        try {
            XposedHelpers.findAndHookMethod("dalvik.system.VMRuntime",
                lpparam.classLoader, "newNonMovableArray",
                Class.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if ((int) param.args[1] > 100000000) {
                            XposedBridge.log("[DanaBypass] OOM blocked!");
                            param.args[1] = 1;
                        }
                    }
                });
        } catch (Throwable e) {}

        // JSON rootDetected intercept
        try {
            XposedHelpers.findAndHookMethod(
                "org.json.JSONObject", lpparam.classLoader,
                "put", String.class, boolean.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String key = (String) param.args[0];
                        if ("rootDetected".equals(key) || "hookDetected".equals(key)
                                || "tamperDetected".equals(key) || "emulatorDetected".equals(key)) {
                            param.args[1] = false;
                            XposedBridge.log("[DanaBypass] " + key + " -> false");
                        }
                    }
                });
            XposedBridge.log("[DanaBypass] JSONObject hooked");
        } catch (Throwable e) {}

        // Block exit
        try {
            XposedHelpers.findAndHookMethod("java.lang.System",
                lpparam.classLoader, "exit", int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] exit blocked!");
                        param.setResult(null);
                    }
                });
        } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] ALL DONE!");
    }

    private void hookFalse(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try {
            XposedHelpers.findAndHookMethod(cls, l.classLoader, method,
                XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] " + method + " OK");
        } catch (Throwable e) {}
    }

    private void hookVoid(String cls, String method, XC_LoadPackage.LoadPackageParam l) {
        try {
            XposedHelpers.findAndHookMethod(cls, l.classLoader, method,
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam p) { return null; }
                });
        } catch (Throwable e) {}
    }
}
