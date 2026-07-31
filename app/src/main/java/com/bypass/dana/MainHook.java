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

        // SSL PINNING - hanya bypass check, jangan block connection setup!
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

        // FIX: UrlTransport - panggil original tapi ignore SSL exception
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
                            // Panggil original
                            XposedBridge.invokeOriginalMethod(
                                param.method, param.thisObject, param.args);
                        } catch (Throwable e) {
                            // Ignore SSL/cert errors saja
                            String msg = e.getMessage();
                            if (msg != null && (msg.contains("pinning") ||
                                msg.contains("certificate") || msg.contains("SSL"))) {
                                XposedBridge.log("[DanaBypass] SSL cert ignored");
                            } else {
                                throw e;
                            }
                        }
                        param.setResult(null);
                    }
                });
            XposedBridge.log("[DanaBypass] UrlTransport fixed!");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] UrlTransport: " + e.getMessage());
        }

        // RISK CHALLENGE
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "init",
                new XC_MethodReplacement() {
                    @Override protected Object replaceHookedMethod(MethodHookParam p) {
                        XposedBridge.log("[DanaBypass] RC.init BLOCKED!");
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] RiskChallenge blocked!");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] RC: " + e.getMessage());
        }

        // JSON rootDetected
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
                        }
                    }
                });
            XposedBridge.log("[DanaBypass] JSONObject hooked");
        } catch (Throwable e) {}

        // OOM block
        try {
            XposedHelpers.findAndHookMethod("dalvik.system.VMRuntime",
                lpparam.classLoader, "newNonMovableArray",
                Class.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if ((int) param.args[1] > 100000000) param.args[1] = 1;
                    }
                });
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
