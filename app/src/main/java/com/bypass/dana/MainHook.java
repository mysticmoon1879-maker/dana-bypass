package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import android.os.Bundle;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] Hooked id.dana!");

        // Root detection bypass
        hook("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getRootDetected", lpparam);
        hook("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getHookDetected", lpparam);
        hook("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getEmulatorDetected", lpparam);
        hook("id.dana.telemetrysdk.model.SecuritySignalsInfo", "getTamperDetected", lpparam);
        hook("id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device", "isRooted", lpparam);
        hook("id.dana.utils.config.model.Device", "isRooted", lpparam);
        hook("id.dana.domain.featureconfig.model.StartupConfig", "getFeatureDexguardTamperCheck", lpparam);
        hook("com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils", "isRooted", lpparam);

        // JSONObject intercept
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
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] JSONObject: " + e.getMessage());
        }

        // RiskChallengeActivity.init - block OOM/anti-tamper
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.riskChallenges.ui.RiskChallengeActivity",
                lpparam.classLoader, "init",
                new XC_MethodReplacement() {
                    @Override
                    protected Object replaceHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] RiskChallengeActivity.init BLOCKED!");
                        return null;
                    }
                });
            XposedBridge.log("[DanaBypass] RiskChallengeActivity.init blocked!");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] RC.init: " + e.getMessage());
        }

        // Block System.exit
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader,
                "exit", int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] exit blocked!");
                        param.setResult(null);
                    }
                });
        } catch (Throwable e) {}

        // OOM block
        try {
            XposedHelpers.findAndHookMethod("dalvik.system.VMRuntime",
                lpparam.classLoader, "newNonMovableArray",
                Class.class, int.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        int size = (int) param.args[1];
                        if (size > 100000000) {
                            param.args[1] = 1;
                            XposedBridge.log("[DanaBypass] OOM blocked!");
                        }
                    }
                });
        } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] All done!");
    }

    private void hook(String className, String method, XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(className, lpparam.classLoader,
                method, XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] " + method + " OK");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] " + method + " skip: " + e.getMessage());
        }
    }
}
