package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import org.json.JSONObject;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("id.dana")) return;

        XposedBridge.log("[DanaBypass] Loaded for id.dana");

        // 1. SecuritySignalsInfo bypass
        try {
            Class<?> ssi = XposedHelpers.findClass(
                "id.dana.telemetrysdk.model.SecuritySignalsInfo", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(ssi, "getRootDetected", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(ssi, "getHookDetected", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(ssi, "getEmulatorDetected", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(ssi, "getTamperDetected", XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] SecuritySignalsInfo hooked");
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] SSI error: " + e.getMessage());
        }

        // 2. Device.isRooted bypass
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device",
                lpparam.classLoader, "isRooted", XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] DeviceInfo hooked");
        } catch (Throwable e) {}

        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.utils.config.model.Device",
                lpparam.classLoader, "isRooted", XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] Device hooked");
        } catch (Throwable e) {}

        // 3. DexGuard bypass
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.domain.featureconfig.model.StartupConfig",
                lpparam.classLoader, "getFeatureDexguardTamperCheck",
                XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] DexGuard hooked");
        } catch (Throwable e) {}

        // 4. JSONObject.put intercept - rootDetected
        XposedHelpers.findAndHookMethod(JSONObject.class, "put",
            String.class, boolean.class, new XC_MethodReplacement() {
                @Override
                protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                    String key = (String) param.args[0];
                    if ("rootDetected".equals(key) || "hookDetected".equals(key)
                            || "tamperDetected".equals(key) || "emulatorDetected".equals(key)) {
                        param.args[1] = false;
                        XposedBridge.log("[DanaBypass] JSON " + key + " -> false");
                    }
                    return XposedBridge.invokeOriginalMethod(param.method, param.thisObject, param.args);
                }
            });
        XposedBridge.log("[DanaBypass] JSONObject hooked");

        // 5. AOMP bypass
        try {
            XposedHelpers.findAndHookMethod(
                "com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils",
                lpparam.classLoader, "isRooted", XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] All hooks applied!");
    }
}
