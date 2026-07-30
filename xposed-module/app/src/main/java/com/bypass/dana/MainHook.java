package com.bypass.dana;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals("id.dana")) return;
        XposedBridge.log("[DanaBypass] Loaded!");

        // 1. SecuritySignalsInfo
        try {
            Class<?> ssi = XposedHelpers.findClass(
                "id.dana.telemetrysdk.model.SecuritySignalsInfo", lpparam.classLoader);
            XposedHelpers.findAndHookMethod(ssi, "getRootDetected", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(ssi, "getHookDetected", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(ssi, "getEmulatorDetected", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(ssi, "getTamperDetected", XC_MethodReplacement.returnConstant(false));
            XposedBridge.log("[DanaBypass] SSI hooked");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] SSI: " + e); }

        // 2. DeviceInfo
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device",
                lpparam.classLoader, "isRooted", XC_MethodReplacement.returnConstant(false));
            XposedHelpers.findAndHookMethod(
                "id.dana.lib.gcontainer.app.bridge.deviceinfo.DeviceInfo$Device",
                lpparam.classLoader, "getIsRooted", XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 3. Device model
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.utils.config.model.Device",
                lpparam.classLoader, "isRooted", XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 4. StartupConfig DexGuard
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.domain.featureconfig.model.StartupConfig",
                lpparam.classLoader, "getFeatureDexguardTamperCheck",
                XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 5. AOMPDeviceUtils
        try {
            XposedHelpers.findAndHookMethod(
                "com.alibaba.ariver.commonability.core.util.AOMPDeviceUtils",
                lpparam.classLoader, "isRooted", XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 6. Blueberry (Tencent SDK)
        try {
            XposedHelpers.findAndHookMethod(
                "com.tencent.turingfd.sdk.antibot_oversea.Blueberry",
                lpparam.classLoader, "a",
                android.content.Context.class,
                XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 7. Firebase CommonUtils
        try {
            XposedHelpers.findAndHookMethod(
                "com.google.firebase.crashlytics.internal.common.CommonUtils",
                lpparam.classLoader, "isRooted",
                android.content.Context.class,
                XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 8. DeviceUtil
        try {
            XposedHelpers.findAndHookMethod(
                "id.dana.lib.gcontainer.util.DeviceUtil",
                lpparam.classLoader, "isRooted",
                android.content.Context.class,
                XC_MethodReplacement.returnConstant(false));
        } catch (Throwable e) {}

        // 9. JSONObject.put - intercept rootDetected (CRITICAL!)
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
                            XposedBridge.log("[DanaBypass] JSON " + key + " -> false");
                        }
                    }
                });
            XposedBridge.log("[DanaBypass] JSONObject hooked");
        } catch (Throwable e) { XposedBridge.log("[DanaBypass] JSON: " + e); }

        // 10. bglb.b - PALING KRITIS! Kirim rootDetected ke server
        // Hook dengan lazy loading karena class load belakangan
        hookBglbLazy(lpparam.classLoader);

        // 11. System.exit block
        try {
            XposedHelpers.findAndHookMethod("java.lang.System", lpparam.classLoader,
                "exit", int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        XposedBridge.log("[DanaBypass] System.exit blocked!");
                        param.setResult(null);
                    }
                });
        } catch (Throwable e) {}

        XposedBridge.log("[DanaBypass] All hooks applied!");
    }

    private void hookBglbLazy(final ClassLoader classLoader) {
        // Hook ClassLoader untuk detect saat bglb di-load
        try {
            XposedHelpers.findAndHookMethod(
                ClassLoader.class, "loadClass", String.class,
                new XC_MethodHook() {
                    private boolean bglbHooked = false;
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (bglbHooked) return;
                        String name = (String) param.args[0];
                        if ("defpackage.bglb".equals(name)) {
                            bglbHooked = true;
                            try {
                                Class<?> bglb = (Class<?>) param.getResult();
                                if (bglb != null) hookBglb(bglb, classLoader);
                            } catch (Throwable e) {
                                XposedBridge.log("[DanaBypass] bglb hook error: " + e);
                            }
                        }
                    }
                });
        } catch (Throwable e) {
            // Fallback: langsung hook jika class sudah ada
            try {
                Class<?> bglb = XposedHelpers.findClass("defpackage.bglb", classLoader);
                hookBglb(bglb, classLoader);
            } catch (Throwable e2) {
                XposedBridge.log("[DanaBypass] bglb not found yet: " + e2);
            }
        }
    }

    private void hookBglb(Class<?> bglb, ClassLoader classLoader) {
        try {
            // Cari method b yang terima InitRequest
            java.lang.reflect.Method[] methods = bglb.getDeclaredMethods();
            for (java.lang.reflect.Method m : methods) {
                if (m.getName().equals("b") && m.getParameterTypes().length == 1) {
                    XposedBridge.hookMethod(m, new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            try {
                                org.json.JSONObject json = (org.json.JSONObject) param.getResult();
                                if (json != null) {
                                    json.put("rootDetected", false);
                                    json.put("hookDetected", false);
                                    json.put("emulatorDetected", false);
                                    json.put("tamperDetected", false);
                                    XposedBridge.log("[DanaBypass] bglb.b -> root=false!");
                                }
                            } catch (Throwable e) {
                                XposedBridge.log("[DanaBypass] bglb post: " + e);
                            }
                        }
                    });
                    XposedBridge.log("[DanaBypass] bglb.b HOOKED!");
                    break;
                }
            }
        } catch (Throwable e) {
            XposedBridge.log("[DanaBypass] bglb hook: " + e);
        }
    }
}
