// SPDX-License-Identifier: Apache-2.0
package com.mediatek.common.util;

import android.content.Context;
import java.util.List;

/**
 * Stand-in for the stock mediatek-common class com.mediatek.ims calls at startup
 * (OpImsServiceCustomizationUtils.getOpFactory). There are no operator plugins on this
 * build, so loadFactory returns null and the APK falls back to its own base factory.
 */
public class OperatorCustomizationFactoryLoader {
    public static class OperatorFactoryInfo {
        public OperatorFactoryInfo(String libName, String factoryName, String packageName,
                String operator) {}
    }

    public static Object loadFactory(Context context, List<OperatorFactoryInfo> list) {
        return null;
    }
}
