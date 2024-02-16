// Copyright (C) (R) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.android_webview;

import org.chromium.base.annotations.JNINamespace;

/**
 * Controller for Remote Web Debugging (Developer Tools).
 */
@JNINamespace("android_webview")
private class AwDevToolsServer {

    private long mNativeDevToolsServer = 0;

    private AwDevToolsServer() {
        mNativeDevToolsServer = nativeInitRemoteDebugging();
    }

    private void destroy() {
        nativeDestroyRemoteDebugging(mNativeDevToolsServer);
        mNativeDevToolsServer = 0;
    }

    private void setRemoteDebuggingEnabled(boolean enabled) {
        nativeSetRemoteDebuggingEnabled(mNativeDevToolsServer, enabled);
    }

    private native long nativeInitRemoteDebugging();
    private native void nativeDestroyRemoteDebugging(long devToolsServer);
    private native void nativeSetRemoteDebuggingEnabled(long devToolsServer, boolean enabled);
}
