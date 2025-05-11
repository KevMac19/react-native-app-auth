package com.rnappauth.utils;

/*
 * Copyright 2016 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */


import android.net.Uri;
import android.util.Log;
import androidx.annotation.NonNull;

import net.openid.appauth.connectivity.ConnectionBuilder;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.concurrent.TimeUnit;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.SecureRandom;
import java.util.Set; // Add this import

/**
 * An implementation of {@link ConnectionBuilder} that permits
 * to set custom headers on connection use to request endpoints.
 * Useful for non-spec compliant oauth providers.
 */
public final class CustomConnectionBuilder implements ConnectionBuilder {

    private Map<String, String> headers = null;

    private int connectionTimeoutMs = (int) TimeUnit.SECONDS.toMillis(15);
    private int readTimeoutMs = (int) TimeUnit.SECONDS.toMillis(10);     
    private ConnectionBuilder connectionBuilder;
    private final Map<String, Set<String>> sslPins;

    public CustomConnectionBuilder(ConnectionBuilder connectionBuilderToUse, 
                                 Map<String, Set<String>> sslPins) {
        this.connectionBuilder = connectionBuilderToUse;
        this.sslPins = sslPins;
    }

    public void setHeaders (Map<String, String> headersToSet) {
        headers = headersToSet;
    }

    public void setConnectionTimeout (int timeout) {
        connectionTimeoutMs = timeout;
        readTimeoutMs = timeout;
    }

    @NonNull
    @Override
    public HttpURLConnection openConnection(@NonNull Uri uri) throws IOException {
        HttpURLConnection conn = connectionBuilder.openConnection(uri);

        if (headers != null) {
            for (Map.Entry<String, String> header: headers.entrySet()) {
                conn.setRequestProperty(header.getKey(), header.getValue());
            }
        }

        conn.setConnectTimeout(connectionTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);

        if (conn instanceof HttpsURLConnection && sslPins != null && !sslPins.isEmpty()) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
            configureSSLPinning(httpsConn);
        }
        return conn;
    }

    private void configureSSLPinning(HttpsURLConnection connection) {
        try {
            Log.d("SSL_DEBUG", "Initializing SSL context with pins: " + sslPins.toString());
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] {new SSLPinner(sslPins)}, new SecureRandom());
            connection.setSSLSocketFactory(sslContext.getSocketFactory());
            Log.d("SSL_DEBUG", "SSL context configured successfully");
        } catch (Exception e) {
            Log.e("SSL_DEBUG", "SSL configuration failed: " + e.getMessage());
            throw new RuntimeException("SSL context initialization failed: " + e.getMessage(), e);
        }
    }
}
