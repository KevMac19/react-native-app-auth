package com.rnappauth.utils;

import android.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.X509TrustManager;
import android.util.Log;
import java.util.HashSet;

public class SSLPinner implements X509TrustManager {
    private final Map<String, Set<String>> domainPins;
    private final Set<String> validPins;

    public SSLPinner(Map<String, Set<String>> domainPins) {
        // Flatten all pins into a single set
        this.validPins = new HashSet<>();
        this.domainPins = domainPins;
        for (Set<String> pins : domainPins.values()) {
            validPins.addAll(pins);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        boolean foundValidPin = false;
        
        for (X509Certificate cert : chain) {
            String pin = getPublicKeyHash(cert);
            Log.d("SSL_PINNER", "Checking pin: " + pin);
            
            if (validPins.contains(pin)) {
                Log.d("SSL_PINNER", "Valid pin found: " + pin);
                foundValidPin = true;
                break;
            }
        }

        if (!foundValidPin) {
            throw new CertificateException("No matching SSL pins found in certificate chain");
        }
    }

    private String parseCommonName(String subjectDN) {
        String[] parts = subjectDN.split(",");
        for (String part : parts) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }
        return subjectDN;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    private String getPublicKeyHash(X509Certificate cert) throws CertificateException {
        try {
            byte[] pubKey = cert.getPublicKey().getEncoded();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(pubKey);
            return Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateException(e);
        }
    }
}