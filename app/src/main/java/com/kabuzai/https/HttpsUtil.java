package com.kabuzai.https;

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * 支持Https请求SSL验证的工具类
 * <p>
 * created by kabuzai
 */
public class HttpsUtil {

    private static final String[] CERTIFICATES = new String[]{};

    /**
     * HttpUrlConnection支持Https验证（单向，足够满足大多数业务的需求）
     * <p>
     * 对安全有更高要求的业务如银行、金融等，需要双向验证，可自定义
     *
     * @param context
     */
    public static void initHttpsUrlConnection(Context context) {
        InputStream[] certificates = getCertificates(context, CERTIFICATES);
        SSLSocketFactory sslSocketFactory = getSSLSocketFactory(certificates, null, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sslSocketFactory);
        if (certificates == null) {
            HttpsURLConnection.setDefaultHostnameVerifier(getUnSafeHostnameVerifier());
        }
    }

    /**
     * 获取支持Https的OkHttpClient
     * <p>
     * 不需要的项目可注释
     *
     * @param context
     * @return
     */
//    public static OkHttpClient getHttpsOkHttpClient(Context context) {
//        OkHttpClient.Builder builder = new OkHttpClient().newBuilder();
//
//        InputStream[] certificates = HttpsUtil.getCertificates(context, CERTIFICATES);
//        SSLSocketFactory sslSocketFactory = HttpsUtil.getSSLSocketFactory(certificates, null, null);
//        builder.sslSocketFactory(sslSocketFactory);
//        if (certificates == null) {
//            builder.hostnameVerifier(HttpsUtil.getUnSafeHostnameVerifier());
//        }
//        return builder.build();
//    }

    /**
     * 获取服务端证书
     * <p>
     * 默认放在Assets目录下
     *
     * @param context
     * @return
     */
    public static InputStream[] getCertificates(Context context, String... fileNames) {
        if (context == null || fileNames == null || fileNames.length <= 0) {
            return null;
        }
        try {
            InputStream[] certificates = new InputStream[fileNames.length];
            for (int i = 0; i < fileNames.length; i++) {
                certificates[i] = context.getAssets().open(fileNames[i]);
            }
            return certificates;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 获取自定义SSLSocketFactory
     * <p>
     * 单项验证时只需要certificates，其余null即可
     * 双向验证时，3个参数均需要
     * <p>
     * 不验证，即信任所有证书时全部传null，同时配合getUnSafeHostnameVerifier()
     * 有安全隐患，慎用！！！
     *
     * @param certificates 服务端证书（.crt）
     * @param bksFile      客户端证书请求文件（.jsk -> .bks)
     * @param password     生成jks时的密钥库口令
     * @return
     */
    public static SSLSocketFactory getSSLSocketFactory(InputStream[] certificates, InputStream bksFile, String password) {
        try {
            TrustManager[] trustManagers = prepareTrustManager(certificates);
            KeyManager[] keyManagers = prepareKeyManager(bksFile, password);
            SSLContext sslContext = SSLContext.getInstance("TLS");
            if (trustManagers == null || trustManagers.length <= 0) {
                trustManagers = new TrustManager[]{new UnSafeTrustManager()};
            }
            sslContext.init(keyManagers, trustManagers, new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new AssertionError(e);
        }
    }

    private static TrustManager[] prepareTrustManager(InputStream... certificates) {
        if (certificates == null || certificates.length <= 0) return null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);
            int index = 0;
            for (InputStream is : certificates) {
                String certificateAlias = Integer.toString(index++);
                Certificate certificate = certificateFactory.generateCertificate(is);
                keyStore.setCertificateEntry(certificateAlias, certificate);
                try {
                    if (is != null)
                        is.close();
                } catch (IOException ignored) {
                }
            }
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            return trustManagerFactory.getTrustManagers();
            // TODO: 2016/11/11 针对有效期异常导致校验失败的情况，目前没有完美的解决方案
//            TrustManager[] keyStoreTrustManagers = trustManagerFactory.getTrustManagers();
//            return getNotValidateTimeTrustManagers((X509TrustManager[]) keyStoreTrustManagers);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static KeyManager[] prepareKeyManager(InputStream bksFile, String password) {
        try {
            if (bksFile == null || password == null) return null;
            KeyStore clientKeyStore = KeyStore.getInstance("BKS");
            clientKeyStore.load(bksFile, password.toCharArray());
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, password.toCharArray());
            return keyManagerFactory.getKeyManagers();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static NotValidateTimeTrustManager[] getNotValidateTimeTrustManagers(X509TrustManager[] trustManagers) {
        NotValidateTimeTrustManager[] notValidateTimeTrustManagers = new NotValidateTimeTrustManager[trustManagers.length];
        for (int i = 0; i< trustManagers.length; i++) {
            notValidateTimeTrustManagers[i] = new NotValidateTimeTrustManager(trustManagers[i]);
        }
        return notValidateTimeTrustManagers;
    }

    /**
     * 不校验证书有效期的TrustManager
     * <p>
     * 防止用户乱改手机时间导致校验失败
     * 注意：由于校验证书时，对有效期的校验并不是最后一项，所以该TrustManager仍然存在安全隐患，并不推荐使用
     */
    private static class NotValidateTimeTrustManager implements X509TrustManager {

        private X509TrustManager defaultTrustManager;

        public NotValidateTimeTrustManager(X509TrustManager defaultTrustManager) {
            this.defaultTrustManager = defaultTrustManager;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            defaultTrustManager.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                defaultTrustManager.checkServerTrusted(chain, authType);
            } catch (CertificateException e) {
                e.printStackTrace();
                Throwable t = e;
                while (t != null) {
                    if (t instanceof CertificateExpiredException
                            || t instanceof CertificateNotYetValidException)
                        return;
                    t = t.getCause();
                }
                throw e;
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return defaultTrustManager.getAcceptedIssuers();
        }
    }


    private static class UnSafeTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{};
        }
    }

    private static class UnSafeHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    }

    /**
     * 不验证，即信任所有证书时使用
     * 有安全隐患，慎用！！！
     *
     * @return
     */
    public static UnSafeHostnameVerifier getUnSafeHostnameVerifier() {
        return new UnSafeHostnameVerifier();
    }
}
