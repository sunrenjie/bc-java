package org.bouncycastle.jsse.provider;

import java.util.Collections;
import java.util.List;

import javax.net.ssl.SNIServerName;

import org.bouncycastle.jsse.BCExtendedSSLSession;

class ExportSSLSession_8
    extends ExportSSLSession_7
{
    // Borrowed from Netty ExtendedOpenSslSession
    // TODO: use OpenSSL API to actually fetch the real data but for now just do what Conscrypt does:
    // https://github.com/google/conscrypt/blob/1.2.0/common/
    // src/main/java/org/conscrypt/Java7ExtendedSSLSession.java#L32
    private static final String[] LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS = {
            "SHA512withRSA", "SHA512withECDSA", "SHA384withRSA", "SHA384withECDSA", "SHA256withRSA",
            "SHA256withECDSA", "SHA224withRSA", "SHA224withECDSA", "SHA1withRSA", "SHA1withECDSA",
    };

    ExportSSLSession_8(BCExtendedSSLSession sslSession)
    {
        super(sslSession);
    }

    @SuppressWarnings("unchecked")
    public List<SNIServerName> getRequestedServerNames()
    {
        return (List<SNIServerName>)JsseUtils_8.exportSNIServerNames(sslSession.getRequestedServerNames());
    }

    @Override
    public final String[] getLocalSupportedSignatureAlgorithms() {
        return LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS.clone();
    }

    // Borrowed from Netty ExtendedOpenSslSession
    // Do not mark as override so we can compile on java8.
    public List<byte[]> getStatusResponses() {
        // Just return an empty list for now until we support it as otherwise we will fail in java9
        // because of their sun.security.ssl.X509TrustManagerImpl class.
        return Collections.emptyList();
    }
}
