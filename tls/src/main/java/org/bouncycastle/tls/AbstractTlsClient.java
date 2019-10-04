package org.bouncycastle.tls;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Integers;

/**
 * Base class for a TLS client.
 */
public abstract class AbstractTlsClient
    extends AbstractTlsPeer
    implements TlsClient
{
    protected TlsClientContext context;
    protected int[] cipherSuites;

    protected Vector supportedGroups;
    protected Vector supportedSignatureAlgorithms;

    public AbstractTlsClient(TlsCrypto crypto)
    {
        super(crypto);
    }

    protected boolean allowUnexpectedServerExtension(Integer extensionType, byte[] extensionData)
        throws IOException
    {
        switch (extensionType.intValue())
        {
        case ExtensionType.supported_groups:
            /*
             * Exception added based on field reports that some servers do send this, although the
             * Supported Elliptic Curves Extension is clearly intended to be client-only. If
             * present, we still require that it is a valid EllipticCurveList.
             */
            TlsExtensionsUtils.readSupportedGroupsExtension(extensionData);
            return true;

        case ExtensionType.ec_point_formats:
            /*
             * Exception added based on field reports that some servers send this even when they
             * didn't negotiate an ECC cipher suite. If present, we still require that it is a valid
             * ECPointFormatList.
             */
            TlsExtensionsUtils.readSupportedPointFormatsExtension(extensionData);
            return true;

        default:
            return false;
        }
    }

    protected Vector getNamedGroupRoles()
    {
        Vector namedGroupRoles = TlsUtils.getNamedGroupRoles(getCipherSuites());

        if (null == supportedSignatureAlgorithms
            || TlsUtils.containsAnySignatureAlgorithm(supportedSignatureAlgorithms, SignatureAlgorithm.ecdsa))
        {
            TlsUtils.addToSet(namedGroupRoles, NamedGroupRole.ecdsa);
        }

        return namedGroupRoles;
    }

    protected void checkForUnexpectedServerExtension(Hashtable serverExtensions, Integer extensionType)
        throws IOException
    {
        byte[] extensionData = TlsUtils.getExtensionData(serverExtensions, extensionType);
        if (extensionData != null && !allowUnexpectedServerExtension(extensionType, extensionData))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
    }

    public TlsPSKIdentity getPSKIdentity() throws IOException
    {
        return null;
    }

    public TlsSRPIdentity getSRPIdentity() throws IOException
    {
        return null;
    }

    public TlsDHGroupVerifier getDHGroupVerifier()
    {
        return new DefaultTlsDHGroupVerifier();
    }

    public TlsSRPConfigVerifier getSRPConfigVerifier()
    {
        return new DefaultTlsSRPConfigVerifier();
    }

    protected Vector getProtocolNames()
    {
        return null;
    }

    protected CertificateStatusRequest getCertificateStatusRequest()
    {
        return new CertificateStatusRequest(CertificateStatusType.ocsp, new OCSPStatusRequest(null, null));
    }

    protected Vector getSNIServerNames()
    {
        return null;
    }

    protected abstract int[] getSupportedCipherSuites();

    /**
     * The default {@link #getClientExtensions()} implementation calls this to determine which named
     * groups to include in the supported_groups extension for the ClientHello.
     * 
     * @param namedGroupRoles
     *            The {@link NamedGroupRole named group roles} for which there should be at
     *            least one supported group. By default this is inferred from the offered cipher
     *            suites and signature algorithms.
     * @return a {@link Vector} of {@link Integer}. See {@link NamedGroup} for group constants.
     */
    protected Vector getSupportedGroups(Vector namedGroupRoles)
    {
        TlsCrypto crypto = getCrypto();
        Vector supportedGroups = new Vector();

        if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdh)))
        {
            TlsUtils.addIfSupported(supportedGroups, crypto, NamedGroup.x25519);
        }

        if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdh))
            || namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdsa)))
        {
            TlsUtils.addIfSupported(supportedGroups, crypto, new int[]{
                NamedGroup.secp256r1, NamedGroup.secp384r1 });
        }

        if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.dh)))
        {
            TlsUtils.addIfSupported(supportedGroups, crypto, new int[]{
                NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096 });
        }

        return supportedGroups;
    }

    protected Vector getSupportedSignatureAlgorithms()
    {
        return TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
    }

    public void init(TlsClientContext context)
    {
        this.context = context;

        this.cipherSuites = getSupportedCipherSuites();
    }

    public void notifyHandshakeBeginning() throws IOException
    {
        super.notifyHandshakeBeginning();

        this.supportedGroups = null;
        this.supportedSignatureAlgorithms = null;
    }

    public TlsSession getSessionToResume()
    {
        return null;
    }

    public boolean isFallback()
    {
        /*
         * RFC 7507 4. The TLS_FALLBACK_SCSV cipher suite value is meant for use by clients that
         * repeat a connection attempt with a downgraded protocol (perform a "fallback retry") in
         * order to work around interoperability problems with legacy servers.
         */
        return false;
    }

    public int[] getCipherSuites()
    {
        return cipherSuites;
    }

    public Hashtable getClientExtensions()
        throws IOException
    {
        Hashtable clientExtensions = new Hashtable();

        boolean offeringPreTLSv13 = false;
        {
            ProtocolVersion[] supportedVersions = getSupportedVersions();
            for (int i = 0; i < supportedVersions.length; ++i)
            {
                if (!TlsUtils.isTLSv13(supportedVersions[i]))
                {
                    offeringPreTLSv13 = true;
                    break;
                }
            }
        }

        if (offeringPreTLSv13)
        {
            TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
        }

        Vector protocolNames = getProtocolNames();
        if (protocolNames != null)
        {
            TlsExtensionsUtils.addALPNExtensionClient(clientExtensions, protocolNames);
        }

        Vector sniServerNames = getSNIServerNames();
        if (sniServerNames != null)
        {
            TlsExtensionsUtils.addServerNameExtensionClient(clientExtensions, sniServerNames);
        }

        CertificateStatusRequest statusRequest = getCertificateStatusRequest();
        if (statusRequest != null)
        {
            TlsExtensionsUtils.addStatusRequestExtension(clientExtensions, statusRequest);
        }

        ProtocolVersion clientVersion = context.getClientVersion();

        /*
         * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
         * Clients MUST NOT offer it if they are offering prior versions.
         */
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
        {
            this.supportedSignatureAlgorithms = getSupportedSignatureAlgorithms();

            TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
        }

        Vector namedGroupRoles = getNamedGroupRoles();

        Vector supportedGroups = getSupportedGroups(namedGroupRoles);
        if (supportedGroups != null && !supportedGroups.isEmpty())
        {
            this.supportedGroups = supportedGroups;

            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
        }

        if (offeringPreTLSv13)
        {
            if (namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdh))
                || namedGroupRoles.contains(Integers.valueOf(NamedGroupRole.ecdsa)))
            {
                TlsExtensionsUtils.addSupportedPointFormatsExtension(clientExtensions, new short[]{ ECPointFormat.uncompressed });
            }
        }

        // RFC 5077 session ticket
        TlsExtensionsUtils.addSessionTicketExtension(clientExtensions);

        return clientExtensions;
    }

    public Vector getEarlyKeyShareGroups()
    {
        if (null != supportedGroups)
        {
            if (supportedGroups.contains(Integers.valueOf(NamedGroup.x25519)))
            {
                return TlsUtils.vectorOfOne(Integers.valueOf(NamedGroup.x25519));
            }
            if (supportedGroups.contains(Integers.valueOf(NamedGroup.secp256r1)))
            {
                return TlsUtils.vectorOfOne(Integers.valueOf(NamedGroup.secp256r1));
            }
        }
        return null;
    }

    public void notifyServerVersion(ProtocolVersion serverVersion)
        throws IOException
    {
    }

    public void notifySessionID(byte[] sessionID)
    {
    }

    public void notifySelectedCipherSuite(int selectedCipherSuite)
    {
    }

    public void processServerExtensions(Hashtable serverExtensions)
        throws IOException
    {
        /*
         * TlsProtocol implementation validates that any server extensions received correspond to
         * client extensions sent. By default, we don't send any, and this method is not called.
         */
        if (serverExtensions != null)
        {
            /*
             * RFC 5246 7.4.1.4.1. Servers MUST NOT send this extension.
             */
            checkForUnexpectedServerExtension(serverExtensions, TlsUtils.EXT_signature_algorithms);
            checkForUnexpectedServerExtension(serverExtensions, TlsUtils.EXT_signature_algorithms_cert);

            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_supported_groups);

            int selectedCipherSuite = context.getSecurityParametersHandshake().getCipherSuite();

            if (TlsECCUtils.isECCCipherSuite(selectedCipherSuite))
            {
                // We only support uncompressed format, this is just to validate the extension, if present.
                TlsExtensionsUtils.getSupportedPointFormatsExtension(serverExtensions);
            }
            else
            {
                checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_ec_point_formats);
            }

            /*
             * RFC 7685 3. The server MUST NOT echo the extension.
             */
            checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_padding);
        }
    }

    public void processServerSupplementalData(Vector serverSupplementalData)
        throws IOException
    {
        if (serverSupplementalData != null)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    public Vector getClientSupplementalData()
        throws IOException
    {
        return null;
    }

    public void notifyNewSessionTicket(NewSessionTicket newSessionTicket, SecurityParameters securityParameters)
        throws IOException
    {
    }

    public NewSessionTicket getNewSessionTicket()
    {
        return null;
    }

    public SecurityParameters getSecurityParameters()
    {
        return null;
    }
}
