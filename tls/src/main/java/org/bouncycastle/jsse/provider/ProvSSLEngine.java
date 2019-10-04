package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

import org.bouncycastle.jsse.BCApplicationProtocolSelector;
import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.NewSessionTicket;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.RecordPreview;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

/*
 * TODO[jsse] Known limitations (relative to SSLEngine javadoc): 1. The wrap() and unwrap() methods
 * are synchronized, so will not execute concurrently with each other. 2. Never delegates tasks i.e.
 * getDelegatedTasks() will always return null; CPU-intensive parts of the handshake will execute
 * during wrap/unwrap calls.
 */
class ProvSSLEngine
    extends SSLEngine
    implements BCSSLEngine, ProvTlsManager
{
    private static final Logger LOG = Logger.getLogger(ProvSSLEngine.class.getName());
    private static final ConcurrentHashMap<String, NewSessionTicket> sessionTicketMap = new ConcurrentHashMap<String, NewSessionTicket>();
    private static final ConcurrentHashMap<String, SecurityParameters> secParamMap = new ConcurrentHashMap<String, SecurityParameters>();

    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;
    protected final ProvSSLParameters sslParameters;

    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = false;

    protected boolean closedEarly = false;
    protected boolean initialHandshakeBegun = false;
    protected HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING; 
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected ProvSSLConnection connection = null;
    protected ProvSSLSessionHandshake handshakeSession = null;

    protected SSLException deferredException = null;

    protected ProvSSLEngine(ProvSSLContextSpi context, ContextData contextData)
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    protected ProvSSLEngine(ProvSSLContextSpi context, ContextData contextData, String host, int port)
    {
        super(host, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    public ProvSSLContextSpi getContext()
    {
        return context;
    }

    public ContextData getContextData()
    {
        return contextData;
    }

    @Override
    public synchronized void beginHandshake()
        throws SSLException
    {
        if (closedEarly)
        {
            throw new SSLException("Connection is already closed");
        }
        if (initialHandshakeBegun)
        {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }

        this.initialHandshakeBegun = true;

        try
        {
            if (this.useClientMode)
            {
                TlsClientProtocol clientProtocol = new TlsClientProtocol();
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(this, sslParameters.copy());
                // RFC 5077: re-use existing session ticket from hash map if available.
                String key = getPeerHost() + ":" + getPeerPort();
                NewSessionTicket ticket = sessionTicketMap.get(key);
                SecurityParameters sp = secParamMap.get(key);
                if (ticket != null && sp != null) {
                    client.setNewSessionTicket(ticket);
                    client.setSecurityParameters(sp.makeCopy()); // clone for the non-sharable master secret.
                }
                this.protocolPeer = client;

                clientProtocol.connect(client);
                this.handshakeStatus = HandshakeStatus.NEED_WRAP;
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol();
                this.protocol = serverProtocol;

                ProvTlsServer server = new ProvTlsServer(this, sslParameters.copy());
                this.protocolPeer = server;

                serverProtocol.accept(server);
                this.handshakeStatus = HandshakeStatus.NEED_UNWRAP;
            }
        }
        catch (SSLException e)
        {
            throw e;
        }
        catch (IOException e)
        {
            throw new SSLException(e);
        }
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws IOException
    {
        try
        {
            contextData.getX509TrustManager().checkClientTrusted(chain, authType, this);
        }
        catch (CertificateException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws IOException
    {
        try
        {
            contextData.getX509TrustManager().checkServerTrusted(chain, authType, this);
        }
        catch (CertificateException e)
        {
            throw new TlsFatalAlert(AlertDescription.certificate_unknown, e);
        }
    }

    public String chooseClientAlias(String[] keyType, Principal[] issuers)
    {
        return contextData.getX509KeyManager().chooseEngineClientAlias(keyType, issuers, this);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers)
    {
        return contextData.getX509KeyManager().chooseEngineServerAlias(keyType, issuers, this);
    }

    @Override
    public synchronized void closeInbound()
        throws SSLException
    {
        if (closedEarly)
        {
            // SSLEngine already closed before any handshake attempted
        }
        else if (null == protocol)
        {
            this.closedEarly = true;
        }
        else
        {
            try
            {
                protocol.closeInput();
            }
            catch (IOException e)
            {
                throw new SSLException(e);
            }
        }
    }

    @Override
    public synchronized void closeOutbound()
    {
        if (closedEarly)
        {
            // SSLEngine already closed before any handshake attempted
        }
        else if (null == protocol)
        {
            this.closedEarly = true;
        }
        else
        {
            try
            {
                protocol.close();
            }
            catch (IOException e)
            {
                LOG.log(Level.WARNING, "Failed to close outbound", e);
            }
        }
    }

    // An SSLEngine method from JDK 9, but also a BCSSLEngine method
    public synchronized String getApplicationProtocol()
    {
        return null == connection ? null : connection.getApplicationProtocol();
    }

    public synchronized BCApplicationProtocolSelector<SSLEngine> getBCHandshakeApplicationProtocolSelector()
    {
        return sslParameters.getEngineAPSelector();
    }

    public synchronized BCExtendedSSLSession getBCHandshakeSession()
    {
        return handshakeSession;
    }

    public synchronized BCSSLConnection getConnection()
    {
        return connection;
    }

    @Override
    public synchronized Runnable getDelegatedTask()
    {
        return null;
    }

    @Override
    public synchronized String[] getEnabledCipherSuites()
    {
        return sslParameters.getCipherSuites();
    }

    @Override
    public synchronized String[] getEnabledProtocols()
    {
        return sslParameters.getProtocols();
    }

    @Override
    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

    // An SSLEngine method from JDK 9, but also a BCSSLEngine method
    public synchronized String getHandshakeApplicationProtocol()
    {
        return null == handshakeSession ? null : handshakeSession.getApplicationProtocol();
    }

    @Override
    public synchronized SSLSession getHandshakeSession()
    {
        return null == handshakeSession ? null : handshakeSession.getExportSSLSession();
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        return handshakeStatus;
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    public synchronized BCSSLParameters getParameters()
    {
        return SSLParametersUtil.getParameters(sslParameters);
    }

    @Override
    public synchronized SSLSession getSession()
    {
        ProvSSLSession sslSession = (null == connection) ? ProvSSLSession.NULL_SESSION : connection.getSession();

        return sslSession.getExportSSLSession();
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.getSSLParameters(sslParameters);
    }

    @Override
    public synchronized String[] getSupportedCipherSuites()
    {
        return context.getSupportedCipherSuites();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        return context.getSupportedProtocols();
    }

    @Override
    public synchronized boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public synchronized boolean getWantClientAuth()
    {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public synchronized boolean isInboundDone()
    {
        return closedEarly || (null != protocol && protocol.isClosed());
    }

    @Override
    public synchronized boolean isOutboundDone()
    {
        return closedEarly || (null != protocol && protocol.isClosed() && protocol.getAvailableOutputBytes() < 1);
    }

    public synchronized void setBCHandshakeApplicationProtocolSelector(BCApplicationProtocolSelector<SSLEngine> selector)
    {
        sslParameters.setEngineAPSelector(selector);
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] suites)
    {
        sslParameters.setCipherSuites(suites);
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
    {
        sslParameters.setProtocols(protocols);
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag)
    {
        this.enableSessionCreation = flag;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    public synchronized void setParameters(BCSSLParameters parameters)
    {
        SSLParametersUtil.setParameters(this.sslParameters, parameters);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean useClientMode)
    {
        if (initialHandshakeBegun)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        if (this.useClientMode != useClientMode)
        {
            context.updateDefaultProtocols(sslParameters, !useClientMode);

            this.useClientMode = useClientMode;
        }
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException
    {
        // TODO[jsse] Argument checks - see javadoc

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        Status resultStatus = Status.OK;
        int bytesConsumed = 0, bytesProduced = 0;

        if (protocol.isClosed())
        {
            resultStatus = Status.CLOSED;
        }
        else
        {
            try
            {
                RecordPreview preview = getRecordPreview(src);
                if (preview == null || src.remaining() < preview.getRecordSize())
                {
                    resultStatus = Status.BUFFER_UNDERFLOW;
                }
                else if (hasInsufficientSpace(dsts, offset, length, preview.getApplicationDataLimit()))
                {
                    resultStatus = Status.BUFFER_OVERFLOW;
                }
                else
                {
                    byte[] record = new byte[preview.getRecordSize()];
                    src.get(record);

                    protocol.offerInput(record);
                    bytesConsumed += record.length;

                    int appDataAvailable = protocol.getAvailableInputBytes();
                    for (int dstIndex = 0; dstIndex < length && appDataAvailable > 0; ++dstIndex)
                    {
                        ByteBuffer dst = dsts[offset + dstIndex];
                        int count = Math.min(dst.remaining(), appDataAvailable);
                        if (count > 0)
                        {
                            byte[] appData = new byte[count];
                            int numRead = protocol.readInput(appData, 0, count);
                            assert numRead == count;
                
                            dst.put(appData);
                
                            bytesProduced += count;
                            appDataAvailable -= count;
                        }
                    }

                    // We pre-checked the output would fit, so there should be nothing left over.
                    if (appDataAvailable != 0)
                    {
                        // TODO[tls] Expose a method to fail the connection externally
                        throw new TlsFatalAlert(AlertDescription.record_overflow);
                    }
                }
            }
            catch (IOException e)
            {
                /*
                 * TODO[jsse] 'deferredException' is a workaround for Apache Tomcat's (as of
                 * 8.5.13) SecureNioChannel behaviour when exceptions are thrown from
                 * SSLEngine during the handshake. In the case of SSLEngine.wrap throwing,
                 * Tomcat will call wrap again, allowing any buffered outbound alert to be
                 * flushed. For unwrap, this doesn't happen. So we pretend this unwrap was
                 * OK and ask for NEED_WRAP, then throw in wrap.
                 * 
                 * Note that the SSLEngine javadoc clearly describes a process of flushing
                 * via wrap calls after any closure events, to include thrown exceptions.
                 */
                if (handshakeStatus != HandshakeStatus.NEED_UNWRAP)
                {
                    throw new SSLException(e);
                }

                if (this.deferredException == null)
                {
                    this.deferredException = new SSLException(e);
                }

                handshakeStatus = HandshakeStatus.NEED_WRAP;

                return new SSLEngineResult(Status.OK, HandshakeStatus.NEED_WRAP, bytesConsumed, bytesProduced);
            }
        }

        /*
         * We only ever change the handshakeStatus here if we started in NEED_UNWRAP
         */
        HandshakeStatus resultHandshakeStatus = handshakeStatus;
        if (handshakeStatus == HandshakeStatus.NEED_UNWRAP)
        {
            if (protocol.getAvailableOutputBytes() > 0)
            {
                handshakeStatus = HandshakeStatus.NEED_WRAP;
                resultHandshakeStatus = HandshakeStatus.NEED_WRAP;
            }
            else if (protocolPeer.isHandshakeComplete())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.FINISHED;
            }
            else if (protocol.isClosed())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
            }
            else
            {
                // Still NEED_UNWRAP
            }
        }

        return new SSLEngineResult(resultStatus, resultHandshakeStatus, bytesConsumed, bytesProduced);
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException
    {
        if (deferredException != null)
        {
            SSLException e = deferredException;
            deferredException = null;
            throw e;
        }

        // TODO[jsse] Argument checks - see javadoc

        if (!initialHandshakeBegun)
        {
            beginHandshake();
        }

        Status resultStatus = Status.OK;
        int bytesConsumed = 0, bytesProduced = 0;

        /*
         * If handshake complete and the connection still open, send the application data in 'srcs'
         */
        if (handshakeStatus == HandshakeStatus.NOT_HANDSHAKING)
        {
            if (protocol.isClosed())
            {
                resultStatus = Status.CLOSED;
            }
            else if (protocol.getAvailableOutputBytes() > 0)
            {
                /*
                 * Handle any buffered handshake data fully before sending application data.
                 */
            }
            else
            {
                try
                {
                    /*
                     * Generate at most one maximum-sized application data record per call.
                     */
                    int srcRemaining = getTotalRemaining(srcs, offset, length, protocol.getApplicationDataLimit());
                    if (srcRemaining > 0)
                    {
                        RecordPreview preview = protocol.previewOutputRecord(srcRemaining);

                        int srcLimit = preview.getApplicationDataLimit();
                        int dstLimit = preview.getRecordSize();

                        if (dst.remaining() < dstLimit)
                        {
                            resultStatus = Status.BUFFER_OVERFLOW;
                        }
                        else
                        {
                            for (int srcIndex = 0; srcIndex < length && srcLimit > 0; ++srcIndex)
                            {
                                ByteBuffer src = srcs[offset + srcIndex];
                                int count = Math.min(src.remaining(), srcLimit);
                                if (count > 0)
                                {
                                    byte[] input = new byte[count];
                                    src.get(input);
    
                                    protocol.writeApplicationData(input, 0, count);
    
                                    bytesConsumed += count;
                                    srcLimit -= count;
                                }
                            }
                        }
                    }
                }
                catch (IOException e)
                {
                    // TODO[jsse] Throw a subclass of SSLException?
                    throw new SSLException(e);
                }
            }
        }

        /*
         * Send any available output
         */
        int outputAvailable = protocol.getAvailableOutputBytes();
        if (outputAvailable > 0)
        {
            int count = Math.min(dst.remaining(), outputAvailable);
            if (count > 0)
            {
                byte[] output = new byte[count];
                int numRead = protocol.readOutput(output, 0, count);
                assert numRead == count;
    
                dst.put(output);
    
                bytesProduced += count;
                outputAvailable -= count;
            }
            else
            {
                resultStatus = Status.BUFFER_OVERFLOW;
            }
        }

        /*
         * We only ever change the handshakeStatus here if we started in NEED_WRAP
         */
        HandshakeStatus resultHandshakeStatus = handshakeStatus;
        if (handshakeStatus == HandshakeStatus.NEED_WRAP)
        {
            if (outputAvailable > 0)
            {
                // Still NEED_WRAP
            }
            else if (protocolPeer.isHandshakeComplete())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.FINISHED;
            }
            else if (protocol.isClosed())
            {
                handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
                resultHandshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
            }
            else
            {
                handshakeStatus = HandshakeStatus.NEED_UNWRAP;
                resultHandshakeStatus = HandshakeStatus.NEED_UNWRAP;
                
            }
        }

        return new SSLEngineResult(resultStatus, resultHandshakeStatus, bytesConsumed, bytesProduced);
    }

    public String getPeerHost()
    {
        return super.getPeerHost();
    }

    public String getPeerHostSNI()
    {
        return super.getPeerHost();
    }

    public int getPeerPort()
    {
        return super.getPeerPort();
    }

    public synchronized void notifyHandshakeComplete(ProvSSLConnection connection)
    {
        boolean succeeded = null != handshakeSession && !handshakeSession.isValid();
        String key = getPeerHost() + ":" + getPeerPort();
        if (!succeeded) {
            connection.getSession().invalidate();
            sessionTicketMap.remove(key);
            secParamMap.remove(key);
        }

        this.handshakeSession = null;
        this.connection = connection;

        // RFC 5077: keep away new session ticket if available.
        // The design here is to extract NewSessionTicket from protocol, store at hash map, assign to newly created
        // protocolPeer if host+port pair match.
        if (protocol instanceof TlsClientProtocol && succeeded) {
            TlsClientProtocol p = (TlsClientProtocol) protocol;
            NewSessionTicket ticket = p.getNewSessionTicket();
            if (ticket != null) { // received session ticket from the first successful full handshake
                sessionTicketMap.put(key, ticket);
                secParamMap.put(key, p.getSecurityParameters());
            }
        }
    }

    public synchronized void notifyHandshakeSession(ProvSSLSessionHandshake handshakeSession)
    {
        this.handshakeSession = handshakeSession;
    }

    public synchronized String selectApplicationProtocol(List<String> protocols)
    {
        return sslParameters.getEngineAPSelector().select(this, protocols);
    }

    private RecordPreview getRecordPreview(ByteBuffer src)
        throws IOException
    {
        if (src.remaining() < RecordFormat.FRAGMENT_OFFSET)
        {
            return null;
        }

        byte[] recordHeader = new byte[RecordFormat.FRAGMENT_OFFSET];

        int position = src.position();
        src.get(recordHeader);
        src.position(position);

        return protocol.previewInputRecord(recordHeader);
    }

    private int getTotalRemaining(ByteBuffer[] bufs, int off, int len, int limit)
    {
        int result = 0;
        for (int i = 0; i < len; ++i)
        {
            ByteBuffer buf = bufs[off + i];
            int next = buf.remaining();
            if (next >= (limit - result))
            {
                return limit;
            }
            result += next;
        }
        return result;
    }

    private boolean hasInsufficientSpace(ByteBuffer[] dsts, int off, int len, int amount)
    {
        return getTotalRemaining(dsts, off, len, amount) < amount;
    }
}
