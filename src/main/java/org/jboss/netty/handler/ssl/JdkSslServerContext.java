/*
 * Copyright 2014 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.jboss.netty.handler.ssl;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A server-side {@link SslContext} which uses JDK's SSL/TLS implementation.
 */
public final class JdkSslServerContext extends JdkSslContext {

    private final SSLContext ctx;
    private final List<String> nextProtocols;

    /**
     * Creates a new instance.
     *
     * @param certChainFile an X.509 certificate chain file in PEM format
     * @param keyFile a PKCS#8 private key file in PEM format
     */
    public JdkSslServerContext(File certChainFile, File keyFile) throws SSLException {
        this(certChainFile, keyFile, null);
    }

    /**
     * Creates a new instance.
     *
     * @param certChainFile an X.509 certificate chain file in PEM format
     * @param keyFile a PKCS#8 private key file in PEM format
     * @param keyPassword the password of the {@code keyFile}.
     *                    {@code null} if it's not password-protected.
     */
    public JdkSslServerContext(File certChainFile, File keyFile, String keyPassword)
            throws SSLException {
        this(null, certChainFile, keyFile, keyPassword, null, null, 0, 0);
    }

    /**
     * Creates a new instance.
     *
     * @param bufPool the buffer pool which will be used by this context.
     *                {@code null} to use the default buffer pool.
     * @param certChainFile an X.509 certificate chain file in PEM format
     * @param keyFile a PKCS#8 private key file in PEM format
     * @param keyPassword the password of the {@code keyFile}.
     *                    {@code null} if it's not password-protected.
     * @param ciphers the cipher suites to enable, in the order of preference.
     *                {@code null} to use the default cipher suites.
     * @param nextProtocols the application layer protocols to accept, in the order of preference.
     *                      {@code null} to disable TLS NPN/ALPN extension.
     * @param sessionCacheSize the size of the cache used for storing SSL session objects.
     *                         {@code 0} to use the default value.
     * @param sessionTimeout the timeout for the cached SSL session objects, in seconds.
     *                       {@code 0} to use the default value.
     */
    public JdkSslServerContext(
            SslBufferPool bufPool,
            File certChainFile, File keyFile, String keyPassword,
            Iterable<String> ciphers, Iterable<String> nextProtocols,
            long sessionCacheSize, long sessionTimeout) throws SSLException {
        this(bufPool,
                certChainFile, keyFile, keyPassword,
                null, null,
                ciphers, nextProtocols,
                sessionCacheSize, sessionTimeout);
    }

    /**
     * Creates a new instance.
     *
     * @param bufPool the buffer pool which will be used by this context.
     *                {@code null} to use the default buffer pool.
     * @param certChainFile an X.509 certificate chain file in PEM format
     * @param keyFile a PKCS#8 private key file in PEM format
     * @param keyPassword the password of the {@code keyFile}.
     *                    {@code null} if it's not password-protected.
     * @param clientCertChainFile an X.509 certificate chain file of client certs in PEM format
     * @param trustManagerFactory Trust manager for client certs
     * @param ciphers the cipher suites to enable, in the order of preference.
     *                {@code null} to use the default cipher suites.
     * @param nextProtocols the application layer protocols to accept, in the order of preference.
     *                      {@code null} to disable TLS NPN/ALPN extension.
     * @param sessionCacheSize the size of the cache used for storing SSL session objects.
     *                         {@code 0} to use the default value.
     * @param sessionTimeout the timeout for the cached SSL session objects, in seconds.
     *                       {@code 0} to use the default value.
     */
    public JdkSslServerContext(
            SslBufferPool bufPool,
            File certChainFile, File keyFile, String keyPassword,
            File clientCertChainFile, TrustManagerFactory trustManagerFactory,
            Iterable<String> ciphers, Iterable<String> nextProtocols,
            long sessionCacheSize, long sessionTimeout) throws SSLException {
        this(bufPool,
                getSslFile(certChainFile),
                getSslFile(keyFile),
                keyPassword,
                getSslFile(clientCertChainFile),
                trustManagerFactory, ciphers,
                nextProtocols, sessionCacheSize, sessionTimeout);
    }

    public JdkSslServerContext(
            InputStream certChainFile, InputStream keyFile,
            InputStream clientCertChainFile) throws SSLException {
        this(null,
                certChainFile, keyFile, null,
                clientCertChainFile, null,
                null, null, 0, 0);
    }

    public JdkSslServerContext(
            SslBufferPool bufPool,
            InputStream certChainFile, InputStream keyFile, String keyPassword,
            InputStream clientCertChainFile, TrustManagerFactory trustManagerFactory,
            Iterable<String> ciphers, Iterable<String> nextProtocols,
            long sessionCacheSize, long sessionTimeout) throws SSLException {

        super(bufPool, ciphers);

        if (certChainFile == null) {
            throw new NullPointerException("certChainFile");
        }
        if (keyFile == null) {
            throw new NullPointerException("keyFile");
        }

        if (nextProtocols != null && nextProtocols.iterator().hasNext()) {
            if (!JettyNpnSslEngine.isAvailable()) {
                throw new SSLException("NPN/ALPN unsupported: " + nextProtocols);
            }

            List<String> list = new ArrayList<String>();
            for (String p: nextProtocols) {
                if (p == null) {
                    break;
                }
                list.add(p);
            }

            this.nextProtocols = Collections.unmodifiableList(list);
        } else {
            this.nextProtocols = Collections.emptyList();
        }

        try {
            // Initialize the SSLContext to work with our key managers.
            ctx = SSLContext.getInstance(PROTOCOL);
            KeyManagerFactory kmf = buildKeyManager(certChainFile, keyFile, keyPassword);

            if (clientCertChainFile != null) {
                trustManagerFactory = buildTrustManager(clientCertChainFile);
            }
            TrustManager[] trustManagers = null;
            if (trustManagerFactory != null) {
                trustManagers = trustManagerFactory.getTrustManagers();
            }

            ctx.init(kmf.getKeyManagers(), trustManagers, null);

            SSLSessionContext sessCtx = ctx.getServerSessionContext();
            if (sessionCacheSize > 0) {
                sessCtx.setSessionCacheSize((int) Math.min(sessionCacheSize, Integer.MAX_VALUE));
            }
            if (sessionTimeout > 0) {
                sessCtx.setSessionTimeout((int) Math.min(sessionTimeout, Integer.MAX_VALUE));
            }
        } catch (Exception e) {
            throw new SSLException("failed to initialize the server-side SSL context", e);
        }
    }

    @Override
    public boolean isClient() {
        return false;
    }

    @Override
    public List<String> nextProtocols() {
        return nextProtocols;
    }

    @Override
    public SSLContext context() {
        return ctx;
    }
}
