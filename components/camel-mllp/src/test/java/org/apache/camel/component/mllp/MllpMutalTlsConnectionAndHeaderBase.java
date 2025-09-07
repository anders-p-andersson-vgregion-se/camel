/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.component.mllp;

import java.io.File;
import java.net.URI;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.camel.CamelContext;
import org.apache.camel.EndpointInject;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.jsse.*;
import org.apache.camel.test.AvailablePortFinder;
import org.apache.camel.test.junit.rule.mllp.MllpClientResource;
import org.apache.camel.test.junit5.CamelTestSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Does mTLS connection with MLLP and asserts that the headers are properly set.
 */
public class MllpMutalTlsConnectionAndHeaderBase extends CamelTestSupport {

    public static final String WANTS_CLIENT_AUTHENTICATION = "sslContextParametersWantsClientAuthentication";
    public static final String REQUIRES_CLIENT_AUTHENTICATION = "sslContextParametersRequiresClientAuthentication";
    public static final String NO_CLIENT_AUTHENTICATION = "sslContextParametersNoClientAuthentication";
    public static final String WITH_ONLY_TRUSTSTORE = "sslContextParametersWithOnlyTruststore";
    protected String EXPECTED_CERT_SUBJECT_NAME;
    protected String EXPECTED_CERT_ISSUER_NAME;
    protected String EXPECTED_CERT_SERIAL_NO;
    protected Date EXPECTED_CERT_NOT_BEFORE;
    protected Date EXPECTED_CERT_NOT_AFTER;

    @RegisterExtension
    public MllpClientResource mllpClient = new MllpClientResource();

    @EndpointInject("mock://result")
    protected MockEndpoint result;

    /**
     * Creates an SSLContextParameters object with a key and truststore so that mTLS is conducted.
     *
     * @return           SSLContextParamters with both keystore and truststore paramters.
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    private SSLContextParameters createSslContextParameters(ClientAuthentication clientAuthentication) throws Exception {
        KeyStoreParameters ksp = new KeyStoreParameters();
        ksp.setResource(this.getClass().getClassLoader().getResource("keystore.jks").toString());
        ksp.setPassword("password");

        KeyManagersParameters kmp = new KeyManagersParameters();
        kmp.setKeyPassword("password");
        kmp.setKeyStore(ksp);

        TrustManagersParameters tmp = new TrustManagersParameters();
        tmp.setKeyStore(ksp);

        SSLContextParameters sslContextParameters = new SSLContextParameters();
        sslContextParameters.setKeyManagers(kmp);
        sslContextParameters.setTrustManagers(tmp);

        extractExpectedSSLCertHeaderValuesFromActualCertificate(ksp);

        sslContextParameters.setServerParameters(new SSLContextServerParameters());
        sslContextParameters.getServerParameters().setClientAuthentication(clientAuthentication.name());

        return sslContextParameters;
    }

    /**
     * Extracts values from the certificate the client will use to be used for validation during the tests.
     *
     * @param  ksp       KeyStoreParameters object created from SSLContextParameters creation. Holds the certificate
     *                   information.
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    private void extractExpectedSSLCertHeaderValuesFromActualCertificate(KeyStoreParameters ksp)
            throws Exception {
        File certFile = new File(URI.create(ksp.getResource()));
        char[] password = ksp.getPassword().toCharArray();

        KeyStore ks = KeyStore.getInstance(certFile, password);
        X509Certificate certificate = (X509Certificate) ks.getCertificate("testKey");

        EXPECTED_CERT_ISSUER_NAME = certificate.getIssuerX500Principal().toString();
        EXPECTED_CERT_SUBJECT_NAME = certificate.getSubjectX500Principal().toString();
        EXPECTED_CERT_SERIAL_NO = certificate.getSerialNumber().toString();
        EXPECTED_CERT_NOT_BEFORE = certificate.getNotBefore();
        EXPECTED_CERT_NOT_AFTER = certificate.getNotAfter();

        // Be really sure the expected headers aren't null as expectedHeaderReceived can accept null values,
        // which could create false positive test results.
        Assertions.assertNotNull(EXPECTED_CERT_ISSUER_NAME);
        Assertions.assertNotNull(EXPECTED_CERT_SUBJECT_NAME);
        Assertions.assertNotNull(EXPECTED_CERT_SERIAL_NO);
        Assertions.assertNotNull(EXPECTED_CERT_NOT_BEFORE);
        Assertions.assertNotNull(EXPECTED_CERT_NOT_AFTER);
    }

    /**
     * Creates a SSLContextParameters object with only a truststore. With this, the client will only do TLS connection,
     * it will not send its own certificate for validation.
     *
     * @return           SSLContextParameter object with only a truststore configured.
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    private SSLContextParameters createSslContextParametersWithOnlyTruststore() {
        KeyStoreParameters ksp = new KeyStoreParameters();
        ksp.setResource(this.getClass().getClassLoader().getResource("keystore.jks").toString());
        ksp.setPassword("password");

        TrustManagersParameters tmp = new TrustManagersParameters();
        tmp.setKeyStore(ksp);

        SSLContextParameters sslContextParameters = new SSLContextParameters();
        sslContextParameters.setTrustManagers(tmp);

        return sslContextParameters;
    }

    /**
     * Registers sslContextParametes, both of them, to camel context.
     *
     * @return           camelContext.
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    @Override
    protected CamelContext createCamelContext() throws Exception {
        mllpClient.setMllpHost("localhost");
        mllpClient.setMllpPort(AvailablePortFinder.getNextAvailable());

        DefaultCamelContext context = (DefaultCamelContext) super.createCamelContext();

        context.setUseMDCLogging(true);
        context.getCamelContextExtension().setName(this.getClass().getSimpleName());

        context.getRegistry().bind(WANTS_CLIENT_AUTHENTICATION,
                createSslContextParameters(ClientAuthentication.WANT));
        context.getRegistry().bind(REQUIRES_CLIENT_AUTHENTICATION,
                createSslContextParameters(ClientAuthentication.REQUIRE));
        context.getRegistry().bind(NO_CLIENT_AUTHENTICATION,
                createSslContextParameters(ClientAuthentication.NONE));

        SSLContextParameters sslContextParametersWithOnlyTruststore = createSslContextParametersWithOnlyTruststore();
        context.getRegistry().bind(WITH_ONLY_TRUSTSTORE, sslContextParametersWithOnlyTruststore);
        return context;
    }

    protected String assembleEndpointUri(String sslContextParameters) {
        return String.format("mllp://%s:%d?sslContextParameters=#%s", mllpClient.getMllpHost(), mllpClient.getMllpPort(),
                sslContextParameters);
    }
}
