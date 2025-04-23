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

import javax.net.ssl.SSLSession;

import org.apache.camel.CamelContext;
import org.apache.camel.EndpointInject;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.apache.camel.component.mock.MockEndpoint;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.jsse.KeyManagersParameters;
import org.apache.camel.support.jsse.KeyStoreParameters;
import org.apache.camel.support.jsse.SSLContextParameters;
import org.apache.camel.support.jsse.TrustManagersParameters;
import org.apache.camel.test.AvailablePortFinder;
import org.apache.camel.test.junit.rule.mllp.MllpClientResource;
import org.apache.camel.test.junit5.CamelTestSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * Does mTLS connection with MLLP and asserts that the headers are properly set.
 */
public class MllpMutalTlsConnectionAndHeaderTest extends CamelTestSupport {

    private String EXPECTED_CERT_SUBJECT_NAME;
    private String EXPECTED_CERT_ISSUER_NAME;
    private String EXPECTED_CERT_SERIAL_NO;
    private Date EXPECTED_CERT_NOT_BEFORE;
    private Date EXPECTED_CERT_NOT_AFTER;

    @RegisterExtension
    public MllpClientResource mllpClient = new MllpClientResource();

    @EndpointInject("mock://result")
    MockEndpoint result;

    /**
     * Creates a SSLContextParameters object with a key and truststore so that mTLS is conducted.
     *
     * @return           SSLContextParamters with both keystore and truststore paramters.
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    public SSLContextParameters createSslContextParameters() throws Exception {
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

        // For reasons
        EXPECTED_CERT_ISSUER_NAME = certificate.getIssuerX500Principal().getName();
        EXPECTED_CERT_SUBJECT_NAME = certificate.getSubjectX500Principal().getName();
        EXPECTED_CERT_SERIAL_NO = certificate.getSerialNumber().toString();
        EXPECTED_CERT_NOT_BEFORE = certificate.getNotBefore();
        EXPECTED_CERT_NOT_AFTER = certificate.getNotAfter();
    }

    /**
     * Creates a SSLContextParameters object with only a truststore. With this, the client will only do TLS connection,
     * it will not send its own certificate for validation.
     *
     * @return           SSLContextParameter object with only a truststore configured.
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    public SSLContextParameters createSslContextParametersWithOnlyTruststore() {
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

        SSLContextParameters sslContextParameters = createSslContextParameters();
        context.getRegistry().bind("sslContextParameters", sslContextParameters);

        SSLContextParameters sslContextParametersWithOnlyTruststore = createSslContextParametersWithOnlyTruststore();
        context.getRegistry().bind("sslContextParametersWithOnlyTruststore", sslContextParametersWithOnlyTruststore);
        return context;
    }

    /**
     * Creates test route.
     *
     * @return RouteBuilder.
     */
    @Override
    protected RouteBuilder createRouteBuilder() {
        return new RouteBuilder() {
            String routeId = "mllp-ssl-sender";

            public void configure() {
                fromF("mllp://%d?sslContextParameters=#sslContextParameters", mllpClient.getMllpPort())
                        .log(LoggingLevel.INFO, routeId, "Received Message: ${body}")
                        .to(result);
            }
        };
    }

    /**
     * This test does TLS connection without client sending its certificate, i.e. no mTLS. In this case, none of the
     * MLLP_SSL_CLIENT_CERT* headers should exist as the client didn't provide a certificate.
     * <p/>
     * The MLLP_SSL_SESSION header is asserted to not be null. This header has the SSLSession object, and since this is
     * a TLS connection (just not mTLS), it should be present.
     *
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    @Test
    public void testTlsNoClientCerticateInOutWithMllpConsumer() throws Exception {

        String hl7Message = "MSH|^~\\&|CLIENT|TEST|SERVER|ACK|20231118120000||ADT^A01|123456|T|2.6\r" +
                            "EVN|A01|20231118120000\r" +
                            "PID|1|12345|67890||DOE^JOHN||19800101|M|||123 Main St^^Springfield^IL^62704||(555)555-5555|||||S\r"
                            +
                            "PV1|1|O\r";

        result.expectedBodiesReceived(hl7Message);

        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_SUBJECT_NAME, null);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_ISSUER_NAME, null);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_SERIAL_NO, null);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_NOT_BEFORE, null);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_NOT_AFTER, null);

        result.expectedMessagesMatches(
                exchange -> exchange.getMessage().getHeader(MllpConstants.MLLP_SSL_SESSION, SSLSession.class) != null);

        String endpointUri = String.format("mllp://%s:%d?sslContextParameters=#sslContextParametersWithOnlyTruststore",
                mllpClient.getMllpHost(), mllpClient.getMllpPort());
        template.sendBody(endpointUri, hl7Message);
        result.assertIsSatisfied();

    }

    /**
     * This test does a proper mTLS connection with MLLP. Here the headers are asserted to be present and non null, all
     * of the MLLP_SSL* headers.
     *
     * @throws Exception if anything goes wrong and then should fail the test.
     */
    @Test
    public void testMutalTlsInOutWithMllpConsumer() throws Exception {

        String hl7Message = "MSH|^~\\&|CLIENT|TEST|SERVER|ACK|20231118120000||ADT^A01|123456|T|2.6\r" +
                            "EVN|A01|20231118120000\r" +
                            "PID|1|12345|67890||DOE^JOHN||19800101|M|||123 Main St^^Springfield^IL^62704||(555)555-5555|||||S\r"
                            +
                            "PV1|1|O\r";

        result.expectedBodiesReceived(hl7Message);

        // Be really sure the expected headers aren't null as expectedHeaderReceived can accept null values,
        // which could create false positive test results.
        Assertions.assertNotNull(EXPECTED_CERT_ISSUER_NAME);
        Assertions.assertNotNull(EXPECTED_CERT_SUBJECT_NAME);
        Assertions.assertNotNull(EXPECTED_CERT_NOT_BEFORE);
        Assertions.assertNotNull(EXPECTED_CERT_NOT_AFTER);
        Assertions.assertNotNull(EXPECTED_CERT_SERIAL_NO);

        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_SUBJECT_NAME, EXPECTED_CERT_SUBJECT_NAME);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_ISSUER_NAME, EXPECTED_CERT_ISSUER_NAME);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_SERIAL_NO, EXPECTED_CERT_SERIAL_NO);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_NOT_BEFORE, EXPECTED_CERT_NOT_BEFORE);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_NOT_AFTER, EXPECTED_CERT_NOT_AFTER);
        result.expectedMessagesMatches(
                exchange -> exchange.getMessage().getHeader(MllpConstants.MLLP_SSL_SESSION, SSLSession.class) != null);

        String endpointUri = String.format("mllp://%s:%d?sslContextParameters=#sslContextParameters",
                mllpClient.getMllpHost(), mllpClient.getMllpPort());
        template.sendBody(endpointUri, hl7Message);
        result.assertIsSatisfied();

    }
}
