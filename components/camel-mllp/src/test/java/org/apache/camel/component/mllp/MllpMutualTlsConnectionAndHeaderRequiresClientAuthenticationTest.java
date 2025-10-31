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

import java.net.SocketException;

import org.apache.camel.CamelExecutionException;
import org.apache.camel.LoggingLevel;
import org.apache.camel.builder.RouteBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Does mTLS connection with MLLP and asserts that the headers are properly set.
 */
public class MllpMutualTlsConnectionAndHeaderRequiresClientAuthenticationTest extends MllpMutualTlsConnectionAndHeaderBase {
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
                fromF(assembleEndpointUri(REQUIRES_CLIENT_AUTHENTICATION))
                        .log(LoggingLevel.INFO, routeId, "Received Message: ${body}")
                        .to(result);
            }
        };
    }

    /**
     * This test does TLS connection without a client sending its certificate, i.e., no mTLS. As the server is
     * configured to require client authentication, this should fail.
     *
     */
    @Test
    public void testSendingTlsWithNoClientCertificateToMllpConsumerWhichRequiresClientAuthentication() {
        String hl7Message = "MSH|^~\\&|CLIENT|TEST|SERVER|ACK|20231118120000||ADT^A01|123456|T|2.6\r" +
                            "EVN|A01|20231118120000\r" +
                            "PID|1|12345|67890||DOE^JOHN||19800101|M|||123 Main St^^Springfield^IL^62704||(555)555-5555|||||S\r"
                            +
                            "PV1|1|O\r";
        try {
            template.sendBody(assembleEndpointUri(WITH_ONLY_TRUSTSTORE), hl7Message);
            Assertions.fail("Should not be able to connect without a client certificate");
        } catch (CamelExecutionException e) {
            Assertions.assertInstanceOf(SocketException.class, e.getCause().getCause().getCause());
        }
    }

    /**
     * This test does a proper mTLS connection with MLLP. Here the headers are asserted to be present and non-null, all
     * the MLLP_SSL* headers.
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

        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_SUBJECT_NAME, EXPECTED_CERT_SUBJECT_NAME);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_ISSUER_NAME, EXPECTED_CERT_ISSUER_NAME);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_SERIAL_NO, EXPECTED_CERT_SERIAL_NO);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_NOT_BEFORE, EXPECTED_CERT_NOT_BEFORE);
        result.expectedHeaderReceived(MllpConstants.MLLP_SSL_CLIENT_CERT_NOT_AFTER, EXPECTED_CERT_NOT_AFTER);

        template.sendBody(assembleEndpointUri(REQUIRES_CLIENT_AUTHENTICATION), hl7Message);
        result.assertIsSatisfied();

    }
}
