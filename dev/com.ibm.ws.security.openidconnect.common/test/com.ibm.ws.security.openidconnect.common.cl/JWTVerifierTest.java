/*
 * IBM Confidential
 * 
 * OCO Source Materials
 * 
 * Copyright IBM Corp. 2013
 * 
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */
package com.ibm.ws.security.openidconnect.common.cl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.joda.time.Instant;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import test.common.SharedOutputManager;

import com.ibm.oauth.core.api.error.OAuthException;
import com.ibm.oauth.core.internal.oauth20.OAuth20Constants;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.JWTToken;
import com.ibm.ws.security.oauth_oidc.fat.commonTest.TestSettings;
import com.ibm.ws.security.openidconnect.common.cl.JWTVerifier;
import com.ibm.ws.security.openidconnect.token.JWSHeader;
import com.ibm.ws.security.openidconnect.token.JWTPayload;
import com.ibm.ws.security.openidconnect.token.WSJsonToken;

public class JWTVerifierTest {

    static SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    @Rule
    public TestRule managerRule = outputMgr;

    private static final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };
    // for creating a testing JWT Token
    final static TestSettings mockSettings = mock.mock(TestSettings.class, "mockSettings");

    final String clientId = "client01";
    //final String key = "secret";
    final String key = "secretsecretsecretsecretsecretsecret";  // jose4j wants 256 bits minimum;
    final String defaultAlgorithm = "HS256";
    final String defaultCompany = "unittest.ibm.com";
    final String defaultAudience = "audience.ibm.com";
    final String defaultKeyId = "UniqueKey1";
    //final String defaultClientSecret = "secret";
    final String defaultClientSecret = "secretsecretsecretsecretsecretsecret";  // jose4j wants 256 bits minimum;

    final String tokenRS256 = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleWlkcnMyNTYifQ.eyJpc3MiOiJjbGllb" +
            "nQwMSIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUiLCJpYXQiOjE0MDc4NjcxMzYsI" +
            "mV4cCI6MTQwNzg3NDMzNiwic3ViIjoidGVzdHVzZXIiLCJhdWQiOiJodHRwczovL" +
            "2xvY2FsaG9zdDo4OTQ1L29pZGMvZW5kcG9pbnQvT2lkY0NvbmZpZ1NhbXBsZSJ9." +
            "Z8DMQeA0zPEr-Bv2rx9W1_Lf_4mQCT8Z-byoI0TbwF8Q2l4mJ1otwnW8JH7J2ma8" +
            "V9aO275kxVmObIgWiJo25SoSnlIkng72yLwB2e50xpUQk0U5nVPbdZ0atWPJDA9a" +
            "d-VaaG1H-9LVyHrUMROaFQVE0qjO5L6un4amBbyIdSFnjY-q2llhOyHram3KvP1_" +
            "RHv7VePTEWu7UMptfv1mHPD90j7TBG5rdmiBr3i_PNo1x2aiCcqz9IYuu3ayo-z4" +
            "2SSz7Oa8B-14SjvPIUTpren9TsW9Os_Az3tkisO51yTCTHZFwrCovrz3MrzKLaXW" +
            "P4tcm_As8Z9yJV5z-vo9dg";

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        //outputMgr.captureStreams();
        //outputMgr.trace("*=all");
    }

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() {
        mock.assertIsSatisfied();
        //outputMgr.resetStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        //outputMgr.restoreStreams();
        //outputMgr.trace("*=all=disabled");
    }

    @Test
    public void testJWTVerifierInitGetMethodsInitToken() {
        final String methodName = "testJWTVerifierGetMethodsInitToken";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    defaultAlgorithm,
                    tokenString,
                    300L);
            JWSHeader jwsHeader = jwtVerifier.getJwsHeader();
            jwtVerifier._jsonToken = null;
            JWTPayload jwtPayload = jwtVerifier.getPayload();
            jwtVerifier._jsonToken = null;
            WSJsonToken jsonToken = jwtVerifier.getJsonToken();

            Set<Map.Entry<String, Object>> headers = jwsHeader.entrySet();
            for (Map.Entry<String, Object> header : headers) {
                String headKey = header.getKey();
                Object headValue = header.getValue();
                System.out.println("Header key:" + headKey + " value:" + headValue);
            }
            String algorithm = jwsHeader.getAlgorithm();
            assertEquals("Algorithm is not " + defaultAlgorithm + " but " + algorithm,
                    defaultAlgorithm, algorithm);
            String keyId = jwsHeader.getKeyId();
            assertEquals("jwt key id is not " + defaultKeyId + " but " + keyId,
                    defaultKeyId, keyId);

            Set<Map.Entry<String, Object>> claims = jwtPayload.entrySet();
            for (Map.Entry<String, Object> claim : claims) {
                String claimKey = claim.getKey();
                Object claimValue = claim.getValue();
                System.out.println("Claim key:" + claimKey + " value:" + claimValue);
            }

            String issuer = jsonToken.getIssuer();
            assertEquals("Does not get the defaultCompany but '" + issuer + "'", issuer, defaultCompany);

            Date currentDate = new Date();
            Long currentSeconds = currentDate.getTime() / 1000;
            long instant = jsonToken.getIssuedAt();
           // long jsonTimeSeconds = instant / 1000;
            long jsonTimeSeconds = instant;
            long lDifferent = currentSeconds - jsonTimeSeconds;
            if (lDifferent < 0)
                lDifferent *= -1;
            assertTrue("Time differences should not over 5 seconds currentSeconds:" + currentSeconds + " iat:" + jsonTimeSeconds, lDifferent <= 5);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testJWTVerifierInitGetMethodsVerifySignature() {
        final String methodName = "testJWTVerifierGetMethodsVsrifySingature";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();  //bt: boom
            JWSHeader jwsHeader = jwtVerifier.getJwsHeader();
            JWTPayload jwtPayload = jwtVerifier.getPayload();
            WSJsonToken jsonToken = jwtVerifier.getJsonToken();

            Set<Map.Entry<String, Object>> headers = jwsHeader.entrySet();
            for (Map.Entry<String, Object> header : headers) {
                String headKey = header.getKey();
                Object headValue = header.getValue();
                System.out.println("Header key:" + headKey + " value:" + headValue);
            }

            Set<Map.Entry<String, Object>> claims = jwtPayload.entrySet();
            for (Map.Entry<String, Object> claim : claims) {
                String claimKey = claim.getKey();
                Object claimValue = claim.getValue();
                System.out.println("Claim key:" + claimKey + " value:" + claimValue);
            }

            String issuer = jsonToken.getIssuer();
            assertEquals("Does not get the defaultCompany but '" + issuer + "'", issuer, defaultCompany);

            Date currentDate = new Date();
            Long currentSeconds = currentDate.getTime() / 1000;
            long instant = jsonToken.getIssuedAt();
            //long jsonTimeSeconds = instant / 1000;\
            long jsonTimeSeconds = instant ;
            long lDifferent = currentSeconds - jsonTimeSeconds;
            if (lDifferent < 0)
                lDifferent *= -1;
            assertTrue("Time differences should not over 5 seconds", lDifferent <= 5);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testJWTVerifierTwoSegmentTokenString() {
        final String methodName = "testJWTVerifierTwoSegmentTokenString";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            int index = tokenString.indexOf(".");
            index = tokenString.indexOf(".", index);
            tokenString = tokenString.substring(0, index + 1);
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierBadSegmentTokenString() {
        final String methodName = "testJWTVerifierTwoSegmentTokenString";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            int index = tokenString.indexOf(".");
            index = tokenString.indexOf(".", index);
            tokenString = tokenString.substring(0, index);
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierNullTokenString() {
        final String methodName = "testJWTVerifierNullTokenString";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = null; // create and get a default Token String
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierBadVerifyAlg() {
        final String methodName = "testJWTVerifierBadVerifyAlg";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    "RS256",
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierBadKey() {
        final String methodName = "testJWTVerifierBadKey";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            String badSecret = "badSecret";
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    badSecret.getBytes(),
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierBadKeyClass() {
        final String methodName = "testJWTVerifierBadKeyClass";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            String tokenString = getJwtTokenString(); // create and get a default Token String
            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    Long.valueOf(654321L), // bad key type class 
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierExpires() {
        final String methodName = "testJWTVerifierExpires";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            JWTToken jwtToken = createJwtToken(defaultCompany, defaultKeyId, defaultClientSecret);
            Instant passedInstant = jwtToken.addToCurrentTime(-7200000L); // - 2hour
            jwtToken.setPayloadIat(passedInstant);
            jwtToken.setPayloadExp(3600L); // add 1 hours to IAT
            String tokenString = getJwtTokenString(jwtToken); // create and get a default Token String

            JWTVerifier jwtVerifier = new JWTVerifier(clientId,
                    key,
                    defaultAlgorithm,
                    tokenString, 300L);
            jwtVerifier.verifySignature();
        } catch (OAuthException e) {
            // this is expected since no token string provided
            return;
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
        fail("Shoud have failed but not");
    }

    @Test
    public void testJWTVerifierSimple() {
        final String methodName = "testJWTVerifierSimple";
        System.out.println("----------------" + methodName + "-----------------");
        try {
            JWTVerifier jwtVerifier = new JWTVerifier(tokenRS256);
            String alg = jwtVerifier.getAlgHeader();
            assertEquals("Should get the Alg Header as RS256", OAuth20Constants.SIGNATURE_ALGORITHM_RS256, alg);
            String client = jwtVerifier.getIssFromPayload();
            assertEquals("Should get the iss claim in payload as client01", "client01", client);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    //************* utilities *******
    JWTToken createJwtToken(String issuerCompany, String keyId, String client_secret) {
        final String password = client_secret;
        JWTToken jwtToken = null;

        mock.checking(new Expectations() {
            {
                one(mockSettings).getClientSecret();
                will(returnValue(password));
            }
        });
        try {
            jwtToken = new JWTToken(issuerCompany, keyId, mockSettings);
            // strJwtToken = jwtToken.getJWTTokenString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return jwtToken;
    }

    JWTToken createJwtToken() {
        JWTToken jwtToken = null;
        try {
            jwtToken = createJwtToken(defaultCompany, defaultKeyId, defaultClientSecret);
            Date currentDate = new Date();
            Long currentSeconds = currentDate.getTime() / 1000;
            jwtToken.setPayloadIat(null);
            jwtToken.setPayloadExp(currentSeconds + 3600); // 1 hours
        } catch (Exception e) {
            e.printStackTrace();
        }
        return jwtToken;
    }

    String getJwtTokenString() {
        try {
            return createJwtToken().getJWTTokenString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    String getJwtTokenString(String issuerCompany, String keyId, String client_secret) {
        try {
            return createJwtToken(issuerCompany, keyId, client_secret).getJWTTokenString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    String getJwtTokenString(JWTToken jwtToken) {
        try {
            return jwtToken.getJWTTokenString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
