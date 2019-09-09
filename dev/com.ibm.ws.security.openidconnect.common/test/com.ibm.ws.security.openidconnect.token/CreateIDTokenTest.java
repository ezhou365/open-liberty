package com.ibm.ws.security.openidconnect.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.MethodRule;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.ibm.ws.security.openidconnect.token.Payload;

public class CreateIDTokenTest {

    //private static final byte[] SYMMETRIC_KEY = "thisistestsharedkeyforjasontoken".getBytes();
    Date date = new Date();
    private static final Duration SKEW = Duration.standardMinutes(3);
    public FakeClock clock = new FakeClock(SKEW);
    
    @Rule
    public TestWatcher watch = new TestWatcher(){
        public void starting(Description d){
            System.out.println("****** starting: " + d.getMethodName());
        }
        public void finished(Description d){
            System.out.println("****** finished: " + d.getMethodName());
        }
        public void failed(Throwable t, Description d){
            System.out.println("****** failed: " + d.getMethodName());
        }
    };

    @SuppressWarnings("unused")
    @Test
    // Create IDtoken from signer, claims, and key
    public void createIdTokenNoAtHash() {

        boolean isTokenCreated = true;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setAudience("http://www.ibm.com");
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        try {
            IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue);
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenCreated = false;
        }

        assertTrue("Token is not created", isTokenCreated);
    }

    @Test
    // Create plain IDtoken from header, claims
    public void createPlainTextIdToken() {

        boolean isTokenCreated = true;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("none");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        payLoad.setAudience("http://www.ibm.com");
        payLoad.setExpirationTimeSeconds((date.getTime() + 60000) / 1000);
        payLoad.setIssuer("ibm.com");

        try {
            IDToken idToken1 = new IDToken(jwsHeader, payLoad);
            idToken1.createPlainTextJWT();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenCreated = false;
        }

        assertTrue("Token is not created", isTokenCreated);
    }

    @SuppressWarnings({ "unchecked", "unused" })
    @Test
    // verify plain text IDtoken
    public void verifyPlainTextIdToken() {

        boolean isTokenVerified = false;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("none");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        List<String> list = new ArrayList<String>();
        list.add("https://app-one.com");
        list.add("https://app-two.com");
        payLoad.setAudience(list);
        payLoad.setExpirationTimeSeconds((date.getTime() + 60000) / 1000);
        payLoad.setIssuer("ibm.com");
        payLoad.setAuthorizedParty("https://app-one.com");
        payLoad.setJwtId("id123");
        payLoad.setNonce("nonce123");
        payLoad.setType("type123");
        payLoad.setSubject("subject123");

        try {
            IDToken idToken1 = new IDToken(jwsHeader, payLoad);
            String plainEncodedJWT = idToken1.createPlainTextJWT();
            IDToken idToken2 = new IDToken(plainEncodedJWT, "https://app-one.com", "ibm.com", "none");
            isTokenVerified = idToken2.verify();

            list = (List<String>) idToken2.getPayload().get("aud");
            if (list != null) {
                for (String str : list) {
                    //System.out.println("IDToken payload audience data = " + str);
                }
            }
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("Token is not verified.", isTokenVerified);
    }

    @Test
    // verify signed IDtoken 
    public void verifyIdToken() {

        boolean isTokenVerified = false;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuer("ibm.com");
        List<String> list = new ArrayList<String>();
        list.add("https://app-one.com");
        list.add("https://app-two.com");
        payLoad.setAudience(list);
        payLoad.setAuthorizedParty("https://app-one.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        try {
            // IDToken idToken1 = new IDToken(jwtHeader, jwtClaims, keyValue);
            IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue);
            String signedIDToken = idToken1.getSignedJWTString();
            idToken1 = new IDToken(signedIDToken, keyValue, "https://app-one.com", "ibm.com", "HS256");
            isTokenVerified = idToken1.verify();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("Token is not valid", isTokenVerified);
    }

    @Test
    // verify that we receive this exception
    public void verifyIdTokenValidationFailedException() {

        boolean isException = false;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("none");
        //jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuer("ibm.com");
        List<String> list = new ArrayList<String>();
        list.add("https://app-one.com");
        list.add("https://app-two.com");
        payLoad.setAudience(list);
        payLoad.setAuthorizedParty("https://app-one.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        try {
            // IDToken idToken1 = new IDToken(jwtHeader, jwtClaims, keyValue);
            IDToken idToken1 = new IDToken(jwsHeader, payLoad);
            String unsignedIDToken = idToken1.getJWTString();
            idToken1 = new IDToken(unsignedIDToken, keyValue, "https://app-one.com", "ibm.com", "HS256");
            idToken1.verify();
        } catch (IDTokenValidationFailedException e) {            
            // OIDC_IDTOKEN_SIGNATURE_VERIFY_MISSING_SIGNATURE_ERR=CWWKS1760E
            // Since the nls bundle is moved to clients.common project, unit test can't see it.
            // So, accept either raw or looked up message.
            String strMsg = e.getMessage();
            assertTrue("Did not get CWWKS1760E: error message but " + strMsg, 
                    strMsg.contains("CWWKS1760E:") || strMsg.contains("OIDC_IDTOKEN_SIGNATURE_VERIFY_MISSING_SIGNATURE_ERR"));
            isException = true;
        } catch (Exception ex) {
            System.out.println("Exception:  " + ex + " message:" + ex.getMessage());
            ex.printStackTrace(System.out);
            // TODO Auto-generated catch block        	
        }

        assertTrue("Did not get expected exception", isException);
    }

    @Test
    // verify that we can validate IDToken without specifying algorithm
    public void verifyIdTokenWithoutRPSignAlgorithm() {

        boolean isTokenVerified = false;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuer("ibm.com");
        List<String> list = new ArrayList<String>();
        list.add("https://app-one.com");
        list.add("https://app-two.com");
        payLoad.setAudience(list);
        payLoad.setAuthorizedParty("https://app-one.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        try {
            IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue);

            String signedIDToken = idToken1.getSignedJWTString();
            idToken1 = new IDToken(signedIDToken, keyValue, "https://app-one.com", "ibm.com", "none");
            isTokenVerified = idToken1.verify();
        } catch (Exception ex) {
            System.out.println("Exception:  " + ex.getMessage());
            // TODO Auto-generated catch block
            isTokenVerified = false;

        }

        assertTrue("Token is not verified", isTokenVerified);
    }

    @SuppressWarnings("unused")
    @Test
    // Create ID token from signer, claims, key, and access token
    public void createIdTokenWithAtHash() {

        boolean isTokenCreated = true;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        payLoad.setAudience("http://www.ibm.com");
        payLoad.setExpirationTimeSeconds((date.getTime() + 60000) / 1000);
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();
        String accessToken = "OiOBfMeEKvXte5LFdirNgx4f46uYed3MlLQmdxlC";

        try {
            IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue, accessToken);
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenCreated = false;
        }

        assertTrue("Token is not created", isTokenCreated);
    }

    @Test
    // Verify ID token & access token
    public void verifyIdTokenWithAtHash() {

        boolean isTokenVerified = false;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com");
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();
        String accessToken = "OiOBfMeEKvXte5LFdirNgx4f46uYed3MlLQmdxlC";

        try {
            // IDToken idToken1 = new IDToken(jwtHeader, jwtClaims, keyValue);
            IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue, accessToken);
            String signedIDToken = idToken1.getSignedJWTString();
            idToken1 = new IDToken(signedIDToken, keyValue, "https://app-one.com", "ibm.com", "HS256", accessToken);
            isTokenVerified = idToken1.verify();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("Token is not verified", isTokenVerified);
    }

    @Test
    public void testIssuedAtAfterExpiration() throws Exception {
        setUp();
        Instant issuedAt = clock.now();
        Instant expiration = issuedAt.minus(Duration.standardSeconds(1));
        checkTimeFrameIllegalStateException(issuedAt, expiration);
    }

    @Test
    public void testIssueAtSkew() throws Exception {
        setUp();
        Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardMinutes(1)));
        Instant expiration = issuedAt.plus(Duration.standardSeconds(1));
        checkTimeFrame(issuedAt, expiration);
    }

    @Test
    public void testIssueAtTooMuchSkew() throws Exception {
        setUp();
        Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardMinutes(1)));  // issued 4 minutes into the future
        Instant expiration = issuedAt.plus(Duration.standardSeconds(1));  // expire one second later.
        //System.out.println("IssueAtTooMuchSKEW, issued at = " + issuedAt + ", Expire = " + expiration);
        checkTimeFrameIllegalStateException(issuedAt, expiration);
    }

    @Test
    public void testExpirationSkew() throws Exception {
        setUp();
        Instant expiration = clock.now().minus(SKEW.minus(Duration.standardMinutes(1)));
        Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
        checkTimeFrame(issuedAt, expiration);
    }

    @Test
    public void testExpirationTooMuchSkew() throws Exception {
        setUp();
        Instant expiration = clock.now().minus(SKEW.plus(Duration.standardMinutes(1)));
        Instant issuedAt = expiration.minus(Duration.standardSeconds(1));
        checkTimeFrameIllegalStateException(issuedAt, expiration);
    }

    @Test
    public void testIssuedAtNull() throws Exception {
        setUp();
        Instant expiration = clock.now().plus(Duration.standardSeconds(1));/*
                                                                            * clock.now().minus(
                                                                            * SKEW.minus(Duration.standardSeconds(1)));
                                                                            */
        checkTimeFrame(null, expiration);
    }

    @Test
    public void testExpirationNull() throws Exception {
        setUp();
        Instant issuedAt = clock.now().plus(SKEW.minus(Duration.standardSeconds(1)));
        checkTimeFrame(issuedAt, null);
    }

    @Test
    public void testIssueAtNullExpirationNull() throws Exception {
        setUp();
        checkTimeFrame(null, null);
    }

    @Test
    public void testFutureToken() throws Exception {
        setUp();
        Instant issuedAt = clock.now().plus(SKEW.plus(Duration.standardMinutes(1))); // 4 min in future
        Instant expiration = issuedAt.plus(Duration.standardDays(1));
        checkTimeFrameIllegalStateException(issuedAt, expiration);
    }

    @Test
    public void testPastToken() throws Exception {
        setUp();
        Instant expiration = clock.now().minus(SKEW.plus(Duration.standardMinutes(1)));
        Instant issuedAt = expiration.minus(Duration.standardDays(1));
        checkTimeFrameIllegalStateException(issuedAt, expiration);
    }

    private void checkTimeFrameIllegalStateException(Instant issuedAt, Instant expiration)
            throws Exception {
        try {
            checkTimeFrame(issuedAt, expiration);
            junit.framework.Assert.fail("IllegalStateException should be thrown.");
        } catch (IDTokenValidationFailedException e) {
            // Pass.
        }
    }

    private void checkTimeFrame(Instant issuedAt, Instant expiration) throws Exception {
        boolean isTokenVerified = false;
        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com");
        payLoad.setIssuer("ibm.com");
        if (issuedAt != null) {
            payLoad.setIssuedAtTimeSeconds(issuedAt.getMillis() / 1000);
        }
        if (expiration != null) {
            payLoad.setExpirationTimeSeconds(expiration.getMillis() / 1000);
        }
        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue);
        String signedIDToken = idToken1.getSignedJWTString();
        IDToken idToken2 = new IDToken(signedIDToken, keyValue, "https://app-one.com", "ibm.com", "HS256");
        isTokenVerified = idToken2.verify();

        Payload payload2 = null;
        if (idToken2.getPayload() != null) {
            payload2 = idToken2.getPayload();
        }

        if (issuedAt != null) {
            assertEquals((issuedAt.getMillis() / 1000), payload2.
                    getIssuedAtTimeSeconds().longValue());
        }

        if (expiration != null) {
            assertEquals((expiration.getMillis() / 1000), payload2.
                    getExpirationTimeSeconds().longValue());
        }

        assertTrue("Token is not verified", isTokenVerified);
    }

    private void setUp() throws Exception {
        clock.setNow(new Instant());
    }

    @Test
    // Create ID token from signer, claims, key, and access token
    public void createIdTokenWithRSAKey() {

        boolean isTokenCreated = true;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("RS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        payLoad.setAudience("http://www.ibm.com");
        payLoad.setExpirationTimeSeconds((date.getTime() + 60000) / 1000);
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        String accessToken = "OiOBfMeEKvXte5LFdirNgx4f46uYed3MlLQmdxlC";

        RSAPrivateKey keyValue = null;
        try {
            keyValue = (RSAPrivateKey) generateRSAKeyPair().getPrivate();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenCreated = false;
        }

        if (isTokenCreated) {
            try {
                IDToken idToken1 = new IDToken(jwsHeader, payLoad, keyValue, accessToken);
            } catch (Exception e2) {
                e2.printStackTrace();
                System.out.println("Exception:  " + e2.getMessage());
                isTokenCreated = false;
            }
        }

        assertTrue("Token is not created", isTokenCreated);
    }

    @Test
    // Verify ID token & access token
    public void verifyIdTokenWithRSAKey() {

        boolean isTokenVerified = false;
        boolean isTokenCreated = true;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("RS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process

        payLoad.setExpirationTimeSeconds((date.getTime() + 60000) / 1000);
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        String accessToken = "OiOBfMeEKvXte5LFdirNgx4f46uYed3MlLQmdxlC";

        RSAPrivateKey privateKey = null;
        RSAPublicKey publicKey = null;

        try {
            KeyPair keyPair = generateRSAKeyPair();
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            publicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenCreated = false;
        }

        System.out.println("512 key pair->privateKey '" + privateKey + "'");
        System.out.println("512 key pair->publicKey '" + publicKey + "'");

        if (isTokenCreated) {
            try {
                IDToken idToken1 = new IDToken(jwsHeader, payLoad, privateKey, accessToken);
                String signedIDToken = idToken1.getSignedJWTString();
                idToken1 = new IDToken(signedIDToken, publicKey, "https://app-one.com", "ibm.com", "RS256", accessToken);
                isTokenVerified = idToken1.verify();
            } catch (Exception e1) {
                e1.printStackTrace();
                System.out.println("Exception:  " + e1.getMessage());
                isTokenVerified = false;
            }
        }

        assertTrue("Token is not verified", isTokenVerified);
    }

    @Test
    // kind of id_token decoder without verify the signature
    public void decodeIdTokenParloadFatTest() {

        // Change this line to your id_token string
        String tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg5OTgiLCJpYXQiOjEzODkyODI2OTEsInN1YiI6InRlc3R1c2VyIiwiZXhwIjoxMzg5Mjg2MjkxLCJhdWQiOiJjbGllbnQwMSJ9.OHBR8jnAK6ZP4ca0Uy3lBgfCVkwF1char9b7TR6XrOk";

        String[] pieces = tokenString.split(Pattern.quote(JsonTokenUtil.DELIMITER));

        String jwtHeaderSegment = pieces[0];
        String jwtPayloadSegment = pieces[1];
        //byte[] signature = Base64.decodeBase64(pieces[2]);
        JsonParser parser = new JsonParser();
        JsonObject header = parser.parse(JsonTokenUtil.fromBase64ToJsonString(jwtHeaderSegment))
                .getAsJsonObject();
        JsonObject payload = parser.parse(JsonTokenUtil.fromBase64ToJsonString(jwtPayloadSegment))
                .getAsJsonObject();
        JsonElement jElm = header.get("alg");
        String algorithm = null;
        if (jElm != null) {
            algorithm = jElm.getAsString();
        }
        //System.out.println("alg is:" + algorithm);

        String iss = getPayloadValue(payload, "iss");
        String sub = getPayloadValue(payload, "sub");
        String aud = getPayloadValue(payload, "aud");
        String exp = getPayloadValue(payload, "exp");
        String iat = getPayloadValue(payload, "iat");
        String auth_time = getPayloadValue(payload, "auth_time");
        String nonce = getPayloadValue(payload, "nonce");
        String at_hash = getPayloadValue(payload, "at_hash");
        String acr = getPayloadValue(payload, "acr");
        String amr = getPayloadValue(payload, "amr");
        String azp = getPayloadValue(payload, "azp");
        String aub_jwk = getPayloadValue(payload, "sub_jwk");

        assertNotNull("no header found", header);
        assertNotNull("no iss found", iss);
        assertNotNull("no sub found", sub);
        assertNotNull("no aud found", aud);
        assertNotNull("no exp found", exp);
        assertNotNull("no iat found", iat);
        // assertNotNull( "no at_hash found", at_hash);

        // assertNotNull( "no nonce found", nonce);
        assertEquals("signature is noy HS256 but " + algorithm, algorithm, "HS256");
    }

    @Test
    // kind of id_token decoder without verify the signature
    public void decodeIdTokenParloadImplicitTest() {

        // String tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vaGFybW9uaWM6ODAxMSIsIm5vbmNlIjoibXlOb25jZU15Tm9uY2UiLCJpYXQiOjEzODkyODYxNzAsInN1YiI6InRlc3R1c2VyIiwiZXhwIjoxMzg5Mjg5NzcwLCJhdWQiOiJjbGllbnQwMSJ9.iuqcj3SNSeos38St61fCU9alkExIsgVjVTdQfKilhrM";
        // String tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg5OTgiLCJpYXQiOjEzODkyODI2OTEsInN1YiI6InRlc3R1c2VyIiwiZXhwIjoxMzg5Mjg2MjkxLCJhdWQiOiJjbGllbnQwMSJ9.OHBR8jnAK6ZP4ca0Uy3lBgfCVkwF1char9b7TR6XrOk";
        // Change this line to your id_token string
        String tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vaGFybW9uaWM6ODAxMSIsIm5vbmNlIjoibXlOb25jZU15Tm9uY2UiLCJpYXQiOjEzODkyODYxNzAsInN1YiI6InRlc3R1c2VyIiwiZXhwIjoxMzg5Mjg5NzcwLCJhdWQiOiJjbGllbnQwMSJ9.iuqcj3SNSeos38St61fCU9alkExIsgVjVTdQfKilhrM";
        String[] pieces = tokenString.split(Pattern.quote(JsonTokenUtil.DELIMITER));

        String jwtHeaderSegment = pieces[0];
        String jwtPayloadSegment = pieces[1];
        //byte[] signature = Base64.decodeBase64(pieces[2]);
        JsonParser parser = new JsonParser();
        JsonObject header = parser.parse(JsonTokenUtil.fromBase64ToJsonString(jwtHeaderSegment))
                .getAsJsonObject();
        JsonObject payload = parser.parse(JsonTokenUtil.fromBase64ToJsonString(jwtPayloadSegment))
                .getAsJsonObject();
        JsonElement jElm = header.get("alg");
        String algorithm = null;
        if (jElm != null) {
            algorithm = jElm.getAsString();
        }
        //System.out.println("alg is:" + algorithm);

        String iss = getPayloadValue(payload, "iss");
        String sub = getPayloadValue(payload, "sub");
        String aud = getPayloadValue(payload, "aud");
        String exp = getPayloadValue(payload, "exp");
        String iat = getPayloadValue(payload, "iat");
        String auth_time = getPayloadValue(payload, "auth_time");
        String nonce = getPayloadValue(payload, "nonce");
        String at_hash = getPayloadValue(payload, "at_hash");
        String acr = getPayloadValue(payload, "acr");
        String amr = getPayloadValue(payload, "amr");
        String azp = getPayloadValue(payload, "azp");
        String aub_jwk = getPayloadValue(payload, "sub_jwk");

        assertNotNull("no header found", header);
        assertNotNull("no iss found", iss);
        assertNotNull("no sub found", sub);
        assertNotNull("no aud found", aud);
        assertNotNull("no exp found", exp);
        assertNotNull("no iat found", iat);
        // assertNotNull( "no at_hash found", at_hash);

        // assertNotNull( "no nonce found", nonce);
        assertEquals("signature is noy HS256 but " + algorithm, algorithm, "HS256");
        assertEquals("issuer is not http://harmonic:8011 but " + iss, iss, "http://harmonic:8011"); // oidc implicit
        assertEquals("get an Nonce as:" + nonce, nonce, "myNonceMyNonce"); // oidc implicit
    }

    private String getPayloadValue(JsonObject payload, String key) {
        JsonElement jElm = payload.get(key);
        String value = null;
        if (jElm != null) {
            value = jElm.getAsString();
        }
        //System.out.println(key + " is:" + value);
        return value;
    }

    KeyPair generateRSAKeyPair() throws Exception {
        //return generateRSAKeyPair(512);  // net.oauth tolerated, jose4j does not.
        return generateRSAKeyPair(2048);
    }

    KeyPair generateRSAKeyPair(int modulus) throws Exception {
        KeyPairGenerator rsaKeyPairGen = null;
        KeyPair rsaKeyPair = null;
        //PublicKey rsaPub = null;
        //PrivateKey rsaPriv = null;

        if ((modulus <= 0)) {
            modulus = 512;
        }
        try {
            //rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "IBMJCE");
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            //No such provider or No such algorithm
            throw e;
        }

        rsaKeyPairGen.initialize(modulus);
        rsaKeyPair = rsaKeyPairGen.generateKeyPair();

        return rsaKeyPair;
    }

}
