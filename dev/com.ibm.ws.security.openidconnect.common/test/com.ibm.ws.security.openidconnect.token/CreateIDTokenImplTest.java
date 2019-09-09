package com.ibm.wsspi.security.openidconnect.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.junit.Test;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.ibm.ws.security.openidconnect.token.FakeClock;
import com.ibm.ws.security.openidconnect.token.IDToken;
import com.ibm.ws.security.openidconnect.token.JWSHeader;
import com.ibm.ws.security.openidconnect.token.PayloadConstants;
import com.ibm.ws.security.openidconnect.token.mockIDToken;
import com.ibm.ws.security.openidconnect.token.Payload;
import com.ibm.ws.security.openidconnect.token.impl.IdTokenImpl;

public class CreateIDTokenImplTest {

    private final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };
    final Payload myPayload = mock.mock(Payload.class, "payload");

    //private static final byte[] SYMMETRIC_KEY = "thisistestsharedkeyforjasontoken".getBytes();
    Date date = new Date();
    private static final Duration SKEW = Duration.standardMinutes(3);
    public FakeClock clock = new FakeClock(SKEW);
    static boolean bCreateIdTokenImpl = false;
    static IDToken idToken1 = null;
    static IdTokenImpl idTokenImpl = null;
    static String accessToken = "ThisIsSuppoedToBeAnAccessToken";
    static String refreshToken = "ThisIsSuppoedToBeARefreshToken";
    static String idTokenString = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo4MDIwL29pZGMvZW5kcG9pbnQvT1AiLCJub25jZSI6InYxemc1T1o5dlhQNWgwbEVpWXMxIiwiaWF0IjoxNDU1OTAxODU4LCJzdWIiOiJ1c2VyMSIsImV4cCI6MTQ1NTkwOTA1OCwiYXVkIjoicnAiLCJyZWFsbU5hbWUiOiJPcEJhc2ljUmVhbG0iLCJ1bmlxdWVTZWN1cml0eU5hbWUiOiJ1c2VyMSIsImF0X2hhc2giOiIwSGJ6aFc0OWJoRVAyYjNTVkhmZUdnIn0.VJNknPRe0BhzfMA4MpQIEeVczaHYiMzPiBYejp72zIs";
    static String part2 = "{\"iss\":\"https://localhost:8020/oidc/endpoint/OP\",\"nonce\":\"v1zg5OZ9vXP5h0lEiYs1\",\"iat\":1455901858,\"sub\":\"user1\",\"exp\":1455909058,\"aud\":\"rp\",\"realmName\":\"OpBasicRealm\",\"uniqueSecurityName\":\"user1\",\"at_hash\":\"0HbzhW49bhEP2b3SVHfeGg\"}";

    @Test
    // verify signed IDtoken 
    public void testVerifyTokenImpl() {
        verifyIdTokenImpl();
    }

    public void verifyIdTokenImpl() {

        if (bCreateIdTokenImpl)
            return; // already test

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
            idToken1 = new IDToken(jwsHeader, payLoad, keyValue);
            String signedIDToken = idToken1.getSignedJWTString();
            idToken1 = new IDToken(signedIDToken, keyValue, "https://app-one.com", "ibm.com", "HS256");
            isTokenVerified = idToken1.verify();
            // idTokenString contains iss, nonce, sub, iat, exp, (both nonzero) aud, realmName, uniqueSecurityName, at_hash claims
            idTokenImpl = new IdTokenImpl(idToken1, idTokenString, accessToken, refreshToken);
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("IDTokenImpl is not valid", isTokenVerified);

        idTokenImpl.setJwtId("JwtId");
        idTokenImpl.setType("Bearer"); // token type
        idTokenImpl.setSubject("testuser");
        idTokenImpl.setNotBeforeTimeSeconds(123456789L);
        idTokenImpl.setAuthorizationTimeSeconds(223456789L);
        idTokenImpl.setNonce("nonce");
        idTokenImpl.setAccessTokenHash("access_token_hash");
        idTokenImpl.setClassReference("class_reference");
        List<String> listMRs = new ArrayList<String>();
        listMRs.add("method1");
        listMRs.add("method2");
        idTokenImpl.setMethodsReferences(listMRs);
        idTokenImpl.setOtherClaims("key1", "value1");
        idTokenImpl.setOtherClaims("key2", "value2");
        idTokenImpl.setOtherClaims("key4List", listMRs);

        String strIdTokenImpl = idTokenImpl.toString();

        assertTrue("key1=value1 not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("key1=value1") >= 0);
        assertTrue("key2=value2 not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("key2=value2") >= 0);
        assertTrue("method1 not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("method1") >= 0);
        assertTrue("method2 not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("method2") >= 0);
        assertTrue("type=Bearer not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("type=Bearer") >= 0);
        assertTrue("sub=testuser not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("sub=testuser") >= 0);
        assertTrue("nonce=nonce not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("nonce=nonce") >= 0);
        //assertTrue("123456789 not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("123456789") >= 0);
        //assertTrue("223456789 not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("223456789") >= 0);
        assertTrue("at_hash=access_token_hash not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("at_hash=access_token_hash") >= 0);
        assertTrue("acr=class_reference not found in" + strIdTokenImpl, strIdTokenImpl.indexOf("acr=class_reference") >= 0);
        assertEquals("Did not get idToken '" + part2 + "' but '" + idTokenImpl.getAllClaimsAsJson() + "'", part2, idTokenImpl.getAllClaimsAsJson());
        assertEquals("Did not get accessToken '" + accessToken + "'", accessToken, idTokenImpl.getAccessToken());
        assertEquals("Did not get refreshtoken '" + refreshToken + "'", refreshToken, idTokenImpl.getRefreshToken());
    }

    @Test
    public void testIdTokenImplGetMisc() {
        verifyIdTokenImpl(); // create IDTokenImpl first
        assertEquals("JstId not found", "JwtId", idTokenImpl.getJwtId());
        assertEquals("Bearer not found", "Bearer", idTokenImpl.getType());
        assertEquals("Testuser not found", "testuser", idTokenImpl.getSubject());
        assertEquals("123456789L not found", 123456789L, idTokenImpl.getNotBeforeTimeSeconds());
        assertEquals("223456789L not found", 223456789L, idTokenImpl.getAuthorizationTimeSeconds());
        assertEquals("nonce not found", "nonce", idTokenImpl.getNonce());
        assertEquals("access_token_hash", "access_token_hash", idTokenImpl.getAccessTokenHash());
        assertEquals("class_reference not found", "class_reference", idTokenImpl.getClassReference());
        List<String> listMRs = idTokenImpl.getMethodsReferences();
        assertTrue("method1 not found", listMRs.contains("method1"));
        assertTrue("mathod2 not found", listMRs.contains("method2"));
        assertEquals("value1 not found", "value1", idTokenImpl.getClaim("key1"));
        assertEquals("value2 not found", "value2", idTokenImpl.getClaim("key2"));
    }

    @Test
    public void testIdTokenImplGetCustomClaims() {
        //verifyIdTokenImpl(); // create IDTokenImpl first
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
        payLoad.put("role", "write read"); //custom claim
        payLoad.put("customclaim2", "another custom claim");
        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        boolean isTokenVerified = true;
        try {
            // IDToken idToken1 = new IDToken(jwtHeader, jwtClaims, keyValue);
            idToken1 = new IDToken(jwsHeader, payLoad, keyValue);
            String signedIDToken = idToken1.getSignedJWTString();
            idToken1 = new IDToken(signedIDToken, keyValue, "https://app-one.com", "ibm.com", "HS256");
            isTokenVerified = idToken1.verify();
            //System.out.println("AV998 = " + idToken1.getPayload().get("role"));
            idTokenImpl = new IdTokenImpl(idToken1, idTokenString, accessToken, refreshToken);
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }
        assertTrue("IDTokenImpl is not valid", isTokenVerified);
        assertEquals("custom claim role should exist", "write read", idTokenImpl.getClaim("role"));
        assertEquals("customclaim2 should exist", "another custom claim", idTokenImpl.getClaim("customclaim2"));
    }

    @Test
    public void testIdTokenImplGetAllClaims() {
        System.out.println("---------- testIdTokenImplGetAllClaims -----------------");
        verifyIdTokenImpl(); // create IDTokenImpl first
        Map<String, Object> allMap = idTokenImpl.getAllClaims();
        String[] keys = new String[] {
                PayloadConstants.EXPIRATION_TIME_IN_SECS, //= "exp";
                PayloadConstants.NOT_BEFORE_TIME_IN_SECS, //= "nbf";
                PayloadConstants.ISSUED_AT_TIME_IN_SECS, //= "iat";
                PayloadConstants.ISSUER, // = "iss";
                PayloadConstants.AUDIENCE, // = "aud";
                PayloadConstants.JWTID, // = "jti";
                PayloadConstants.TYPE, // = "typ";
                PayloadConstants.SUBJECT, // = "sub";
                PayloadConstants.AUTHZ_TIME_IN_SECS, // = "auth_time";
                PayloadConstants.AUTHORIZED_PARTY,// = "azp";
                PayloadConstants.NONCE, // = "nonce";
                PayloadConstants.AT_HASH, // = "at_hash";
                PayloadConstants.CLASS_REFERENCE, // = "acr";
                PayloadConstants.METHODS_REFERENCE // = "amr";        		
        };
        boolean[] defineds = new boolean[] {
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                true
        };
        int iCnt = 0;
        for (String key : keys) {
            Object obj = allMap.get(key);
            System.out.println("item " + iCnt + " key: " + key + " present: "+ (obj != null));
            iCnt++;
        }
        iCnt = 0;
        for (String key : keys) {
            Object obj = allMap.get(key);
            if (defineds[iCnt++]) {
                assertTrue(key + " does not exist", obj != null);
            } else {
                assertTrue(key + " does not exist", obj == null);
            }

        }

    }

    @Test
    public void testIdTokenImplGet() {
        verifyIdTokenImpl(); // create IDTokenImpl first
        assertEquals("ibm.com not found", "ibm.com", idTokenImpl.getIssuer());

        List<String> listAudience = (List) idTokenImpl.getAudience();
        assertTrue("https://app-one.com not found", listAudience.contains("https://app-one.com"));
        assertTrue("https://app-two.com not found", listAudience.contains("https://app-two.com"));
        assertEquals("ap:https://app-one.com not found", "https://app-one.com", idTokenImpl.getAuthorizedParty());
    }

    private void setUp() throws Exception {
        clock.setNow(new Instant());
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

    @Test
    public void verifyIdTokenImplMisc() {

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
        IdTokenImpl idTokenImpl1 = null;
        try {
            // IDToken idToken1 = new IDToken(jwtHeader, jwtClaims, keyValue);
            IDToken idToken2 = new IDToken(jwsHeader, payLoad, keyValue);
            String signedIDToken = idToken2.getSignedJWTString();
            mockIDToken idToken3 = new mockIDToken(signedIDToken,
                    keyValue,
                    "https://app-one.com",
                    "ibm.com",
                    "HS256");
            isTokenVerified = idToken3.verify();
            idTokenImpl1 = new IdTokenImpl(idToken3, idTokenString, accessToken, refreshToken);
            final List<String> listMRs = new ArrayList<String>();
            listMRs.add("method1");
            listMRs.add("method2");
            mock.checking(new Expectations() {
                {
                    one(myPayload).get(PayloadConstants.NOT_BEFORE_TIME_IN_SECS);
                    will(returnValue(123456789L));
                    one(myPayload).get(PayloadConstants.JWTID);
                    will(returnValue("JwtId"));
                    one(myPayload).get(PayloadConstants.TYPE);
                    will(returnValue("Bearer"));
                    one(myPayload).get(PayloadConstants.SUBJECT);
                    will(returnValue("testuser"));
                    one(myPayload).get(PayloadConstants.AUTHZ_TIME_IN_SECS);
                    will(returnValue(223456789L));
                    one(myPayload).get(PayloadConstants.NONCE);
                    will(returnValue("nonce"));
                    one(myPayload).get(PayloadConstants.AT_HASH);
                    will(returnValue("access_token_hash"));
                    one(myPayload).get(PayloadConstants.CLASS_REFERENCE);
                    will(returnValue("class_reference"));
                    one(myPayload).get(PayloadConstants.METHODS_REFERENCE);
                    will(returnValue(listMRs));
                }
            });
            idToken3.startMock(myPayload);
            idToken3.addToPayloadFields(idTokenImpl1, "NBF");
            idToken3.addToPayloadFields(idTokenImpl1, "JTI");
            idToken3.addToPayloadFields(idTokenImpl1, "TYP");
            idToken3.addToPayloadFields(idTokenImpl1, "SUB");
            idToken3.addToPayloadFields(idTokenImpl1, "AUTH_TIME");
            idToken3.addToPayloadFields(idTokenImpl1, "NONCE");
            idToken3.addToPayloadFields(idTokenImpl1, "AT_HASH");
            idToken3.addToPayloadFields(idTokenImpl1, "ACR");
            idToken3.addToPayloadFields(idTokenImpl1, "AMR");
            idTokenImpl1.setAudience((Object) new String("https://app-one.com"));
            idTokenImpl1.setExpirationTimeSeconds(32456789L);
            idTokenImpl1.setIssuedAtTimeSeconds(42456789L);
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("IDTokenImpl is not valid", isTokenVerified);

        assertEquals("JstId not found", "JwtId", idTokenImpl1.getJwtId());
        assertEquals("Bearer not found", "Bearer", idTokenImpl1.getType());
        assertEquals("Testuser not found", "testuser", idTokenImpl1.getSubject());
        assertEquals("123456789L not found", 123456789L, idTokenImpl1.getNotBeforeTimeSeconds());
        assertEquals("223456789L not found", 223456789L, idTokenImpl1.getAuthorizationTimeSeconds());
        assertEquals("nonce not found", "nonce", idTokenImpl1.getNonce());
        assertEquals("access_token_hash", "access_token_hash", idTokenImpl1.getAccessTokenHash());
        assertEquals("class_reference not found", "class_reference", idTokenImpl1.getClassReference());
        assertEquals("Experiation time is not 32456789L", 32456789L, idTokenImpl1.getExpirationTimeSeconds());
        assertEquals("Issued at time is not 42456789L", 42456789L, idTokenImpl1.getIssuedAtTimeSeconds());
        List<String> listMRs = idTokenImpl1.getMethodsReferences();
        assertNotNull("listMRs is null", listMRs);
        assertTrue("method1 not found", listMRs.contains("method1"));
        assertTrue("mathod2 not found", listMRs.contains("method2"));
        List<String> listAudience = (List<String>) idTokenImpl1.getAudience();
        assertTrue("https://app-one.com not found", listAudience.contains("https://app-one.com"));
        assertFalse("https://app-one.com not found", listAudience.contains("https://app-two.com"));
        //assertEquals("value1 not found", "value1", idTokenImpl1.getOtherClaims("key1"));
        //assertEquals("value2 not found", "value2", idTokenImpl1.getOtherClaims("key2"));

    }

    @Test
    public void verifyIdTokenMisc() {

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
        mockIDToken idToken3 = null;
        IdTokenImpl idTokenImpl1 = null;
        try {
            // IDToken idToken1 = new IDToken(jwtHeader, jwtClaims, keyValue);
            IDToken idToken2 = new IDToken(jwsHeader, payLoad, keyValue);
            String signedIDToken = idToken2.getSignedJWTString();
            idToken3 = new mockIDToken(signedIDToken,
                    keyValue,
                    "https://app-one.com",
                    "ibm.com",
                    "HS256");
            isTokenVerified = idToken3.verify();
            idTokenImpl1 = new IdTokenImpl(idToken3, idTokenString, accessToken, refreshToken);
            final List<String> listMRs = new ArrayList<String>();
            listMRs.add("method1");
            listMRs.add("method2");
            mock.checking(new Expectations() {
                {
                    one(myPayload).get(PayloadConstants.NOT_BEFORE_TIME_IN_SECS);
                    will(returnValue(123456789L));
                    one(myPayload).setNotBeforeTimeSeconds(with(any(Long.class)));
                    one(myPayload).get(PayloadConstants.JWTID);
                    will(returnValue("JwtId"));
                    one(myPayload).setJwtId(with(any(String.class)));
                    one(myPayload).get(PayloadConstants.TYPE);
                    will(returnValue("Bearer"));
                    one(myPayload).setType(with(any(String.class)));
                    one(myPayload).get(PayloadConstants.SUBJECT);
                    will(returnValue("testuser"));
                    one(myPayload).setSubject(with(any(String.class)));
                    one(myPayload).get(PayloadConstants.AUTHZ_TIME_IN_SECS);
                    will(returnValue(223456789L));
                    one(myPayload).setAuthorizationTimeSeconds(with(any(Long.class)));
                    one(myPayload).get(PayloadConstants.NONCE);
                    will(returnValue("nonce"));
                    one(myPayload).setNonce(with(any(String.class)));
                    one(myPayload).get(PayloadConstants.AT_HASH);
                    will(returnValue("access_token_hash"));
                    one(myPayload).setAccessTokenHash(with(any(String.class)));
                    one(myPayload).get(PayloadConstants.CLASS_REFERENCE);
                    will(returnValue("class_reference"));
                    one(myPayload).setClassReference(with(any(String.class)));
                    one(myPayload).get(PayloadConstants.METHODS_REFERENCE);
                    will(returnValue(listMRs));
                    one(myPayload).setMethodsReferences(with(any(List.class)));
                }
            });
            idToken3.startMock(myPayload);
            idToken3.addToPayloadFields(idTokenImpl1, "NBF");
            idToken3.addToPayloadFields(idTokenImpl1, "JTI");
            idToken3.addToPayloadFields(idTokenImpl1, "TYP");
            idToken3.addToPayloadFields(idTokenImpl1, "SUB");
            idToken3.addToPayloadFields(idTokenImpl1, "AUTH_TIME");
            idToken3.addToPayloadFields(idTokenImpl1, "NONCE");
            idToken3.addToPayloadFields(idTokenImpl1, "AT_HASH");
            idToken3.addToPayloadFields(idTokenImpl1, "ACR");
            idToken3.addToPayloadFields(idTokenImpl1, "AMR");
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("IDTokenImpl is not valid", isTokenVerified);
        Payload payload = idToken3.getPayload();
        assertEquals("It's not myPayload", payload, myPayload);
        //assertEquals("JstId not found", "JwtId", payload.getJwtId());
        //assertEquals("Bearer not found", "Bearer", payload.getType());
        //assertEquals("Testuser not found", "testuser", payload.getSubject());
        //assertEquals("123456789L not found", 123456789L, payload.getNotBeforeTimeSeconds());
        //assertEquals("223456789L not found", 223456789L, payload.getAuthorizationTimeSeconds());
        //assertEquals("nonce not found", "nonce", payload.getNonce());
        //assertEquals("access_token_hash", "access_token_hash", payload.getAccessTokenHash());
        //assertEquals("class_reference not found", "class_reference", payload.getClassReference());
        List<String> listMRs = idTokenImpl1.getMethodsReferences();
        assertNotNull("listMRs is null", listMRs);
        assertTrue("method1 not found", listMRs.contains("method1"));
        assertTrue("mathod2 not found", listMRs.contains("method2"));
        //assertEquals("value1 not found", "value1", idTokenImpl1.getOtherClaims("key1"));
        //assertEquals("value2 not found", "value2", idTokenImpl1.getOtherClaims("key2"));
    }
}
