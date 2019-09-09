/*
 * IBM Confidential
 * 
 * OCO Source Materials
 * 
 * Copyright IBM Corp. 2014
 * 
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */

package com.ibm.ws.security.openidconnect.token;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;


import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import test.common.SharedOutputManager;

import com.google.gson.JsonObject;
import com.ibm.ws.security.openidconnect.token.Payload;

public class JWTTest {
    Date date = new Date();
    private static SharedOutputManager outputMgr;

    private final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr = SharedOutputManager.getInstance();
        //outputMgr.captureStreams();
    }

    @Before
    public void setUp() throws Exception {
        mock.checking(new Expectations() {
            {
                //allowing(cc).locateService("configurationAdmin", configAdminRef);
                //will(returnValue(configAdmin));
            }
        });
    }

    @After
    public void tearDown() {
        mock.assertIsSatisfied();
        //outputMgr.resetStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        //outputMgr.restoreStreams();
    }

    @Test
    public void testCreatePayloadFromString() {

        String tokenString = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg5OTgiLCJpYXQiOjEzODkyODI2OTEsInN1YiI6InRlc3R1c2VyIiwiZXhwIjoxMzg5Mjg2MjkxLCJhdWQiOiJjbGllbnQwMSJ9.OHBR8jnAK6ZP4ca0Uy3lBgfCVkwF1char9b7TR6XrOk";
        JWT jwt = new JWT(tokenString, "clientId", "Issuer", "RSA256");
        Payload payload = jwt.createPayloadFromString(tokenString);
        //TODO, need to add some validation here once we implemented the method
    }

    @Test
    public void testCreateHeader() {
        JWSHeader jwsHeader = new JWSHeader();

        long testNum = 12345L;
        jwsHeader.put("numKey", testNum);
        List<String> testList = new ArrayList<String>(2);
        testList.add("listElem1");
        testList.add("listElem2");
        jwsHeader.put("listKey", testList);
        jwsHeader.setType("JWT");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com");
        payLoad.setIssuer("ibm.com");
        JWT jwt = new JWT(jwsHeader, payLoad);
        JsonObject jsonObj = jwt.createHeader();
        assertNotNull("Json object is not valid", jsonObj);
        String alg = jsonObj.get("alg").getAsString();
        assertEquals("none", alg);
    }

    @Test
    public void testGetHeader() {
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("RS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        JWT jwt = new JWT(jwsHeader, payLoad);
        JWSHeader header = jwt.getHeader();
        assertNotNull("no header found", header);
        assertEquals("Algorithm should be RS256, but it is" +
                header.getAlgorithm(), header.getAlgorithm(), "RS256");
    }

    @Test
    public void testParseAndVerify() {
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        JWT jwt = new JWT(jwsHeader, payLoad, keyValue);
        //jwt.parseAndVerify(jwt);
        //TODO, need to add some validation once we complete the implementation of the method
    }



   

    //@Test
    /*
    public void testCreateSigner() {
        String methodName = "createSignerTest";
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();
        JWT jwt = new JWT(jwsHeader, payLoad, keyValue);

            jwt.createSigner();
        } catch (InvalidKeyException e) {

            // e.printStackTrace();
            outputMgr.failWithThrowable(methodName, e);
        }

        jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("RS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        payLoad = new Payload();
        payLoad.setAudience("https://app-one.com");
        payLoad.setIssuer("ibm.com");

        KeyPairGenerator rsaKeyPairGen = null;
        KeyPair rsaKeyPair = null;
        RSAPrivateKey privateKey = null;
        RSAPublicKey publicKey = null;

        try {
            //rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", "IBMJCE");
            rsaKeyPairGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyPairGen.initialize(512);
            rsaKeyPair = rsaKeyPairGen.generateKeyPair();

            privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
            publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        } catch (Exception e) {
            //No such provider or No such algorithm
            outputMgr.failWithThrowable(methodName, e);
        }
        jwt = new JWT(jwsHeader, payLoad, privateKey);
        try {
            jwt.createSigner();
        } catch (InvalidKeyException e) {

            // e.printStackTrace();
            outputMgr.failWithThrowable(methodName, e);
        }

    }
*/    

    @Test
    public void testGetJWTString() {
        String methodName = "getJWTStringTest";
        String expectedJWTHeader =
                "eyJhbGciOiJub25lIn0";
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("none");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        JWT jwt = new JWT(jwsHeader, payLoad);
        String plainJWTStr = jwt.getJWTString();
        String[] pieces = plainJWTStr.split(Pattern.quote(JsonTokenUtil.DELIMITER));
        assertNotNull("plain text JWT is not valid", plainJWTStr);
        /*
         * assertEquals("Plain JWT should be " + pieces[0], expectedJWTHeader,
         * pieces[0]);
         */

    }

    @Test
    public void testGetSignedJWTString() {
        String methodName = "getSignedJWTStringTest";
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT
        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();

        JWT jwt = new JWT(jwsHeader, payLoad, keyValue);
        String signedJWTStr = null;
        try {
            signedJWTStr = jwt.getSignedJWTString();
        } catch (InvalidKeyException e) {
            //e.printStackTrace();
            outputMgr.failWithThrowable(methodName, e);
        } catch (SignatureException e) {
            outputMgr.failWithThrowable(methodName, e);
        }
        assertNotNull("Signed JWT is not valid", signedJWTStr);
    }

    @Test
    public void testAddToHeaderFields() {
        String methodName = "addToHeaderFieldsTest";
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();
        JWT jwt = new JWT(jwsHeader, payLoad, keyValue);

        List<String> critical = new ArrayList<String>();
        critical.add("https://app-one.com");
        critical.add("https://app-two.com");
        JWSHeader header = jwt.getHeader();
        JsonTokenUtil.addToHeaderFields(header, "crit", critical);
        String[] expectedArray = { "https://app-one.com", "https://app-two.com" };

        List<String> critList = jwt.getHeader().getCritical();
        String[] receivedArray = new String[critList.size()];
        for (int i = 0; i < critList.size(); i++) {
            receivedArray[i] = critList.get(i);
        }
        assertArrayEquals("Header critical list is not same as the one that we passed",
                expectedArray, receivedArray);

    }

    @Test
    public void testAddToHeaderFields2() {
        String methodName = "addToHeaderFieldsTest";
        // Create jws header
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload
        Payload payLoad = new Payload();
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process
        payLoad.setIssuer("ibm.com");

        byte[] keyValue = "thisistestsharedkeyforjasontoken".getBytes();
        JWT jwt = new JWT(jwsHeader, payLoad, keyValue);
        JWSHeader header = jwt.getHeader();
        JsonTokenUtil.addToHeaderFields(header, "typ", "JWT");
        JsonTokenUtil.addToHeaderFields(header, "cty", "JWT");
        JsonTokenUtil.addToHeaderFields(header, "jku", "https://example.ibm.com");
        JsonTokenUtil.addToHeaderFields(header, "jwk", "jsonwebkey");
        JsonTokenUtil.addToHeaderFields(header, "x5u", "https://example.ibm.com");
        JsonTokenUtil.addToHeaderFields(header, "x5t", "encodedX509Certificate");
        JsonTokenUtil.addToHeaderFields(header, "x5c", "X509Cert");

        String receivedType = jwt.getHeader().getType();
        String expectedType = "JWT";
        String receivedJku = jwt.getHeader().getJwkUrl();
        String receivedJwk = jwt.getHeader().getJwk();
        String receivedContentType = jwt.getHeader().getContentType();
        String receivedX5u = jwt.getHeader().getX509Url();
        String receivedX509Thumbprint = jwt.getHeader().getX509Thumbprint();
        String receivedX509Cert = jwt.getHeader().getX509Certificate();

        assertEquals(expectedType, receivedType);
        assertEquals(expectedType, receivedContentType);
        assertEquals("https://example.ibm.com", receivedJku);
        assertEquals("jsonwebkey", receivedJwk);
        assertEquals("https://example.ibm.com", receivedX5u);
        assertEquals("encodedX509Certificate", receivedX509Thumbprint);
        assertEquals("X509Cert", receivedX509Cert);
    }

    @Test
    public void testVerifySignatureOnlyWithSharedKey() {
        boolean isTokenVerified = false;

        // Create jwt header for the JWT token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("HS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the JWT token
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

            JWT token = new JWT(jwsHeader, payLoad, keyValue);
            String signedToken = token.getSignedJWTString();
            token = new JWT(signedToken, keyValue, "https://app-one.com", "ibm.com", "HS256");
            isTokenVerified = token.verifySignatureOnly();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isTokenVerified = false;
        }

        assertTrue("Token is not valid", isTokenVerified);

    }

    @Test
    public void testVerifySignatureOnlyWithPublicKey() {
        boolean isTokenVerified = false;
        boolean isKeyCreated = true;

        // Create jwt header for the ID token
        JWSHeader jwsHeader = new JWSHeader();
        jwsHeader.setAlgorithm("RS256");
        jwsHeader.setKeyId("testkey1");

        // Create payload for the ID token
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        payLoad.setAudience("https://app-one.com"); //Audience has to match client_id in verify process

        payLoad.setExpirationTimeSeconds((date.getTime() - (6000)) / 1000); //already expired
        payLoad.setIssuer("ibm.com");

        // Key value used for signing JWT

        RSAPrivateKey privateKey = null;
        RSAPublicKey publicKey = null;

        try {
            //KeyPair keyPair = generateRSAKeyPair(512);  // jose4j requires >=2048
            KeyPair keyPair = generateRSAKeyPair(2048);
            privateKey = (RSAPrivateKey) keyPair.getPrivate();
            publicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception e1) {
            e1.printStackTrace();
            System.out.println("Exception:  " + e1.getMessage());
            isKeyCreated = false;
        }

        if (isKeyCreated) {
            try {
                JWT token1 = new JWT(jwsHeader, payLoad, privateKey);
                String signedToken = token1.getSignedJWTString();
                token1 = new JWT(signedToken, publicKey, "https://app-one.com", "ibm.com", "RS256");
                isTokenVerified = token1.verifySignatureOnly(); //token is expired but signature should be verified successfully
                System.out.println("verifySignatureOnly returns: "+ isTokenVerified);
            } catch (Exception e1) {
                e1.printStackTrace(System.out);
                System.out.println("Exception:  " + e1.getMessage());
                isTokenVerified = false;
            }
        }

        assertTrue("Token is not verified", isTokenVerified);

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
