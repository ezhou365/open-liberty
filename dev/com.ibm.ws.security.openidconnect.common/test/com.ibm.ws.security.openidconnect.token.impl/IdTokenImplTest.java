/*
 * IBM Confidential
 *
 * OCO Source Materials
 *
 * Copyright IBM Corp. 2017
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */

package com.ibm.ws.security.openidconnect.token.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.ibm.ws.security.openidconnect.common.Constants;
import com.ibm.ws.security.openidconnect.token.IDToken;

import test.common.SharedOutputManager;
import test.common.junit.matchers.RegexMatcher;

@SuppressWarnings("unchecked")
public class IdTokenImplTest {

    static SharedOutputManager outputMgr = SharedOutputManager.getInstance().trace("com.ibm.ws.security.openidconnect.common.*=all");

    private final Mockery mockery = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };

    final static String TO_STRING_ISS = "iss";
    final static String TO_STRING_TYPE = "type";
    final static String TO_STRING_CLIENT_ID = "client_id";
    final static String TO_STRING_SUB = "sub";
    final static String TO_STRING_AUD = "aud";
    final static String TO_STRING_EXP = "exp";
    final static String TO_STRING_IAT = "iat";
    final static String TO_STRING_NONCE = "nonce";
    final static String TO_STRING_AT_HASH = "at_hash";
    final static String TO_STRING_ACR = "acr";
    final static String TO_STRING_AMR = "amr";
    final static String TO_STRING_AZP = "azp";

    final static String CLAIM_CLIENT_ID = "azp2";
    final static String CLAIM_EXTRA_STRING = "xString";
    final static String CLAIM_EXTRA_STRING_LIST = "xSList";
    final static String CLAIM_EXTRA_ARRAY_LIST_EMPTY = "xArrayListEmpty";
    final static String CLAIM_EXTRA_ARRAY_LIST = "xAList";
    final static String CLAIM_EXTRA_JSON_OBJECT = "xJsonObj";

    final static String ID_TOKEN = "xxx.yyy.idtoken";
    final static String ACCESS_TOKEN = "SomeAccessTokenValue";
    final static String REFRESH_TOKEN = "SomeRefreshTokenValue";
    final static String CLIENT_ID = "myClientId";
    final static String ISSUER = "myIssuer";
    final static String TYPE = "Some Type";
    final static String SUBJECT = "mySubject";
    final static Object AUDIENCE = "myAudience";
    final static String NONCE = "someNonce";
    final static String AT_HASH = "myAtHash";
    final static String CLASS_REFERENCE = "some class reference";
    final static String METHODS_REFERENCE = "some methods reference";
    final static String AUTHORIZED_PARTY = "myAuthorizedParty";

    final static String EXTRA_KEY_1 = "xKey1";
    final static String EXTRA_VAL_1 = "extra value 1";
    final static String EXTRA_VAL_2 = "extra_val2";
    final static String EXTRA_STRING = "Some extra string claim value";
    final static List<String> EXTRA_STRING_LIST = Arrays.asList(EXTRA_VAL_1, EXTRA_VAL_2);
    final static JSONArray EXTRA_ARRAY_LIST_EMPTY = new JSONArray();
    final static JSONArray EXTRA_ARRAY_LIST = new JSONArray();
    final static JSONObject EXTRA_JSON_OBJECT = new JSONObject();
    final static long EXPIRATION_TIME_IN_SECS = 100;
    final static long ISSUED_AT_TIME_IN_SECS = 50;

    static {
        EXTRA_ARRAY_LIST.add(EXTRA_VAL_1);
        EXTRA_ARRAY_LIST.add(EXTRA_VAL_2);
        EXTRA_JSON_OBJECT.put(EXTRA_KEY_1, EXTRA_VAL_1);
    }

    final IDToken idToken = mockery.mock(IDToken.class);

    @Rule
    public TestName testName = new TestName();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr.captureStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.dumpStreams();
        outputMgr.resetStreams();
        outputMgr.restoreStreams();
    }

    @Before
    public void beforeTest() {
        System.out.println("Entering test: " + testName.getMethodName());
    }

    @After
    public void tearDown() throws Exception {
        mockery.assertIsSatisfied();
        System.out.println("Exiting test: " + testName.getMethodName());
    }

    /********************************************* constructor *********************************************/

    @Test
    public void constructor_nullAccessAndRefreshTokens() {
        mockery.checking(new Expectations() {
            {
                allowing(idToken).addToIdTokenImpl(with(any(IdTokenImpl.class)));
            }
        });
        IdTokenImpl token = new IdTokenImpl(idToken, "", null, null);

        assertNull("Access token should have been null but wasn't. Result: " + token.getAccessToken(), token.getAccessToken());
        assertNull("Refresh token should have been null but wasn't. Result: " + token.getRefreshToken(), token.getRefreshToken());
    }

    @Test
    public void constructor_validArgs() {
        mockery.checking(new Expectations() {
            {
                allowing(idToken).addToIdTokenImpl(with(any(IdTokenImpl.class)));
            }
        });
        IdTokenImpl token = new IdTokenImpl(idToken, ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN);

        assertEquals("Access token did not match expected value.", ACCESS_TOKEN, token.getAccessToken());
        assertEquals("Refresh token did not match expected value.", REFRESH_TOKEN, token.getRefreshToken());
    }

    /********************************************* toString *********************************************/

    @Test
    public void toString_noClaims() {
        mockery.checking(new Expectations() {
            {
                allowing(idToken).addToIdTokenImpl(with(any(IdTokenImpl.class)));
            }
        });
        IdTokenImpl token = new IdTokenImpl(idToken, "", null, null);

        assertEquals("Constructor with null args should result in token string that just has token type.", Constants.TOKEN_TYPE_ID_TOKEN, token.toString());
    }

    @Test
    public void toString_missingIssuer() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, null, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, null, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingType() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, null, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, null, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingSubject() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, null, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, null, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingAudience() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, null, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, null, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_multipleAudiences() {
        IdTokenImpl token = createStandardToken();

        List<?> audiences = Arrays.asList("aud1", 2, EXTRA_JSON_OBJECT);
        setClaimsMap(token, ISSUER, TYPE, SUBJECT, audiences, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, audiences, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_negativeExp() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, -10, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, -10, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_negativeIat() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, -10, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, -10, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingNonce() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, null, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, null, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingAtHash() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, null, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, null, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingClassRef() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, null, AUTHORIZED_PARTY, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, null, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_missingAzp() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, null, getExtraClaims());

        String tokenString = token.toString();

        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, null);
        assertStandardExtraClaims(tokenString);
    }

    @Test
    public void toString_fullClaimsMap() {
        IdTokenImpl token = createStandardToken();

        setClaimsMap(token, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY, getExtraClaims());

        Map<String, Object> originalMap = new HashMap<String, Object>(token.getAllClaims());
        String tokenString = token.toString();

        assertEquals("The claim map after calling toString() does not match the original claim map.", originalMap, token.getAllClaims());
        assertTokenStringStart(tokenString);
        assertClaimsStrings(tokenString, ISSUER, TYPE, SUBJECT, AUDIENCE, EXPIRATION_TIME_IN_SECS, ISSUED_AT_TIME_IN_SECS, NONCE, AT_HASH, CLASS_REFERENCE, AUTHORIZED_PARTY);
        assertStandardExtraClaims(tokenString);
    }

    /********************************************* appendClaimKey *********************************************/

    @Test
    public void appendClaimKey_emptyBufferNullKey() {
        IdTokenImpl token = createStandardToken();

        StringBuffer sb = new StringBuffer();
        StringBuffer result = token.appendClaimKey(sb, null);

        assertEquals("Result did not match expected value.", "null=", result.toString());
    }

    @Test
    public void appendClaimKey_emptyBufferEmptyKey() {
        IdTokenImpl token = createStandardToken();

        StringBuffer sb = new StringBuffer();
        StringBuffer result = token.appendClaimKey(sb, "");

        assertEquals("Result did not match expected value.", "=", result.toString());
    }

    @Test
    public void appendClaimKey_emptyBuffer() {
        IdTokenImpl token = createStandardToken();

        String key = "Some kind=of, claim key";
        StringBuffer sb = new StringBuffer();
        StringBuffer result = token.appendClaimKey(sb, key);

        assertEquals("Result did not match expected value.", key + "=", result.toString());
    }

    @Test
    public void appendClaimKey_nonEmptyBuffer() {
        IdTokenImpl token = createStandardToken();

        String startValue = "some start value";
        String key = "key";
        StringBuffer sb = new StringBuffer(startValue);
        StringBuffer result = token.appendClaimKey(sb, key);

        // Start value doesn't contain '=' so no comma should be added
        assertEquals("Result did not match expected value.", startValue + key + "=", result.toString());
    }

    @Test
    public void appendClaimKey_nonEmptyBufferMultipleEntries() {
        IdTokenImpl token = createStandardToken();

        String startValue = "some=start,value =is\" already=, present ";
        String key = "new,key=\"to add, to the, mix=";
        StringBuffer sb = new StringBuffer(startValue);
        StringBuffer result = token.appendClaimKey(sb, key);

        assertEquals("Result did not match expected value.", startValue + ", " + key + "=", result.toString());
    }

    /********************************************* getListString *********************************************/

    @Test
    public void getListString_nullList() {
        IdTokenImpl token = createStandardToken();

        String result = token.getListString(null);

        assertNull("Result for null list should have been a null string, but was not. Result: [" + result + "].", result);
    }

    @Test
    public void getListString_emptyList() {
        IdTokenImpl token = createStandardToken();

        String result = token.getListString(Arrays.asList());

        assertEquals("Result did not match expected value.", "[]", result);
    }

    @Test
    public void getListString_intList() {
        IdTokenImpl token = createStandardToken();

        String result = token.getListString(Arrays.asList(1, 2, 3));

        assertEquals("Result did not match expected value.", "[1, 2, 3]", result);
    }

    @Test
    public void getListString_stringList() {
        IdTokenImpl token = createStandardToken();

        String result = token.getListString(Arrays.asList("one", "two", "three"));

        assertEquals("Result did not match expected value.", "[one, two, three]", result);
    }

    @Test
    public void getListString_mixedList() {
        IdTokenImpl token = createStandardToken();

        String result = token.getListString(Arrays.asList("one", 1, 3.14, Arrays.asList("subList"), EXTRA_ARRAY_LIST_EMPTY, EXTRA_ARRAY_LIST, EXTRA_JSON_OBJECT));

        assertEquals("Result did not match expected value.", "[one, 1, 3.14, [subList], [], [\"" + EXTRA_VAL_1 + "\",\"" + EXTRA_VAL_2 + "\"], {\"" + EXTRA_KEY_1 + "\":\"" + EXTRA_VAL_1 + "\"}]", result);
    }

    /********************************************* Helper methods *********************************************/

    IdTokenImpl createStandardToken() {
        mockery.checking(new Expectations() {
            {
                allowing(idToken).addToIdTokenImpl(with(any(IdTokenImpl.class)));
            }
        });
        return new IdTokenImpl(idToken, ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN);
    }

    void setClaimsMap(IdTokenImpl token, String issuer, String type, String subject, Object audience, long exp, long iat, String nonce, String atHash, String classRef, String azp, Map<String, Object> extraClaims) {
        if (issuer != null) {
            token.setIssuer(issuer);
        }
        if (type != null) {
            token.setType(type);
        }
        if (subject != null) {
            token.setSubject(subject);
        }
        if (audience != null) {
            token.setAudience(audience);
        }
        token.setExpirationTimeSeconds(exp);
        token.setIssuedAtTimeSeconds(iat);
        if (nonce != null) {
            token.setNonce(nonce);
        }
        if (atHash != null) {
            token.setAccessTokenHash(atHash);
        }
        if (classRef != null) {
            token.setClassReference(classRef);
        }
        if (azp != null) {
            token.setAuthorizedParty(azp);
        }

        if (extraClaims != null) {
            for (Entry<String, Object> entry : extraClaims.entrySet()) {
                token.setOtherClaims(entry.getKey(), entry.getValue());
            }
        }
    }

    Map<String, Object> getExtraClaims() {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put(CLAIM_CLIENT_ID, CLIENT_ID);
        map.put(CLAIM_EXTRA_STRING, EXTRA_STRING);
        map.put(CLAIM_EXTRA_STRING_LIST, EXTRA_STRING_LIST);
        map.put(CLAIM_EXTRA_ARRAY_LIST_EMPTY, EXTRA_ARRAY_LIST_EMPTY);
        map.put(CLAIM_EXTRA_ARRAY_LIST, EXTRA_ARRAY_LIST);
        map.put(CLAIM_EXTRA_JSON_OBJECT, EXTRA_JSON_OBJECT);
        return map;
    }

    void assertTokenStringStart(String tokenString) {
        assertStringContainsRegex("^" + Constants.TOKEN_TYPE_ID_TOKEN + ":", tokenString);
    }

    void assertClaimsStrings(String tokenString, String issuer, String type, String subject, Object audience, long exp, long iat, String nonce, String atHash, String classRef, String azp) {
        checkClaimString(tokenString, TO_STRING_ISS, issuer);
        checkClaimString(tokenString, TO_STRING_TYPE, type);
        checkClaimString(tokenString, TO_STRING_SUB, subject);
        if (audience instanceof String) {
            // Bare String object will be cast to a List whose toString method automatically adds the square brackets, so must manually add the brackets here
            checkClaimString(tokenString, TO_STRING_AUD, "[" + audience + "]");
        } else {
            // toString method of the audience object is expected to automatically include enclosing square brackets
            checkClaimString(tokenString, TO_STRING_AUD, audience);
        }
        checkClaimString(tokenString, TO_STRING_EXP, exp);
        checkClaimString(tokenString, TO_STRING_IAT, iat);
        checkClaimString(tokenString, TO_STRING_NONCE, nonce);
        checkClaimString(tokenString, TO_STRING_AT_HASH, atHash);
        checkClaimString(tokenString, TO_STRING_ACR, classRef);
        checkClaimString(tokenString, TO_STRING_AZP, azp);
    }

    void assertStandardExtraClaims(String tokenString) {
        assertStringContains(TO_STRING_CLIENT_ID + "=" + CLIENT_ID, tokenString);
        assertStringContains(CLAIM_EXTRA_STRING + "=" + EXTRA_STRING, tokenString);
        assertStringContains(CLAIM_EXTRA_STRING_LIST + "=[" + EXTRA_VAL_1 + ", " + EXTRA_VAL_2 + "]", tokenString);
        assertStringContains(CLAIM_EXTRA_ARRAY_LIST_EMPTY + "=[]", tokenString);
        assertStringContains(CLAIM_EXTRA_ARRAY_LIST + "=[\"" + EXTRA_VAL_1 + "\",\"" + EXTRA_VAL_2 + "\"]", tokenString);
        assertStringContains(CLAIM_EXTRA_JSON_OBJECT + "={\"" + EXTRA_KEY_1 + "\":\"" + EXTRA_VAL_1 + "\"}", tokenString);
    }

    void checkClaimString(String tokenString, String key, Object value) {
        if (value == null) {
            assertStringDoesNotContain(key + "=", tokenString);
        } else {
            assertStringContains(key + "=" + value, tokenString);
        }
    }

    void assertStringContains(String stringToFind, String searchString) {
        assertTrue("Expected to find [" + stringToFind + "] but did not. Searched in: [" + searchString + "].", searchString.contains(stringToFind));
    }

    void assertStringDoesNotContain(String stringToFind, String searchString) {
        assertFalse("Should not have found [" + stringToFind + "] but did. Searched in: [" + searchString + "].", searchString.contains(stringToFind));
    }

    void assertStringContainsRegex(String regex, String searchString) {
        assertTrue("Expected to find pattern [" + regex + "] but did not. Searched in: [" + searchString + "].", RegexMatcher.match(searchString, regex));
    }
}
