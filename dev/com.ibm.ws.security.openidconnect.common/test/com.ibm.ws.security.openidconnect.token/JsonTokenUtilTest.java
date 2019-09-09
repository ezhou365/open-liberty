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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.junit.After;
import org.junit.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

public class JsonTokenUtilTest {

    private final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };

    final WSJsonToken jsonToken = mock.mock(WSJsonToken.class);

    @After
    public void tearDown() throws Exception {
        mock.assertIsSatisfied();
    }

    @Test
    public void testGetElementNullPayload() {
        assertNull(JsonTokenUtil.getElement((JWTPayload) null, null));
    }

    @Test
    public void testGetAudString() {
        JWTPayload jpl = new JWTPayload();
        String result = "client01";
        jpl.setAudience(result);
        assertEquals(result, JsonTokenUtil.getAud(jpl));
    }

    @Test
    public void testGetAudNotFound() {
        JWTPayload jpl = new JWTPayload();
        assertNull(JsonTokenUtil.getAud(jpl));
    }

    @Test
    public void testGetAudListOneElement() {
        JWTPayload jpl = new JWTPayload();
        List<String> list = new ArrayList<String>();
        String result = "client01";
        list.add(result);
        jpl.setAudience(list);
        assertEquals(result, JsonTokenUtil.getAud(jpl));
    }

    @Test
    public void testGetAudListMultipleElements() {
        JWTPayload jpl = new JWTPayload();
        List<String> list = new ArrayList<String>();
        String result = "client01";
        list.add(result);
        list.add("client02");
        jpl.setAudience(list);
        assertNull(JsonTokenUtil.getAud(jpl));
    }

    @Test
    public void testGetIssString() {
        JWTPayload jpl = new JWTPayload();
        String result = "http://test:8080/oidc";
        jpl.setIssuer(result);
        assertEquals(result, JsonTokenUtil.getIss(jpl));
    }

    @Test
    public void testGetSubString() {
        JWTPayload jpl = new JWTPayload();
        String result = "user01";
        jpl.setSubject(result);
        assertEquals(result, JsonTokenUtil.getSub(jpl));
    }

    /********************************************* fromJsonToken (JWTPayload) *********************************************/

    @Test
    public void testFomJsonToken_jwtPayload_nullToken_nullPayload() {
        WSJsonToken token = null;
        JWTPayload resultPayload = null;
        JsonTokenUtil.fromJsonToken(token, resultPayload);
        assertNull("Result payload should have been null but was not.", resultPayload);
    }

    @Test
    public void testFomJsonToken_jwtPayload_nullToken() {
        WSJsonToken token = null;
        JWTPayload resultPayload = new JWTPayload();
        JsonTokenUtil.fromJsonToken(token, resultPayload);
        assertTrue("Result payload should have been empty but wasn't. Result had keys: " + resultPayload.keySet(), resultPayload.isEmpty());
    }

    @Test
    public void testFomJsonToken_jwtPayload_nullPayload() {
        JWTPayload resultPayload = null;
        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertNull("Result payload should have been null but was not.", resultPayload);
    }

    /**
     * Tests:
     * - Token payload: null
     */
    @Test
    public void testFomJsonToken_jwtPayload_nullTokenPayload() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = null;
        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertTrue("Result payload should have been empty but wasn't. Result had keys: " + resultPayload.keySet(), resultPayload.isEmpty());
    }

    /**
     * Tests:
     * - Token payload: {}
     */
    @Test
    public void testFomJsonToken_jwtPayload_emptyTokenPayload() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertTrue("Result payload should have been empty but wasn't. Result had keys: " + resultPayload.keySet(), resultPayload.isEmpty());
    }

    /**
     * Tests:
     * - Token payload: { "key" : null }
     */
    @Test
    public void testFomJsonToken_jwtPayload_singleEntryTokenPayload_nullValue() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String key = "nullValue";
        tokenPayload.add("nullValue", null);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());
        assertEquals("Entry for \"" + key + "\" did not match expected value.", JsonNull.INSTANCE, resultPayload.get(key));
    }

    /**
     * Tests:
     * - Token payload: Multiple entries, each value is a JSON primitive
     */
    @Test
    public void testFomJsonToken_jwtPayload_multiEntryTokenPayload_primitiveValues() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String stringValue = "stringValue";
        boolean booleanValue = false;
        long longValue = 12345L;
        double doubleValue = 1.234;
        char charValue = 'm';
        tokenPayload.add("null", null);
        tokenPayload.addProperty("string", stringValue);
        tokenPayload.addProperty("boolean", booleanValue);
        tokenPayload.addProperty("long", longValue);
        tokenPayload.addProperty("double", doubleValue);
        tokenPayload.addProperty("char", charValue);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());
        assertEquals("Entry for \"null\" did not match expected value.", JsonNull.INSTANCE, resultPayload.get("null"));
        assertEquals("Entry for \"string\" did not match expected value.", stringValue, resultPayload.get("string"));
        assertEquals("Entry for \"boolean\" did not match expected value.", booleanValue, resultPayload.get("boolean"));
        assertEquals("Entry for \"long\" did not match expected value.", longValue, resultPayload.get("long"));
        assertEquals("Entry for \"double\" did not match expected value.", doubleValue, resultPayload.get("double"));
        assertEquals("Entry for \"char\" did not match expected value.", new Character(charValue).toString(), resultPayload.get("char"));
    }

    /**
     * Tests:
     * - Token payload: { "key" : [] }
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testFomJsonToken_jwtPayload_singleEntryTokenPayload_jsonArrayValue_empty() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String key = "key";
        JsonArray value = new JsonArray();
        tokenPayload.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());
        // The token payload object is added as a JsonArray, but will be read back out as an ArrayList object
        assertEquals("Entry for \"" + key + "\" did not match expected value.", new ArrayList(), resultPayload.get(key));
    }

    /**
     * Tests:
     * - Token payload: { "key" : [ one string entry ] }
     */
    @Test
    public void testFomJsonToken_jwtPayload_singleEntryTokenPayload_jsonArrayValue_oneEntry_string() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String key = "key";
        String arrayEntry = "stringValue";
        JsonArray value = new JsonArray();
        value.add(new JsonPrimitive(arrayEntry));
        tokenPayload.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        verifyJsonArrayPayload(resultPayload, key, arrayEntry);
    }

    /**
     * Tests:
     * - Token payload: { "key" : [ ... ] }
     */
    @Test
    public void testFomJsonToken_jwtPayload_singleEntryTokenPayload_jsonArrayValue_multipleEntries() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String key = "key";
        JsonArray value = new JsonArray();
        value.add(new JsonPrimitive("1"));
        value.add(new JsonPrimitive(2));
        value.add(new JsonPrimitive('3'));
        value.add(new JsonPrimitive(false));
        tokenPayload.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        verifyJsonArrayPayload(resultPayload, key, "1, 2, 3, false");
    }

    /**
     * Tests:
     * - Token payload: { "key" : {} }
     */
    @Test
    public void testFomJsonToken_jwtPayload_singleEntryTokenPayload_jsonObjectValue_empty() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String key = "key";
        JsonObject value = new JsonObject();
        tokenPayload.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());
        assertEquals("Entry for \"" + key + "\" did not match expected value.", value.toString(), resultPayload.get(key).toString());
    }

    /**
     * Tests:
     * - Token payload: { "key" : { "sub-key" : "sub-value" } }
     */
    @Test
    public void testFomJsonToken_jwtPayload_singleEntryTokenPayload_jsonObjectValue_singleEntry_stringValue() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String key = "key";
        String subKey = "sub-key";
        String subValue = "sub-value";
        JsonObject value = new JsonObject();
        value.addProperty(subKey, subValue);
        tokenPayload.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        verifyJsonObjectPayload(resultPayload, key, subKey, subValue);
    }

    /**
     * Tests:
     * - Token payload includes key already included in the result payload
     * Expects:
     * - Existing value will be replaced with the new value from the token payload
     */
    @Test
    public void testFomJsonToken_jwtPayload_tokenPayloadIncludesExistingKey() {
        String key = "key";
        String value = "value";
        JWTPayload resultPayload = new JWTPayload();
        resultPayload.put(key, value);

        final JsonObject tokenPayload = new JsonObject();
        boolean newValue = true;
        tokenPayload.addProperty(key, newValue);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertEquals("New value for key \"" + key + "\" did not match expected value.", newValue, resultPayload.get(key));
    }

    /**
     * Tests:
     * - Token payload includes multiple keys with all varieties of value types (primitives, arrays, objects, etc.)
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testFomJsonToken_jwtPayload_complicatedTokenPayload() {
        JWTPayload resultPayload = new JWTPayload();

        final JsonObject tokenPayload = new JsonObject();
        String nullKey = "null";
        String stringKey = "string";
        String booleanKey = "boolean";
        String longKey = "long";
        String doubleKey = "double";
        String charKey = "char";
        String arrayKey = "array";
        String objectKey = "object";

        String stringValue = "stringValue";
        boolean booleanValue = true;
        long longValue = 1L;
        double doubleValue = 3.14;
        char charValue = 'z';
        JsonArray arrayValue = getComplexArray();
        JsonObject objectValue = getSimpleObject();
        tokenPayload.add(nullKey, null);
        tokenPayload.addProperty(stringKey, stringValue);
        tokenPayload.addProperty(booleanKey, booleanValue);
        tokenPayload.addProperty(longKey, longValue);
        tokenPayload.addProperty(doubleKey, doubleValue);
        tokenPayload.addProperty(charKey, charValue);
        tokenPayload.add(arrayKey, arrayValue);
        tokenPayload.add(objectKey, objectValue);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getPayload();
                will(returnValue(tokenPayload));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, resultPayload);
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());
        assertEquals("Entry for \"" + nullKey + "\" should have been null but wasn't.", JsonNull.INSTANCE, resultPayload.get(nullKey));
        assertEquals("Entry for \"" + stringKey + "\" did not match expected value.", stringValue, resultPayload.get(stringKey));
        assertEquals("Entry for \"" + booleanKey + "\" did not match expected value.", booleanValue, resultPayload.get(booleanKey));
        assertEquals("Entry for \"" + longKey + "\" did not match expected value.", longValue, resultPayload.get(longKey));
        assertEquals("Entry for \"" + doubleKey + "\" did not match expected value.", doubleValue, resultPayload.get(doubleKey));
        assertEquals("Entry for \"" + charKey + "\" did not match expected value.", new Character(charValue).toString(), resultPayload.get(charKey));

        assertTrue("Entry for \"" + arrayKey + "\" was not an instance of a List object, but should have been. Entry was: " + resultPayload.get(arrayKey), resultPayload.get(arrayKey) instanceof List);
        assertTrue("Entry for \"" + objectKey + "\" was not an instance of a Map object, but should have been. Entry was: " + resultPayload.get(objectKey), resultPayload.get(objectKey) instanceof Map);

        List<Object> listResult = (List<Object>) resultPayload.get(arrayKey);
        compareJsonArrayInputToListOutput(arrayValue, listResult);

        Map<String, Object> objectResult = (Map<String, Object>) resultPayload.get(objectKey);
        compareJsonObjectInputToMapOutput(objectValue, objectResult);
    }

    /********************************************* fromJsonToken (JWSHeader) *********************************************/

    @Test
    public void testFomJsonToken_jwsHeader_nullToken_nullPayload() {
        WSJsonToken token = null;
        JWSHeader header = null;
        JsonTokenUtil.fromJsonToken(token, header);
        assertNull("Result header should have been null but was not.", header);
    }

    @Test
    public void testFomJsonToken_jwsHeader_nullToken() {
        WSJsonToken token = null;
        JWSHeader header = new JWSHeader();
        JsonTokenUtil.fromJsonToken(token, header);
        assertTrue("Result header should have been empty but wasn't. Result had keys: " + header.keySet(), header.isEmpty());
    }

    @Test
    public void testFomJsonToken_jwsHeader_nullPayload() {
        JWSHeader header = null;
        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertNull("Result header should have been null but was not.", header);
    }

    /**
     * Tests:
     * - Header: null
     */
    @Test
    public void testFomJsonToken_jwsHeader_nullHeader() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = null;
        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertTrue("Result header should have been empty but wasn't. Result had keys: " + header.keySet(), header.isEmpty());
    }

    /**
     * Tests:
     * - Header: {}
     */
    @Test
    public void testFomJsonToken_jwsHeader_emptyHeader() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertTrue("Result header should have been empty but wasn't. Result had keys: " + header.keySet(), header.isEmpty());
    }

    /**
     * Tests:
     * - Header: { "key" : null }
     */
    @Test
    public void testFomJsonToken_jwsHeader_singleEntryHeader_nullValue() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        tokenHeader.add("nullValue", null);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertTrue("Result header should have been empty but wasn't. Result had keys: " + header.keySet(), header.isEmpty());
    }

    /**
     * Tests:
     * - Header: Multiple entries, each value is a JSON primitive
     */
    @Test
    public void testFomJsonToken_jwsHeader_multiEntryHeader_primitiveValues() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        String stringValue = "stringValue";
        boolean booleanValue = false;
        long longValue = 12345L;
        double doubleValue = 1.234;
        char charValue = 'm';
        tokenHeader.add("nullKey", null);
        tokenHeader.addProperty("boolean", booleanValue);
        tokenHeader.addProperty("long", longValue);
        tokenHeader.addProperty("double", doubleValue);
        // TODO - string or char values are required to have a key matching an enum in HeaderParameter
        tokenHeader.addProperty("alg", stringValue);
        tokenHeader.addProperty("kid", charValue);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertFalse("Result header should not have been empty but was.", header.isEmpty());
        assertEquals("Entry for \"null\" did not match expected value.", null, header.get("null"));
        assertEquals("Entry for \"alg\" did not match expected value.", stringValue, header.get("alg"));
        assertEquals("Entry for \"boolean\" did not match expected value.", booleanValue, header.get("boolean"));
        assertEquals("Entry for \"long\" did not match expected value.", longValue, header.get("long"));
        assertEquals("Entry for \"double\" did not match expected value.", doubleValue, header.get("double"));
        assertEquals("Entry for \"kid\" did not match expected value.", new Character(charValue).toString(), header.get("kid"));
    }

    /**
     * Tests:
     * - Header: { "key" : [] }
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testFomJsonToken_jwsHeader_singleEntryHeader_jsonArrayValue_empty() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        // TODO - JSON array values are required to have a key matching an enum in HeaderParameter
        String key = "alg";
        JsonArray value = new JsonArray();
        tokenHeader.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertFalse("Result header should not have been empty but was.", header.isEmpty());
        // The token header object is added as a JsonArray, but will be read back out as an ArrayList object
        assertEquals("Entry for \"" + key + "\" did not match expected value.", new ArrayList(), header.get(key));
    }

    /**
     * Tests:
     * - Header: { "key" : [ one string entry ] }
     */
    @Test
    public void testFomJsonToken_jwsHeader_singleEntryHeader_jsonArrayValue_oneEntry_string() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        // TODO - JSON array values are required to have a key matching an enum in HeaderParameter
        String key = "typ";
        String arrayEntry = "stringValue";
        JsonArray value = new JsonArray();
        value.add(new JsonPrimitive(arrayEntry));
        tokenHeader.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        verifyJsonArrayHeader(header, key, arrayEntry);
    }

    /**
     * Tests:
     * - Header: { "key" : [ ... ] }
     */
    @Test
    public void testFomJsonToken_jwsHeader_singleEntryHeader_jsonArrayValue_multipleEntries() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        // TODO - JSON array values are required to have a key matching an enum in HeaderParameter
        String key = "cty";
        JsonArray value = new JsonArray();
        value.add(new JsonPrimitive("1"));
        value.add(new JsonPrimitive(2));
        value.add(new JsonPrimitive('3'));
        value.add(new JsonPrimitive(false));
        tokenHeader.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        // Only the string/char entries in the array should be added
        verifyJsonArrayHeader(header, key, "1, 3");
    }

    /**
     * Tests:
     * - Header: { "key" : {} }
     */
    @Test
    public void testFomJsonToken_jwsHeader_singleEntryHeader_jsonObjectValue_empty() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        String key = "key";
        JsonObject value = new JsonObject();
        tokenHeader.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        // TODO - JSON objects are currently ignored
        assertTrue("Result header should have been empty but wasn't. Result had keys: " + header.keySet(), header.isEmpty());
    }

    /**
     * Tests:
     * - Header: { "key" : { "sub-key" : "sub-value" } }
     */
    @Test
    public void testFomJsonToken_jwsHeader_singleEntryHeader_jsonObjectValue_singleEntry_stringValue() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        String key = "key";
        String subKey = "sub-key";
        String subValue = "sub-value";
        JsonObject value = new JsonObject();
        value.addProperty(subKey, subValue);
        tokenHeader.add(key, value);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        // TODO - JSON objects are currently ignored
        assertTrue("Result header should have been empty but wasn't. Result had keys: " + header.keySet(), header.isEmpty());
    }

    /**
     * Tests:
     * - Token header includes key already included in the result header
     * Expects:
     * - Existing value will be replaced with the new value from the token header
     */
    @Test
    public void testFomJsonToken_jwsHeader_tokenHeaderIncludesExistingKey() {
        String key = "key";
        String value = "value";
        JWSHeader header = new JWSHeader();
        header.put(key, value);

        final JsonObject tokenHeader = new JsonObject();
        long newValue = 42L;
        tokenHeader.addProperty(key, newValue);

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertEquals("New value for key \"" + key + "\" did not match expected value.", newValue, header.get(key));
    }

    /**
     * Tests:
     * - Token header includes multiple keys with all varieties of value types (primitives, arrays, objects, etc.)
     */
    @Test
    public void testFomJsonToken_jwsHeader_complicatedHeader() {
        JWSHeader header = new JWSHeader();

        final JsonObject tokenHeader = new JsonObject();
        String nullKey = "null";
        String stringKey = "jku";
        String booleanKey = "boolean";
        String longKey = "long";
        String doubleKey = "double";
        String charKey = "jwk";
        String arrayKey = "x5u";
        String objectKey = "x5c";

        String stringValue = "stringValue";
        boolean booleanValue = true;
        long longValue = 1L;
        double doubleValue = 3.14;
        char charValue = 'z';
        JsonArray arrayValue = getComplexArray();
        tokenHeader.add(nullKey, null);
        tokenHeader.addProperty(stringKey, stringValue);
        tokenHeader.addProperty(booleanKey, booleanValue);
        tokenHeader.addProperty(longKey, longValue);
        tokenHeader.addProperty(doubleKey, doubleValue);
        tokenHeader.addProperty(charKey, charValue);
        tokenHeader.add(arrayKey, arrayValue);
        tokenHeader.add(objectKey, getSimpleObject());

        mock.checking(new Expectations() {
            {
                one(jsonToken).getHeader();
                will(returnValue(tokenHeader));
            }
        });

        JsonTokenUtil.fromJsonToken(jsonToken, header);
        assertFalse("Result header should not have been empty but was.", header.isEmpty());
        assertEquals("Entry for \"" + nullKey + "\" should have been null but wasn't.", null, header.get(nullKey));
        assertEquals("Entry for \"" + stringKey + "\" did not match expected value.", stringValue, header.get(stringKey));
        assertEquals("Entry for \"" + booleanKey + "\" did not match expected value.", booleanValue, header.get(booleanKey));
        assertEquals("Entry for \"" + longKey + "\" did not match expected value.", longValue, header.get(longKey));
        assertEquals("Entry for \"" + doubleKey + "\" did not match expected value.", doubleValue, header.get(doubleKey));
        assertEquals("Entry for \"" + charKey + "\" did not match expected value.", new Character(charValue).toString(), header.get(charKey));

        assertTrue("Result did not contain expected key \"" + arrayKey + "\". Result had keys: " + header.keySet(), header.containsKey(arrayKey));
        // Only the string/char entries in the array should be added
        verifyJsonArrayHeader(header, arrayKey, "array string, a");

        // JSON objects are ignored
        assertFalse("Result contained key \"" + objectKey + "\" but was not expected to. Value was: " + header.get(objectKey), header.containsKey(objectKey));
    }

    /********************************************* getJsonPrimitive *********************************************/

    /**
     * Tests:
     * - Primitive: null
     * Expects:
     * - Result is null
     */
    @Test
    public void testGetJsonPrimitive_null() {
        JsonPrimitive primitive = null;
        Object result = JsonTokenUtil.getJsonPrimitive(primitive);
        assertEquals("Result should have been null but was not.", null, result);
    }

    /**
     * Tests:
     * - Primitive: string
     * Expects:
     * - Result matches input string
     */
    @Test
    public void testGetJsonPrimitive_string() {
        String input = "test";
        JsonPrimitive primitive = new JsonPrimitive(input);
        Object result = JsonTokenUtil.getJsonPrimitive(primitive);
        assertEquals("Result did not match expected value.", input, result);
    }

    /**
     * Tests:
     * - Primitive: boolean
     * Expects:
     * - Result matches input boolean
     */
    @Test
    public void testGetJsonPrimitive_boolean() {
        boolean input = true;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Object result = JsonTokenUtil.getJsonPrimitive(primitive);
        assertEquals("Result did not match expected value.", input, result);
    }

    /**
     * Tests:
     * - Primitive: long
     * Expects:
     * - Result matches input long
     */
    @Test
    public void testGetJsonPrimitive_long() {
        long input = 789L;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Object result = JsonTokenUtil.getJsonPrimitive(primitive);
        assertEquals("Result did not match expected value.", input, result);
    }

    /**
     * Tests:
     * - Primitive: double
     * Expects:
     * - Result matches input double
     */
    @Test
    public void testGetJsonPrimitive_double() {
        double input = 1.234;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Object result = JsonTokenUtil.getJsonPrimitive(primitive);
        assertEquals("Result did not match expected value.", input, result);
    }

    /**
     * Tests:
     * - Primitive: char
     * Expects:
     * - Result matches input char (but as its string representation)
     */
    @Test
    public void testGetJsonPrimitive_char() {
        char input = '!';
        JsonPrimitive primitive = new JsonPrimitive(input);
        Object result = JsonTokenUtil.getJsonPrimitive(primitive);
        assertEquals("Result did not match expected value.", new Character(input).toString(), result);
    }

    /********************************************* getJsonPrimitiveNumber *********************************************/

    /**
     * Tests:
     * - Input: Long
     */
    @Test
    public void testGetJsonPrimitiveNumber_long() {
        long input = 123456789L;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Number result = JsonTokenUtil.getJsonPrimitiveNumber(primitive);
        assertEquals("Result did not match the input number.", input, result);
    }

    /**
     * Tests:
     * - Input: Max long value
     */
    @Test
    public void testGetJsonPrimitiveNumber_longMax() {
        long input = Long.MAX_VALUE;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Number result = JsonTokenUtil.getJsonPrimitiveNumber(primitive);
        assertEquals("Result did not match the input number.", input, result);
    }

    /**
     * Tests:
     * - Input: Min long value
     */
    @Test
    public void testGetJsonPrimitiveNumber_longMin() {
        long input = Long.MIN_VALUE;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Number result = JsonTokenUtil.getJsonPrimitiveNumber(primitive);
        assertEquals("Result did not match the input number.", input, result);
    }

    /**
     * Tests:
     * - Input: Double
     */
    @Test
    public void testGetJsonPrimitiveNumber_double() {
        double input = 1.234;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Number result = JsonTokenUtil.getJsonPrimitiveNumber(primitive);
        assertEquals("Result did not match the input number.", input, result);
    }

    /**
     * Tests:
     * - Input: Max double value
     */
    @Test
    public void testGetJsonPrimitiveNumber_doubleMax() {
        double input = Double.MAX_VALUE;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Number result = JsonTokenUtil.getJsonPrimitiveNumber(primitive);
        assertEquals("Result did not match the input number.", input, result);
    }

    /**
     * Tests:
     * - Input: Min double value
     */
    @Test
    public void testGetJsonPrimitiveNumber_doubleMin() {
        double input = Double.MIN_VALUE;
        JsonPrimitive primitive = new JsonPrimitive(input);
        Number result = JsonTokenUtil.getJsonPrimitiveNumber(primitive);
        assertEquals("Result did not match the input number.", input, result);
    }

    /********************************************* createListFromJsonArray *********************************************/

    /**
     * Tests:
     * - Input array: null
     */
    @Test
    public void testCreateListFromJsonArray_nullArray() {
        JsonArray array = null;
        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Result should have been null but wasn't.", null, result);
    }

    /**
     * Tests:
     * - Input array: []
     */
    @Test
    public void testCreateListFromJsonArray_emptyArray() {
        JsonArray array = new JsonArray();
        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertTrue("Result should have been empty but was " + result, result.isEmpty());
    }

    /**
     * Tests:
     * - Input array: [ null ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_null() {
        JsonArray array = new JsonArray();
        array.add(null);

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", JsonNull.INSTANCE, result.get(0));
    }

    /**
     * Tests:
     * - Input array: [ string ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_string() {
        String arrayEntry = "stringValue";
        JsonArray array = new JsonArray();
        array.add(new JsonPrimitive(arrayEntry));

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry, result.get(0));
    }

    /**
     * Tests:
     * - Input array: [ boolean ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_boolean() {
        boolean arrayEntry = false;
        JsonArray array = new JsonArray();
        array.add(new JsonPrimitive(arrayEntry));

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry, result.get(0));
    }

    /**
     * Tests:
     * - Input array: [ long ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_long() {
        long arrayEntry = 1L;
        JsonArray array = new JsonArray();
        array.add(new JsonPrimitive(arrayEntry));

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry, result.get(0));
    }

    /**
     * Tests:
     * - Input array: [ double ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_double() {
        double arrayEntry = 3.141592654;
        JsonArray array = new JsonArray();
        array.add(new JsonPrimitive(arrayEntry));

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry, result.get(0));
    }

    /**
     * Tests:
     * - Input array: [ char ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_char() {
        char arrayEntry = 'z';
        JsonArray array = new JsonArray();
        array.add(new JsonPrimitive(arrayEntry));

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        // Result will be the string equivalent of the character
        assertEquals("Entry in result did not match expected value.", new Character(arrayEntry).toString(), result.get(0));
    }

    /**
     * Tests:
     * - Input array: [ [] ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_jsonArray_empty() {
        JsonArray arrayEntry = new JsonArray();
        JsonArray array = new JsonArray();
        array.add(arrayEntry);

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry.toString(), result.get(0).toString());
    }

    /**
     * Tests:
     * - Input array: [ [ null ] ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_jsonArray_oneEntryNull() {
        JsonArray arrayEntry = new JsonArray();
        arrayEntry.add(null);
        JsonArray array = new JsonArray();
        array.add(arrayEntry);

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry.toString(), result.get(0).toString());
    }

    /**
     * Tests:
     * - Input array: [ [ string ] ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_jsonArray_oneEntryString() {
        JsonArray arrayEntry = new JsonArray();
        final String subArrayValue = "sub-value";
        arrayEntry.add(new JsonPrimitive(subArrayValue));
        JsonArray array = new JsonArray();
        array.add(arrayEntry);

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        // String representation of a List doesn't include quotes around strings
        String normalizedArrayString = arrayEntry.toString().replaceAll("\"", "");
        assertEquals("Entry in result did not match expected value.", normalizedArrayString, result.get(0).toString());
    }

    /**
     * Tests:
     * - Input array: [ {} ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_jsonObject_empty() {
        JsonObject arrayEntry = new JsonObject();
        JsonArray array = new JsonArray();
        array.add(arrayEntry);

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        assertEquals("Entry in result did not match expected value.", arrayEntry.toString(), result.get(0).toString());
    }

    /**
     * Tests:
     * - Input array: [ { ... } ]
     */
    @Test
    public void testCreateListFromJsonArray_oneEntry_jsonObject_nonEmpty() {
        JsonObject arrayEntry = new JsonObject();
        arrayEntry.addProperty("sub-key", "sub-value");
        JsonArray array = new JsonArray();
        array.add(arrayEntry);

        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        // String representation of a List doesn't include quotes around strings, and key-value pairs are separated by '=', not ':'
        String normalizedArrayString = arrayEntry.toString().replaceAll("\"", "").replaceAll(":", "=");
        assertEquals("Entry in result did not match expected value.", normalizedArrayString, result.get(0).toString());
    }

    /**
     * Tests:
     * - Input array: [ list, of, primitives ]
     */
    @Test
    public void testCreateListFromJsonArray_primitivesArray() {
        JsonArray array = new JsonArray();
        array.add(null);
        array.add(new JsonPrimitive("string"));
        array.add(new JsonPrimitive(false));
        array.add(new JsonPrimitive(1L));
        array.add(new JsonPrimitive(1.23));
        array.add(new JsonPrimitive('*'));
        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        // String representation of a List doesn't include quotes around strings and has a space after each comma separating each entry
        String normalizedArrayString = array.toString().replaceAll("\"", "").replaceAll(",", ", ");
        assertEquals("Result did not match expected value.", normalizedArrayString, result.toString());
    }

    /**
     * Tests:
     * - Input array: [ [ ... ], [ ... ], [ ... ] ]
     */
    @Test
    public void testCreateListFromJsonArray_arraysWithinArray() {
        JsonArray array = new JsonArray();
        JsonArray subArray1 = new JsonArray();
        subArray1.add(null);
        subArray1.add(new JsonPrimitive("string"));
        JsonArray subArray2 = new JsonArray();
        subArray2.add(new JsonPrimitive(false));
        subArray2.add(new JsonPrimitive(1L));
        JsonArray subArray3 = new JsonArray();
        subArray3.add(new JsonPrimitive(1.23));
        subArray3.add(new JsonPrimitive('*'));
        array.add(subArray1);
        array.add(subArray2);
        array.add(subArray3);
        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        // String representation of a List doesn't include quotes around strings and has a space after each comma separating each entry
        String normalizedArrayString = array.toString().replaceAll("\"", "").replaceAll(",", ", ");
        assertEquals("Result did not match expected value.", normalizedArrayString, result.toString());
    }

    /**
     * Tests:
     * - Input array: [ { ... }, { ... }, { ... } ]
     */
    @Test
    public void testCreateListFromJsonArray_objectsArray() {
        JsonObject subObject1 = new JsonObject();
        subObject1.add("nullKey", null);
        subObject1.add("char", new JsonPrimitive('y'));
        JsonObject subObject2 = new JsonObject();
        subObject2.add("string", new JsonPrimitive("value"));
        subObject2.add("double", new JsonPrimitive(3.14));
        JsonObject subObject3 = new JsonObject();
        subObject3.add("boolean", new JsonPrimitive(true));
        subObject3.add("long", new JsonPrimitive(123456789L));

        JsonArray array = new JsonArray();
        array.add(subObject1);
        array.add(subObject2);
        array.add(subObject3);
        List<Object> result = JsonTokenUtil.createListFromJsonArray(array);
        // String representation of a List doesn't include quotes around strings and has a space after each comma separating each entry
        String normalizedArrayString = array.toString().replaceAll("\"", "").replaceAll(":", "=").replaceAll(",", ", ");
        assertEquals("Result did not match expected value.", normalizedArrayString, result.toString());
    }

    /********************************************* createMapFromJsonObject *********************************************/

    /**
     * Tests:
     * - Input object: null
     */
    @Test
    public void testCreateMapFromJsonObject_nullObject() {
        JsonObject object = null;
        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);
        assertEquals("Result should have been null but wasn't.", null, result);
    }

    /**
     * Tests:
     * - Input object: {}
     */
    @Test
    public void testCreateMapFromJsonObject_emptyObject() {
        JsonObject object = new JsonObject();
        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);
        assertTrue("Result should have been empty but was " + result, result.isEmpty());
    }

    /**
     * Tests:
     * - Input object: { "key" : null }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_nullValue() {
        String key = "key";
        JsonObject object = new JsonObject();
        object.add(key, null);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", JsonNull.INSTANCE, result.get(key));
    }

    /**
     * Tests:
     * - Input object: { "key" : string }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_stringValue() {
        String key = "key";
        String value = "stringValue";
        JsonObject object = new JsonObject();
        object.addProperty(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value, result.get(key));
    }

    /**
     * Tests:
     * - Input object: { "key" : boolean }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_booleanValue() {
        String key = "key";
        boolean value = true;
        JsonObject object = new JsonObject();
        object.addProperty(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value, result.get(key));
    }

    /**
     * Tests:
     * - Input object: { "key" : long }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_longValue() {
        String key = "key";
        long value = 123L;
        JsonObject object = new JsonObject();
        object.addProperty(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value, result.get(key));
    }

    /**
     * Tests:
     * - Input object: { "key" : double }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_doubleValue() {
        String key = "key";
        double value = 0.123456789;
        JsonObject object = new JsonObject();
        object.addProperty(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value, result.get(key));
    }

    /**
     * Tests:
     * - Input object: { "key" : char }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_charValue() {
        String key = "key";
        char value = 'b';
        JsonObject object = new JsonObject();
        object.addProperty(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        // Result will be the string equivalent of the character
        assertEquals("Result did not match expected value.", new Character(value).toString(), result.get(key));
    }

    /**
     * Tests:
     * - Input object: { "key" : [] }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_jsonArrayValue_empty() {
        String key = "key";
        JsonArray value = new JsonArray();
        JsonObject object = new JsonObject();
        object.add(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value.toString(), result.get(key).toString());
    }

    /**
     * Tests:
     * - Input object: { "key" : [ null ] }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_jsonArrayValue_singleEntry_null() {
        String key = "key";
        JsonArray value = new JsonArray();
        value.add(null);
        JsonObject object = new JsonObject();
        object.add(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value.toString(), result.get(key).toString());
    }

    /**
     * Tests:
     * - Input object: { "key" : [ string ] }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_jsonArrayValue_singleEntry_string() {
        String key = "key";
        String subValue = "subValue";
        JsonArray value = new JsonArray();
        value.add(new JsonPrimitive(subValue));
        JsonObject object = new JsonObject();
        object.add(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        // String representation of a List doesn't include quotes around strings
        String normalizedString = value.toString().replaceAll("\"", "");
        assertEquals("Result did not match expected value.", normalizedString, result.get(key).toString());
    }

    /**
     * Tests:
     * - Input object: { "key" : {} }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_jsonObjectValue_empty() {
        String key = "key";
        JsonObject value = new JsonObject();
        JsonObject object = new JsonObject();
        object.add(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Result did not match expected value.", value.toString(), result.get(key).toString());
    }

    /**
     * Tests:
     * - Input object: { "key" : { "sub key" : null } }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_jsonObjectValue_singleEntry_null() {
        String key = "key";
        String subKey = "sub key";
        JsonObject value = new JsonObject();
        value.add(subKey, null);
        JsonObject object = new JsonObject();
        object.add(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        // String representation of a Map doesn't include quotes around strings, and key-value pairs are separated by '=', not ':'
        String normalizedString = value.toString().replaceAll("\"", "").replaceAll(":", "=");
        assertEquals("Result did not match expected value.", normalizedString, result.get(key).toString());
    }

    /**
     * Tests:
     * - Input object: { "key" : { "sub key" : double } }
     */
    @Test
    public void testCreateMapFromJsonObject_singleEntry_jsonObjectValue_singleEntry_double() {
        String key = "key";
        String subKey = "sub key";
        double subValue = 0.123456789;
        JsonObject value = new JsonObject();
        value.addProperty(subKey, subValue);
        JsonObject object = new JsonObject();
        object.add(key, value);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        // String representation of a Map doesn't include quotes around strings, and key-value pairs are separated by '=', not ':'
        String normalizedString = value.toString().replaceAll("\"", "").replaceAll(":", "=");
        assertEquals("Result did not match expected value.", normalizedString, result.get(key).toString());
    }

    /**
     * Tests:
     * - Input object: Contains only primitives
     */
    @Test
    public void testCreateMapFromJsonObject_primitivesObject() {
        JsonObject object = new JsonObject();
        object.add("nullValue", null);
        object.addProperty("string", "stringValue");
        object.addProperty("boolean", true);
        object.addProperty("long", 9L);
        object.addProperty("double", 9.87);
        object.addProperty("char", 'a');

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Entry for \"nullValue\" did not match expected value.", JsonNull.INSTANCE, result.get("nullValue"));
        assertEquals("Entry for \"string\" did not match expected value.", "stringValue", result.get("string"));
        assertEquals("Entry for \"boolean\" did not match expected value.", true, result.get("boolean"));
        assertEquals("Entry for \"long\" did not match expected value.", 9L, result.get("long"));
        assertEquals("Entry for \"double\" did not match expected value.", 9.87, result.get("double"));
        assertEquals("Entry for \"char\" did not match expected value.", new Character('a').toString(), result.get("char"));
    }

    /**
     * Tests:
     * - Input object: Contains a mix of JSON value types
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testCreateMapFromJsonObject_complexObject() {
        JsonObject object = new JsonObject();
        String nullKey = "nullValue";
        String longKey = "long";
        String arrayKey = "array";
        String objectKey = "object";
        long longValue = 1L;
        JsonArray arrayValue = getComplexArray();
        JsonObject objectValue = getSimpleObject();

        object.add(nullKey, null);
        object.addProperty(longKey, longValue);
        object.add(arrayKey, arrayValue);
        object.add(objectKey, objectValue);

        Map<String, Object> result = JsonTokenUtil.createMapFromJsonObject(object);

        assertEquals("Entry for \"" + nullKey + "\" did not match expected value.", JsonNull.INSTANCE, result.get(nullKey));
        assertEquals("Entry for \"" + longKey + "\" did not match expected value.", longValue, result.get(longKey));

        assertTrue("Entry for \"" + arrayKey + "\" was not an instance of a List object, but should have been. Entry was: " + result.get(arrayKey), result.get(arrayKey) instanceof List);
        assertTrue("Entry for \"" + objectKey + "\" was not an instance of a Map object, but should have been. Entry was: " + result.get(objectKey), result.get(objectKey) instanceof Map);

        List<Object> listResult = (List<Object>) result.get(arrayKey);
        compareJsonArrayInputToListOutput(arrayValue, listResult);

        Map<String, Object> objectResult = (Map<String, Object>) result.get(objectKey);
        compareJsonObjectInputToMapOutput(objectValue, objectResult);
    }

    /********************************************* Helper methods *********************************************/

    private void verifyJsonArrayPayload(JWTPayload resultPayload, String key, Object arrayEntry) {
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());

        String expectedValue = "[" + (arrayEntry == null ? null : arrayEntry.toString()) + "]";
        assertEquals("Entry for \"" + key + "\" did not match expected value.", expectedValue, resultPayload.get(key).toString());
    }

    private void verifyJsonArrayHeader(JWSHeader header, String key, Object arrayEntry) {
        assertFalse("Result header should not have been empty but was.", header.isEmpty());

        String expectedValue = "[" + (arrayEntry == null ? null : arrayEntry.toString()) + "]";
        assertEquals("Entry for \"" + key + "\" did not match expected value.", expectedValue, header.get(key).toString());
    }

    private void verifyJsonObjectPayload(JWTPayload resultPayload, String key, String subKey, Object subValue) {
        assertFalse("Result payload should not have been empty but was.", resultPayload.isEmpty());
        assertEquals("Entry for \"" + key + "\" did not match expected value.", "{" + subKey + "=" + subValue + "}", resultPayload.get(key).toString());
    }

    private void compareJsonArrayInputToListOutput(JsonArray input, List<Object> output) {
        assertEquals("Input array and output list did not contain the same number of entries. Input was: " + input + ". Output was: " + output, input.size(), output.size());
        for (int i = 0; i < input.size(); i++) {
            Object convertedEntry = convertJsonElementToPojo(input.get(i));
            assertTrue("List produced in the result did not contain expected [" + convertedEntry + "] entry. List was: " + output, output.contains(convertedEntry));
        }
    }

    private void compareJsonObjectInputToMapOutput(JsonObject input, Map<String, Object> output) {
        Set<Entry<String, JsonElement>> inputEntries = input.entrySet();
        assertEquals("Input and output objects did not contain the same number of entries. Input entries were: " + inputEntries + ". Output entries were: " + output.keySet(), inputEntries.size(), output.size());

        for (Entry<String, JsonElement> inputEntry : inputEntries) {
            String key = inputEntry.getKey();
            assertTrue("Map produced in the result did not contain expected [" + key + "] entry. Map was: " + output, output.containsKey(key));

            Object convertedEntry = convertJsonElementToPojo(inputEntry.getValue());
            assertEquals("Entry for [" + key + "] did not match the value in the original JSON object.", convertedEntry, output.get(key));
        }
    }

    private Object convertJsonElementToPojo(JsonElement element) {
        Object convertedObject = null;
        if (element.isJsonPrimitive()) {
            convertedObject = convertJsonPrimitiveToPojo(element.getAsJsonPrimitive());
        } else if (element.isJsonArray()) {
            convertedObject = convertJsonArrayToPojo(element.getAsJsonArray());
        } else if (element.isJsonObject()) {
            convertedObject = convertJsonObjectToPojo(element.getAsJsonObject());
        } else if (element.isJsonNull()) {
            convertedObject = JsonNull.INSTANCE;
        }
        return convertedObject;
    }

    private Object convertJsonPrimitiveToPojo(JsonPrimitive primitive) {
        Object convertedObject = null;
        if (primitive.isBoolean()) {
            convertedObject = primitive.getAsBoolean();
        } else if (primitive.isNumber()) {
            convertedObject = primitive.getAsNumber();
        } else if (primitive.isString()) {
            convertedObject = primitive.getAsString();
        }
        return convertedObject;
    }

    private Object convertJsonArrayToPojo(JsonArray array) {
        List<Object> list = new ArrayList<Object>();
        for (int i = 0; i < array.size(); i++) {
            list.add(convertJsonElementToPojo(array.get(i)));
        }
        return list;
    }

    private Object convertJsonObjectToPojo(JsonObject object) {
        Map<String, Object> map = new HashMap<String, Object>();
        Set<Entry<String, JsonElement>> entries = object.entrySet();
        for (Entry<String, JsonElement> entry : entries) {
            String key = entry.getKey();
            map.put(key, convertJsonElementToPojo(entry.getValue()));
        }
        return map;
    }

    private JsonArray getComplexArray() {
        JsonArray array = new JsonArray();
        array.add(null);
        array.add(new JsonPrimitive("array string"));
        array.add(new JsonPrimitive(false));
        array.add(new JsonPrimitive(4L));
        array.add(new JsonPrimitive(4.5));
        array.add(new JsonPrimitive('a'));
        array.add(getSimpleArray());
        array.add(getSimpleObject());
        return array;
    }

    private JsonArray getSimpleArray() {
        JsonArray array = new JsonArray();
        array.add(new JsonPrimitive("simple array string"));
        array.add(new JsonPrimitive(true));
        array.add(new JsonPrimitive(1.234));
        return array;
    }

    private JsonObject getSimpleObject() {
        JsonObject object = new JsonObject();
        object.addProperty("object string", "objectStringValue");
        object.addProperty("object boolean", false);
        object.add("object array", getSimpleArray());
        return object;
    }

}
