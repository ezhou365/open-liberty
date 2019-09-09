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
package com.ibm.ws.security.openidconnect.common;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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

import com.ibm.oauth.core.api.OAuthComponentInstance;
import com.ibm.oauth.core.api.attributes.AttributeList;
import com.ibm.oauth.core.api.oauth20.token.OAuth20Token;
import com.ibm.oauth.core.internal.oauth20.OAuth20ComponentInternal;
import com.ibm.oauth.core.internal.oauth20.OAuth20Constants;
import com.ibm.oauth.core.internal.oauth20.config.OAuth20ConfigProvider;
import com.ibm.oauth.core.internal.oauth20.responsetype.impl.OAuth20ResponseTypeHandlerTokenImpl;
import com.ibm.oauth.core.internal.oauth20.token.OAuth20TokenFactory;
import com.ibm.ws.security.oauth20.api.OidcOAuth20Client;
import com.ibm.ws.security.oauth20.api.OidcOAuth20ClientProvider;
import com.ibm.ws.security.oauth20.util.OIDCConstants;
import com.ibm.ws.security.openidconnect.common.cl.BuildResponseTypeUtil;
import com.ibm.ws.security.openidconnect.server.plugins.IDTokenHandler;
import com.ibm.ws.security.openidconnect.server.plugins.IDTokenImpl;
import com.ibm.ws.security.openidconnect.server.plugins.OIDCGrantTypeHandlerCodeImpl;
import com.ibm.ws.security.openidconnect.server.plugins.OIDCGrantTypeHandlerRefreshImpl;

public class BuildResponseTypeUtilTest {
    private static SharedOutputManager outputMgr;

    private final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };
    final AttributeList attributeList = mock.mock(AttributeList.class, "attributeList");
    final OAuth20TokenFactory oauth20TokenFactory = mock.mock(OAuth20TokenFactory.class, "oauth20ToknFactory");
    final OAuth20Token code = mock.mock(OAuth20Token.class, "code");
    final Map<String, String[]> accessTokenMap = mock.mock(Map.class, "accessTokenmap");
    final OAuth20Token access = mock.mock(OAuth20Token.class, "access");
    final OAuth20Token refresh = mock.mock(OAuth20Token.class, "refresh");
    final OAuth20Token idtoken = mock.mock(OAuth20Token.class, "idtoken");
    final OAuth20ComponentInternal componentInternal = mock.mock(OAuth20ComponentInternal.class, "componentInternal");
    final OAuth20ConfigProvider oauth20ConfigProvider = mock.mock(OAuth20ConfigProvider.class, "oauth20ConfigProvider");
    final OAuthComponentInstance oauthComponentInstance = mock.mock(OAuthComponentInstance.class, "oauuthComponentInstance");
    final IDTokenHandler idTokenHandler = mock.mock(IDTokenHandler.class, "idTokenhandler");
    final OidcOAuth20ClientProvider oauth20ClientProvider = mock.mock(OidcOAuth20ClientProvider.class, "oauth20ClientProvider");
    final OidcOAuth20Client oauth20Client = mock.mock(OidcOAuth20Client.class, "oauth20Client");
    final IDTokenImpl idTokenImpl = mock.mock(IDTokenImpl.class, "idTokenImpl");
    final List<OAuth20Token> tokenList = mock.mock(ArrayList.class);
    final Iterator iterator = mock.mock(Iterator.class, "iterator");
    final OAuth20ResponseTypeHandlerTokenImpl oa20rthti = mock.mock(OAuth20ResponseTypeHandlerTokenImpl.class, "oa20rthti");

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr = SharedOutputManager.getInstance();
        outputMgr.captureStreams();
    }

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() {
        mock.assertIsSatisfied();
        outputMgr.resetStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.restoreStreams();
    }

    @Test
    public void testConstructor() {
        final String methodName = "testConstructor";
        try {
            BuildResponseTypeUtil brtu = new BuildResponseTypeUtil();
            assertNotNull("Can not instantiate an BuildResponseUtil", brtu);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testHandleIDToken() {
        final String methodName = "testHandleIDToken";
        try {
            AttributeList attrList = new AttributeList();
            final String idTokenStr = "idtoken_header.idtoken_payload.idtoken_signature";
            mock.checking(new Expectations() {
                {
                    one(idTokenImpl).getTokenString();
                    will(returnValue(idTokenStr));
                }
            });
            BuildResponseTypeUtil.handleIDToken(attrList, idTokenImpl);
            String[] aStr1 = attrList.getAttributeValuesByNameAndType(OIDCConstants.ID_TOKEN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr1);
            assertEquals("The return array ought to have accessTokenString in it but not",
                    idTokenStr, aStr1[0]);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testHandleRefreshToken() {
        final String methodName = "testHandleRefreshToken";
        try {
            AttributeList attrList = new AttributeList();
            final String refreshTokenStr = "refreshtokenabcdef";
            final String refreshTokenId = "refreshtokenID";
            mock.checking(new Expectations() {
                {
                    one(refresh).getTokenString();
                    will(returnValue(refreshTokenStr));
                    one(refresh).getId();
                    will(returnValue(refreshTokenId));
                }
            });

            BuildResponseTypeUtil.handleRefreshToken(attrList, refresh);

            String[] aStr1 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.REFRESH_TOKEN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr1);
            assertEquals("The return array ought to have accessTokenString in it but not",
                    refreshTokenStr, aStr1[0]);

            String[] aStr2 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.REFRESH_TOKEN_ID,
                    OAuth20Constants.ATTRTYPE_RESPONSE_META);
            assertNotNull("It ought to have at least on instance in attribute values", aStr2);
            assertEquals("The return array ought to have accessTokenID in it but not",
                    refreshTokenId, aStr2[0]);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testHandleAccessToken() {
        final String methodName = "testHandleAccessToken";
        try {
            AttributeList attrList = new AttributeList();
            final String accessTokenStr = "accesstokenabcdefg";
            final String accessTokenId = "refreshtokenID";
            final String accessTokenSub = "accSub";
            final String accessTokenStateId = "stateId1";
            final String[] accessTokenScopes = new String[] { "openid", "profile" };
            mock.checking(new Expectations() {
                {
                    one(access).getTokenString();
                    will(returnValue(accessTokenStr));
                    one(access).getId();
                    will(returnValue(accessTokenId));
                    one(access).getSubType();
                    will(returnValue(accessTokenSub));
                    one(access).getCreatedAt();
                    will(returnValue((long) 20000));
                    one(access).getLifetimeSeconds();
                    will(returnValue(2)); // 2000
                    one(access).getStateId();
                    will(returnValue(accessTokenStateId));
                    one(access).getScope();
                    will(returnValue(accessTokenScopes));
                }
            });

            BuildResponseTypeUtil.handleAccessToken(attrList, access);

            String[] aStr1 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.ACCESS_TOKEN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr1);
            assertEquals("The return array ought to have accessTokenString in it but not",
                    accessTokenStr, aStr1[0]);

            String[] aStr2 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.ACCESS_TOKEN_ID,
                    OAuth20Constants.ATTRTYPE_RESPONSE_META);
            assertNotNull("It ought to have at least on instance in attribute values", aStr2);
            assertEquals("The return array ought to have accessTokenID in it but not",
                    accessTokenId, aStr2[0]);

            String[] aStr3 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.TOKEN_TYPE,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr3);
            assertEquals("The return array ought to have accessTokenSub in it but not",
                    accessTokenSub, aStr3[0]);

            String[] aStr4 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.EXPIRES_IN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr4);
            assertEquals("The return array ought to have expires_int value in it but not",
                    aStr4.length, 1);

            String[] aStr5 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.STATE_ID,
                    OAuth20Constants.ATTRTYPE_RESPONSE_STATE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr5);
            assertEquals("The return array ought to have startId value in it but not",
                    accessTokenStateId, aStr5[0]);

            String[] aStr6 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.SCOPE,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr6);
            assertEquals("The return array ought to have 2 scopes but not",
                    aStr6.length, 2);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testBuildResponseType() {
        final String methodName = "testBuildResponseType";
        try {
            myBuildResponseTypeTest myTest = new myBuildResponseTypeTest();
            myTest.mockAccessToken();
            myTest.mockRefreshToken();
            myTest.mockIdToken();
            BuildResponseTypeUtil.buildResponseGrantType(myTest.attrList, tokenList);
            myTest.checkAccessResult();
            myTest.checkRefreshResult();
            myTest.checkIdTokenResult();
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testBuildResponseTypeCode() {
        final String methodName = "testBuildResponseTypeCode";
        try {
            myBuildResponseTypeTest myTest = new myBuildResponseTypeTest();
            myTest.mockAccessToken();
            myTest.mockRefreshToken();
            myTest.mockIdToken();
            OIDCGrantTypeHandlerCodeImpl ogthci = new OIDCGrantTypeHandlerCodeImpl();
            ogthci.buildResponseGrantType(myTest.attrList, tokenList);
            myTest.checkAccessResult();
            myTest.checkRefreshResult();
            myTest.checkIdTokenResult();
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testBuildResponseTypeRefresh() {
        final String methodName = "testBuildResponseTypeRefresh";
        try {
            myBuildResponseTypeTest myTest = new myBuildResponseTypeTest();
            myTest.mockAccessToken();
            //myTest.mockRefreshToken();
            myTest.mockIdToken();
            OIDCGrantTypeHandlerRefreshImpl ogthri = new OIDCGrantTypeHandlerRefreshImpl();
            ogthri.buildResponseGrantType(myTest.attrList, tokenList);
            myTest.checkAccessResult();
            //myTest.checkRefreshResult();
            myTest.checkIdTokenResult();
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }

    }

    @Test
    public void testPutAccessTokenInMap() {
        final String methodName = "testPutAccessTokenInMap";
        try {
            final String accessTokenStr = "accessTokenABCDEFGHIJKLMNOPQ";
            Map<String, String[]> idTokenMap = new HashMap<String, String[]>();
            List<OAuth20Token> tokenList = new ArrayList<OAuth20Token>();
            tokenList.add(access);
            mock.checking(new Expectations() {
                {
                    one(access).getType();
                    will(returnValue(OAuth20Constants.ACCESS_TOKEN));
                    one(access).getTokenString();
                    will(returnValue(accessTokenStr));
                }
            });

            BuildResponseTypeUtil.putAccessTokenInMap(idTokenMap, tokenList);
            String[] tokenStrings = idTokenMap.get(OAuth20Constants.ACCESS_TOKEN);
            assertEquals("The accessTokenString should have only one entry but it does not", 1, tokenStrings.length);
            assertEquals("It does not get the right accessTokenStr", accessTokenStr, tokenStrings[0]);

        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    @Test
    public void testPutIssuerIdentifierInMap() {
        final String methodName = "testPutIssuerIdentifierInMap";
        try {
            Map<String, String[]> idTokenMap = new HashMap<String, String[]>();
            AttributeList attrList = new AttributeList();
            String issuerIdentifier = "issuerIdentifier.ibm.com";
            attrList.setAttribute("issuerIdentifier", "ibm.com.type.one", new String[] { issuerIdentifier });
            BuildResponseTypeUtil.putIssuerIdentifierInMap(idTokenMap, attrList);
            String[] tokenStrings = idTokenMap.get("issuerIdentifier");
            assertEquals("The accessTokenString should have only one entry but it does not", 1, tokenStrings.length);
            assertEquals("It does not get the right accessTokenStr", issuerIdentifier, tokenStrings[0]);
        } catch (Throwable t) {
            outputMgr.failWithThrowable(methodName, t);
        }
    }

    class myBuildResponseTypeTest {
        AttributeList attrList = new AttributeList();
        final String methodName = "testBuildResponseType";
        // accessToken
        final String accessTokenStr = "accesstokenabcdefg";
        final String accessTokenId = "refreshtokenID";
        final String accessTokenSub = "accSub";
        final String accessTokenStateId = "stateId1";
        final String[] accessTokenScopes = new String[] { "openid", "profile" };
        // refresh token
        final String refreshTokenStr = "refreshtokenabcdef";
        final String refreshTokenId = "refreshtokenID";
        // IDToken
        final String idTokenStr = "idtoken_header.idtoken_payload.idtoken_signature";

        public void mockAccessToken() {
            // access token
            mock.checking(new Expectations() {
                {
                    one(tokenList).iterator();
                    will(returnValue(iterator));
                    one(iterator).hasNext();
                    will(returnValue(true));
                    one(iterator).next();
                    will(returnValue(access));
                    one(access).getType();
                    will(returnValue(OAuth20Constants.ACCESS_TOKEN));
                    one(access).getTokenString();
                    will(returnValue(accessTokenStr));
                    one(access).getId();
                    will(returnValue(accessTokenId));
                    one(access).getSubType();
                    will(returnValue(accessTokenSub));
                    one(access).getCreatedAt();
                    will(returnValue((long) 20000));
                    one(access).getLifetimeSeconds();
                    will(returnValue(2)); // 2000
                    one(access).getStateId();
                    will(returnValue(accessTokenStateId));
                    one(access).getScope();
                    will(returnValue(accessTokenScopes));
                }
            });
        }

        public void mockRefreshToken() {

            // refresh token
            mock.checking(new Expectations() {
                {
                    one(iterator).hasNext();
                    will(returnValue(true));
                    one(iterator).next();
                    will(returnValue(refresh));
                    one(refresh).getType();
                    will(returnValue("authorization_grant"));
                    one(refresh).getTokenString();
                    will(returnValue(refreshTokenStr));
                    one(refresh).getId();
                    will(returnValue(refreshTokenId));
                }
            });
        }

        public void mockIdToken() {

            // IDToken
            mock.checking(new Expectations() {
                {
                    one(iterator).hasNext();
                    will(returnValue(true));
                    one(iterator).next();
                    will(returnValue(idTokenImpl));
                    one(idTokenImpl).getType();
                    will(returnValue(OIDCConstants.ID_TOKEN));
                    one(idTokenImpl).getTokenString();
                    will(returnValue(idTokenStr));

                    one(iterator).hasNext();
                    will(returnValue(false));
                }
            });
        }

        public void execute() {

            mockAccessToken();
            mockRefreshToken();
            mockIdToken();
            BuildResponseTypeUtil.buildResponseGrantType(attrList, tokenList);
            checkAccessResult();
            checkRefreshResult();
            checkIdTokenResult();

        }

        public void checkAccessResult() {

            // access token
            String[] aStr1 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.ACCESS_TOKEN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr1);
            assertEquals("The return array ought to have accessTokenString in it but not",
                    accessTokenStr, aStr1[0]);

            String[] aStr2 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.ACCESS_TOKEN_ID,
                    OAuth20Constants.ATTRTYPE_RESPONSE_META);
            assertNotNull("It ought to have at least on instance in attribute values", aStr2);
            assertEquals("The return array ought to have accessTokenID in it but not",
                    accessTokenId, aStr2[0]);

            String[] aStr3 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.TOKEN_TYPE,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr3);
            assertEquals("The return array ought to have accessTokenSub in it but not",
                    accessTokenSub, aStr3[0]);

            String[] aStr4 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.EXPIRES_IN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr4);
            assertEquals("The return array ought to have expires_int value in it but not",
                    aStr4.length, 1);

            String[] aStr5 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.STATE_ID,
                    OAuth20Constants.ATTRTYPE_RESPONSE_STATE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr5);
            assertEquals("The return array ought to have startId value in it but not",
                    accessTokenStateId, aStr5[0]);

            String[] aStr6 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.SCOPE,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr6);
            assertEquals("The return array ought to have 2 scopes but not",
                    aStr6.length, 2);

        }

        public void checkRefreshResult() {

            String[] aStr1 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.REFRESH_TOKEN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr1);
            assertEquals("The return array ought to have accessTokenString in it but not",
                    refreshTokenStr, aStr1[0]);

            String[] aStr2 = attrList.getAttributeValuesByNameAndType(OAuth20Constants.REFRESH_TOKEN_ID,
                    OAuth20Constants.ATTRTYPE_RESPONSE_META);
            assertNotNull("It ought to have at least on instance in attribute values", aStr2);
            assertEquals("The return array ought to have accessTokenID in it but not",
                    refreshTokenId, aStr2[0]);

        }

        public void checkIdTokenResult() {

            String[] aStr1 = attrList.getAttributeValuesByNameAndType(OIDCConstants.ID_TOKEN,
                    OAuth20Constants.ATTRTYPE_RESPONSE_ATTRIBUTE);
            assertNotNull("It ought to have at least on instance in attribute values", aStr1);
            assertEquals("The return array ought to have accessTokenString in it but not",
                    idTokenStr, aStr1[0]);

        }
    }
}
