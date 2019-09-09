/*
 * IBM Confidential
 *
 * OCO Source Materials
 *
 * Copyright IBM Corp. 2018
 *
 * The source code for this program is not published or otherwise divested
 * of its trade secrets, irrespective of what has been deposited with the
 * U.S. Copyright Office.
 */

package com.ibm.ws.security.openidconnect.common;

import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.security.openidconnect.clients.common.OidcClientRequest;
import com.ibm.ws.security.openidconnect.jose4j.Jose4jValidator;
import com.ibm.ws.security.openidconnect.token.JWTTokenValidationFailedException;

public class Jose4jValidatorTest {

    private static final Mockery mockery = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

    }

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() {
        mockery.assertIsSatisfied();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {

    }

    // check that we reject a token without an iat (issued at).
    // the expectations assure that we throw the exception for the right reason (no iat) and not some other reason.
    @Test
    public void testIatRequired() {
        final Key key = mockery.mock(java.security.Key.class);
        final OidcClientRequest req = mockery.mock(OidcClientRequest.class);
        final JwtContext jctxt = mockery.mock(JwtContext.class);
        final JwtClaims jclaims = mockery.mock(JwtClaims.class);
        final JsonWebSignature jsig = mockery.mock(JsonWebSignature.class);
        final TraceComponent tc = mockery.mock(TraceComponent.class);
        final List<String> audiences = new ArrayList<String>();
        audiences.add("clientId");
        final List<String> allowedAudiences = new ArrayList<String>();
        allowedAudiences.add("clientId");
        boolean caughtExpectedException = false;

        try {
            mockery.checking(new Expectations() {
                {
                    allowing(req).getTokenType();
                    will(returnValue(OidcCommonClientRequest.TYPE_ID_TOKEN));

                    allowing(req).disableIssChecking();
                    will(returnValue(true));

                    allowing(req).getAudiences();
                    will(returnValue(allowedAudiences));

                    allowing(jctxt).getJwtClaims();
                    will(returnValue(jclaims));

                    allowing(jclaims).getAudience();
                    will(returnValue(audiences));

                    allowing(req).allowedAllAudiences();
                    will(returnValue(true));

                    allowing(jclaims).getIssuer();
                    will(returnValue(null));

                    // mockery needs to check this got invoked to make sure we got this far in the code.
                    one(jclaims).getIssuedAt(); // this should cause the failure
                    will(returnValue(null));

                    one(req).errorCommon(with(any(Boolean.class)), with(any(TraceComponent.class)), with(any(String.class)), with(any(Object[].class)));

                }
            });

            Jose4jValidator val = new Jose4jValidator(key, 300, "" /* issuer */, "clientid", "none" /* sigalg */, req);

            val.parseJwtWithValidation("blah.blah.blah", jctxt, jsig);
            System.out.println("No exception was thrown");
        } catch (JWTTokenValidationFailedException e) {
            // can't say for sure this exception was thrown for the reason we're hoping for,
            // but if not, we will likely fail for mockery expectations not met.
            caughtExpectedException = true;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }

        assertTrue("did not catch expected validation exception due to missing iat ", caughtExpectedException);
    }

}
