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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

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

import com.ibm.ws.security.openidconnect.token.Payload;

public class IDTokenPayloadTest {
    private static SharedOutputManager outputMgr;
    Date date = new Date();

    private final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr = SharedOutputManager.getInstance();
        outputMgr.captureStreams();
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
        outputMgr.resetStreams();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.restoreStreams();
    }

    @Test
    public void testSetAuthorizationTime() {
        Payload payLoad = new Payload();
        payLoad.setIssuedAtTimeSeconds(date.getTime() / 1000);
        payLoad.setAuthorizationTimeSeconds((date.getTime() + 20000) / 1000);
        Long authorizationTime = payLoad.getAuthorizationTimeSeconds();
        assertNotNull("Authorization time in seconds is not valid", authorizationTime);
    }

    @Test
    public void testSetAuthorizedParty() {
        Payload payLoad = new Payload();
        payLoad.setAuthorizedParty("authorizedParty");
        String authorized = payLoad.getAuthorizedParty();
        String authorized2 = (String) payLoad.get("azp");
        assertEquals(authorized, authorized2);
    }

    @Test
    public void testSetClassReference() {
        Payload payLoad = new Payload();
        payLoad.setClassReference("classReference");
        String receivedClassReference = (String) payLoad.get("acr");
        String received2 = payLoad.getClassReference();
        assertEquals("classReference", receivedClassReference);
        assertEquals(receivedClassReference, received2);
    }

    @Test
    public void testSetmethodsReferences() {
        Payload payLoad = new Payload();
        List<String> methods = new ArrayList();
        methods.add("methodref1");
        methods.add("methodref2");
        String[] list1 = { "methodref1", "methodref2" };
        payLoad.setMethodsReferences(methods);
        List<String> receivedList = payLoad.getMethodsReferences();
        String[] list2 = new String[receivedList.size()];
        for (int i = 0; i < receivedList.size(); i++) {
            list2[i] = receivedList.get(i);
        }
        assertArrayEquals("Methods references are not same",
                list1, list2);

    }

    @Test
    public void testSetNotBeforeTimeSeconds() {
        Payload payLoad = new Payload();
        payLoad.setNotBeforeTimeSeconds((date.getTime() - 10000) / 1000);
        long nbt1 = payLoad.getNotBeforeTimeSeconds().longValue();
        long nbt2 = (long) (Long) payLoad.get("nbf");
        assertEquals(nbt1, nbt2);
    }
}
