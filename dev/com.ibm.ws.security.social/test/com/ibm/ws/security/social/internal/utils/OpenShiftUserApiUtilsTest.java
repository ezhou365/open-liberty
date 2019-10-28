/*******************************************************************************
 * Copyright (c) 2019 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.social.internal.utils;

import static org.junit.Assert.*;

import javax.net.ssl.SSLSocketFactory;

import org.jmock.Expectations;
import org.jose4j.lang.JoseException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.ws.security.social.error.SocialLoginException;
import com.ibm.ws.security.social.internal.OidcLoginConfigImpl;
import com.ibm.ws.security.social.internal.OpenShiftLoginConfigImpl;
import com.ibm.ws.security.social.test.CommonTestClass;

import test.common.SharedOutputManager;

public class OpenShiftUserApiUtilsTest extends CommonTestClass {
        
	private final OpenShiftUserApiUtils openShiftUserApiUtils = new OpenShiftUserApiUtils(new OpenShiftLoginConfigImpl());
   // private final OpenShiftUserApiUtils openShiftUserApiUtils = mockery.mock(OpenShiftUserApiUtils.class);
    private static SharedOutputManager outputMgr = SharedOutputManager.getInstance().trace("com.ibm.ws.security.social.*=all");

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr.captureStreams();
    }

    @Before
    public void setUp() throws Exception {
        System.out.println("Entering test: " + testName.getMethodName());
    }

    @After
    public void tearDown() throws Exception {
        System.out.println("Exiting test: " + testName.getMethodName());
        outputMgr.resetStreams();
        mockery.assertIsSatisfied();
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        outputMgr.dumpStreams();
        outputMgr.restoreStreams();
    }

    @Test
    public void correctJSONTest() {
    	String correctString = "{\"kind\":\"TokenReview\",\"apiVersion\":\"authentication.k8s.io/v1\",\"metadata\":{\"creationTimestamp\":null},\"spec\":{\"token\":\"OR4SdSuy-8NRK8NEiYXxxDu01DZcT6jPj5RJ32CDA_c\"},\"status\":{\"authenticated\":true,\"user\":{\"username\":\"admin\",\"uid\":\"ef111c43-d33a-11e9-b239-0016ac102af6\",\"groups\":[\"arunagroup\",\"system:authenticated:oauth\",\"system:authenticated\"],\"extra\":{\"scopes.authorization.openshift.io\":[\"user:full\"]}}}}";
    	try {
//           mockery.checking(new Expectations() {
//                {
//                    allowing(openShiftUserApiUtils).modifyExistingResponseToJSON();
//                    will(returnValue(httpClient));
//                    one(httpClient).execute(httpUriRequest);
//                    will(throwException(new IOException(defaultExceptionMsg)));
//                }
//            });
			String returnedString = openShiftUserApiUtils.modifyExistingResponseToJSON(correctString);
			System.out.println(returnedString);
			assertEquals(returnedString,"{\"username\":\"admin\",\"groups\":[\"arunagroup\",\"system:authenticated:oauth\",\"system:authenticated\"]}");
		} catch (Throwable t) {
			outputMgr.failWithThrowable(testName.getMethodName(), t);
		}
    }
    @Test
    public void nullJSONTest() {
    	try {
    	openShiftUserApiUtils.modifyExistingResponseToJSON(null);
    	fail();
			
		} 
    	catch (SocialLoginException e) {
    		//nls 
    		
			verifyException(e,"The response received from the user response api is null" );
			
		}
    	catch( Throwable t) {
    		outputMgr.failWithThrowable(testName.getMethodName(), t);
    	}
    }
    
    @Test
    public void emptyJSONTest() {
    	try {
    	openShiftUserApiUtils.modifyExistingResponseToJSON("");
		fail();	
		} 
    	catch (SocialLoginException e) {
    		//nls 
			verifyException(e,"The response received from the user response api is empty" );
			
		}
    	catch( Throwable t) {
    		outputMgr.failWithThrowable(testName.getMethodName(), t);
    	}
    }

}

