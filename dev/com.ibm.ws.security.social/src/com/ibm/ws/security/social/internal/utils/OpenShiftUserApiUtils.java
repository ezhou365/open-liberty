/*******************************************************************************
 * Copyright (c) 2019 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.social.internal.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.json.JsonValue.ValueType;
import javax.json.stream.JsonParsingException;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.HttpServletResponse;

//import org.jose4j.json.internal.json_simple.parser.JSONParser;
import org.jose4j.json.internal.json_simple.parser.ParseException;

import org.jose4j.lang.JoseException;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.security.common.http.HttpUtils;

import com.ibm.ws.security.social.error.SocialLoginException;

import com.ibm.ws.security.social.TraceConstants;
import com.ibm.ws.security.social.internal.Oauth2LoginConfigImpl;


public class OpenShiftUserApiUtils {

    public static final TraceComponent tc = Tr.register(OpenShiftUserApiUtils.class, TraceConstants.TRACE_GROUP, TraceConstants.MESSAGE_BUNDLE);

    Oauth2LoginConfigImpl config = null;

    HttpUtils httpUtils = new HttpUtils();

    public OpenShiftUserApiUtils(Oauth2LoginConfigImpl config) {
        this.config = config;
    }

    public String getUserApiResponse(@Sensitive String accessToken, SSLSocketFactory sslSocketFactory) throws SocialLoginException {
        String response = null;
        try {
            HttpURLConnection connection = sendUserApiRequest(accessToken, sslSocketFactory);
            response = readUserApiResponse(connection);
        } catch (Exception e) {
            throw new SocialLoginException("OPENSHIFT_ERROR_GETTING_USER_INFO", e, new Object[] { e });
        }
        return response;
    }

    HttpURLConnection sendUserApiRequest(@Sensitive String accessToken, SSLSocketFactory sslSocketFactory) throws IOException, SocialLoginException {
        HttpURLConnection connection = httpUtils.createConnection(HttpUtils.RequestMethod.POST, config.getUserApi(), sslSocketFactory);
        connection = httpUtils.setHeaders(connection, getUserApiRequestHeaders());
        connection.setDoOutput(true);

        OutputStream outputStream = connection.getOutputStream();
        OutputStreamWriter streamWriter = new OutputStreamWriter(outputStream, "UTF-8");

        String bodyString = createUserApiRequestBody(accessToken);
        streamWriter.write(bodyString);
        streamWriter.close();
        outputStream.close();
        connection.connect();
        return connection;
    }

    @Sensitive
    Map<String, String> getUserApiRequestHeaders() {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Authorization", "Bearer " + config.getServiceAccountTokenForK8sTokenreview());
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        return headers;
    }

    String createUserApiRequestBody(@Sensitive String accessToken) throws SocialLoginException {
        if (accessToken == null) {
            throw new SocialLoginException("OPENSHIFT_ACCESS_TOKEN_MISSING", null, null);
        }
        JsonObjectBuilder bodyBuilder = Json.createObjectBuilder();
        bodyBuilder.add("kind", "TokenReview");
        bodyBuilder.add("apiVersion", "authentication.k8s.io/v1");
        bodyBuilder.add("spec", Json.createObjectBuilder().add("token", accessToken));
        return bodyBuilder.build().toString();
    }

    String readUserApiResponse(HttpURLConnection connection) throws IOException, SocialLoginException, JoseException, ParseException {
        int responseCode = connection.getResponseCode();
        String response = httpUtils.readConnectionResponse(connection);
        if (responseCode != HttpServletResponse.SC_CREATED) {
            throw new SocialLoginException("OPENSHIFT_USER_API_BAD_STATUS", null, new Object[] { responseCode, response });
        }
        return modifyExistingResponseToJSON(response);
    }

    String modifyExistingResponseToJSON(String response) throws JoseException, SocialLoginException, ParseException{
    	
    	if(response==null) {
    		throw new SocialLoginException("The response received from the user response api is null",null,null);
    	}
    	if(response.isEmpty()) {
    		throw new SocialLoginException("The response received from the user response api is empty",null,null);
    	}
    	JsonObject jsonResponse;
    	try {
    		jsonResponse = Json.createReader(new StringReader(response)).readObject();
    	}
    	catch(JsonParsingException e) {
    		throw new SocialLoginException("The response was not a json object. Response was: " + response,e,null);
    	}
    	
    	
    	JsonObject statusInnerMap,userInnerMap;
    	JsonObjectBuilder modifiedResponse = Json.createObjectBuilder();
    	if(jsonResponse.containsKey("status")) {
    	//System.out.println(jsonResponse.get("status"));
            JsonValue statusValue = jsonResponse.get("status");
            if (ValueType.STRING == statusValue.getValueType()) {
        		if(jsonResponse.getString("status").equals("Failure")) {
        	        
        			throw new SocialLoginException(jsonResponse.getString("message"),null,null);
        		
        		}
            }
    		statusInnerMap = jsonResponse.getJsonObject("status");
    		

    				
    	}
    	else {
    		throw new SocialLoginException("Expected to find a key status in the map but did not find it",null,null);
    	}
    	if(statusInnerMap.containsKey("user")) {
    		userInnerMap = statusInnerMap.getJsonObject("user");
    		modifiedResponse.add("username", userInnerMap.getString(config.getUserNameAttribute()));
    	}
    	else {
        	throw new SocialLoginException("Expected to find a key [0] in the map but did not find it",null,null); 
    	}
    	if(userInnerMap.containsKey("groups")) {
    		JsonValue groupsValue = userInnerMap.get("groups");
    		if(groupsValue.getValueType() != ValueType.ARRAY) {
    			throw new SocialLoginException("Groups is not jsonarray",null,null); 
    		}
    		 modifiedResponse.add("groups", userInnerMap.getJsonArray("groups")); 
        	
    	}
     
        return modifiedResponse.build().toString();

    }



}
