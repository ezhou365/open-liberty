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
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.http.HttpServletResponse;

//import org.jose4j.json.internal.json_simple.parser.JSONParser;
import org.jose4j.json.internal.json_simple.parser.ParseException;

import org.jose4j.lang.JoseException;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.security.common.http.HttpUtils;
import com.ibm.ws.security.common.jwk.utils.JsonUtils;

import com.ibm.ws.security.social.error.SocialLoginException;

import com.ibm.ws.security.social.TraceConstants;
import com.ibm.ws.security.social.error.SocialLoginException;
import com.ibm.ws.security.social.internal.Oauth2LoginConfigImpl;


public class OpenShiftUserApiUtils {

    public static final TraceComponent tc = Tr.register(OpenShiftUserApiUtils.class, TraceConstants.TRACE_GROUP, TraceConstants.MESSAGE_BUNDLE);

    Oauth2LoginConfigImpl config = null;

    HttpUtils httpUtils = new HttpUtils();

    public OpenShiftUserApiUtils(Oauth2LoginConfigImpl config) {
        this.config = config;
    }
    
    public String getUserApiResponse(@Sensitive String accessToken, SSLSocketFactory sslSocketFactory) throws JoseException, IOException, SocialLoginException, ParseException{

        String response = null;
        try {
            HttpURLConnection connection = sendUserApiRequest(accessToken, sslSocketFactory);
            response = readUserApiResponse(connection);
        } catch (ParseException e) {
        	//do something
        }
        catch (Exception e) {
            throw new SocialLoginException("OPENSHIFT_ERROR_GETTING_USER_INFO", e, new Object[] { e });
        } 
        return response;
       // return response;
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

    String modifyExistingResponseToJSON(String response) throws JoseException, SocialLoginException, ParseException{
    	
    	if(response==null) {
    		throw new SocialLoginException("The response received from the user response api is null",null,null);
    	}
    	if(response.isEmpty()) {
    		throw new SocialLoginException("The response received from the user response api is empty",null,null);
    	}
        //String jsonFormatResponse = JsonUtils.toJson(response);
        Map<?, ?> firstMap = JsonUtils.claimsFromJsonObject(response);
        
        Map<?, ?> statusInnerMap = (LinkedHashMap<?, ?>)firstMap.get("status");
        
        if(statusInnerMap==null) {
        	throw new SocialLoginException("Expected to find a key [0] in the map but did not find it",null,null);
        }
        Map<?, ?> userInnerMap = (LinkedHashMap<?, ?>)statusInnerMap.get("user");
        
        if(userInnerMap==null) {
        	throw new SocialLoginException("Expected to find a key [0] in the map but did not find it",null,null); 
        }
        List<?> groupList;
        if(userInnerMap.get("groups") instanceof List  ) {
        	groupList = (ArrayList<?>) userInnerMap.get("groups");
        }

        else {
        	throw new SocialLoginException("The value associated with groups should be a list but it a [1]",null,null); 
        }
        if(userInnerMap.get("username")==null) {
        	throw new SocialLoginException("The value associated with username is null",null,null);
        }
        if(((String)userInnerMap.get("username") +"").isEmpty()) {
        	throw new SocialLoginException("The value associated with username is empty",null,null);
        }
        
        JsonObjectBuilder modifiedResponse = Json.createObjectBuilder();
        String current = (String)userInnerMap.get("username") ;
      
        modifiedResponse.add("username", current);

        JsonArrayBuilder groups = Json.createArrayBuilder();
        for (int i = 0; i < groupList.size(); i++) {
            groups.add((String) groupList.get(i));
        }
        modifiedResponse.add("groups", groups.build());
       
        return modifiedResponse.build().toString();
    }



    String readUserApiResponse(HttpURLConnection connection) throws IOException, SocialLoginException, JoseException, ParseException {
        int responseCode = connection.getResponseCode();
        String response = httpUtils.readConnectionResponse(connection);
        if (responseCode != HttpServletResponse.SC_CREATED) {
            throw new SocialLoginException("OPENSHIFT_USER_API_BAD_STATUS", null, new Object[] { responseCode, response });
        }
        return modifyExistingResponseToJSON(response);
    }



}
