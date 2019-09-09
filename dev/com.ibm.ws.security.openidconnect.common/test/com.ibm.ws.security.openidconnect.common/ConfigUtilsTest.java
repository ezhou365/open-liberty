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
package com.ibm.ws.security.openidconnect.common;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

import test.common.SharedOutputManager;

import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;

@SuppressWarnings("unchecked")
public class ConfigUtilsTest {
    static SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    @Rule
    public TestRule managerRule = outputMgr;

    private final Mockery mock = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };
    static final String KEY_ID = "id";

    static final String KEY_CONFIGURATION_ADMIN = "configurationAdmin";
    static final String CFG_KEY_ELEMENT_PID = "elementRef";;

    final AtomicServiceReference<ConfigurationAdmin> configAdminRef = mock.mock(AtomicServiceReference.class, "configAdminRef");
    protected final ConfigurationAdmin configAdmin = mock.mock(ConfigurationAdmin.class);
    protected final org.osgi.service.cm.Configuration config = mock.mock(org.osgi.service.cm.Configuration.class);

    @After
    public void tearDown() {
        mock.assertIsSatisfied();
        outputMgr.resetStreams();
    }

    @Test
    public void contructorWithNull() throws Exception {
        final Map<String, Object> noProps = new Hashtable<String, Object>();
        ConfigUtils configUtils = new ConfigUtils(null);
        Properties properties = configUtils.processProps(noProps, CFG_KEY_ELEMENT_PID);
        assertNotNull("properties should not be null", properties);
    }

    @Test
    public void testProcessProps() throws Exception {
        final Dictionary<String, String> properties = new Hashtable<String, String>();
        properties.put(KEY_ID, KEY_ID);
        properties.put("service.id", "123");
        properties.put("config.id", "123");
        properties.put(".others", "123");
        properties.put("prop1", "value1");
        properties.put("prop2", "value2");
        mock.checking(new Expectations() {
            {
                allowing(configAdminRef).getReference();
                one(configAdminRef).getServiceWithException();
                will(returnValue(configAdmin));
                one(configAdmin).listConfigurations("(service.pid=elementRef)");
                will(returnValue(new Configuration[] { config }));
                one(configAdmin).getConfiguration("elementRef", "");
                will(returnValue(config));

                one(config).getProperties();
                will(returnValue(properties));
            }
        });

        ConfigUtils configUtils = new ConfigUtils(configAdminRef);
        final Map<String, Object> props = createProps();
        Properties returnProps = configUtils.processProps(props, CFG_KEY_ELEMENT_PID);
        assertEquals("Should have two properties", 2, returnProps.size());
        assertEquals("value1", returnProps.getProperty("prop1"));
        assertEquals("value2", returnProps.getProperty("prop2"));
    }

    @Test
    public void testProcessFlatProps() throws Exception {
        final Map<String, Object> props = new HashMap<String, Object>();
        props.put(ConfigUtils.CFG_KEY_CLAIM_TO_UR_MAP + ".0.prop1", "value1");
        props.put(ConfigUtils.CFG_KEY_CLAIM_TO_UR_MAP + ".0.prop2", "value2");
        ConfigUtils configUtils = new ConfigUtils(null);
        Properties returnProps = configUtils.processFlatProps(props, ConfigUtils.CFG_KEY_CLAIM_TO_UR_MAP);
        assertEquals("Should have 8 properties", 8, returnProps.size());
        assertEquals("value1", returnProps.getProperty("prop1"));
        assertEquals("value2", returnProps.getProperty("prop2"));
    }

    @Test
    public void testProcessDiscoveryProps() throws Exception {
        ConfigUtils configUtils = new ConfigUtils(configAdminRef);
        final Map<String, Object> props = createDiscoveryProps();
        Properties returnProps = configUtils.processDiscoveryProps(props, ConfigUtils.CFG_KEY_DISCOVERY);
        assertEquals("Should have fourteen properties", 14, returnProps.size());
        assertArrayEquals(new String[] { "code", "token", "id_token token" }, (String[]) returnProps.get("responseTypesSupported"));
        assertArrayEquals(new String[] { "public" }, (String[]) returnProps.get("subjectTypesSupported"));
        assertArrayEquals(new String[] { "openid", "general", "profile", "email", "address", "phone" }, (String[]) returnProps.get("scopesSupported"));
        assertArrayEquals(new String[] { "authorization_code", "implicit", "refresh_token", "client_credentials", "password", "urn:ietf:params:oauth:grant-type:jwt-bearer" }, (String[]) returnProps.get("grantTypesSupported"));
    }

    private Map<String, Object> createDiscoveryProps() {
        final Map<String, Object> discoveryProps = new Hashtable<String, Object>();
        discoveryProps.put(ConfigUtils.CFG_KEY_DISCOVERY, "");
        return discoveryProps;
    }

    /**
     */
    private Map<String, Object> createProps() {
        final Map<String, Object> props = new Hashtable<String, Object>();
        props.put(KEY_ID, KEY_ID);
        props.put(CFG_KEY_ELEMENT_PID, CFG_KEY_ELEMENT_PID);
        props.put("prop1", "value1");
        props.put("prop2", "value2");
        return props;
    }
}
