package com.oz.gateway.test;

import com.oz.gateway.GatewayApplication;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import java.util.logging.Logger;

/**
 * Created by Ozgur V. Amac on 12/4/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = GatewayApplication.class)
@WebIntegrationTest(randomPort = true)
public class GatewayClientTest implements RestTemplateHolder {
    private static final Logger log = Logger.getLogger(GatewayClientTest.class.getName());

    private RestOperations restOp = new TestRestTemplate();

    @Value("http://localhost:${local.server.port}")
    private String host;

//    @Autowired
//    private DataSource dataSource;
//
//    private final String clientWithSecret = "oz-client-with-secret";
//    private final String trustedClient = "oz-trusted-client";
//    private final String clientWithRedirect = "oz-client-with-registered-redirect";
//    private final String secret = "oursecret";
//
//    private final String anyUser = "anyUser";
//    private final String trustedUser = "trustedUser";
//    private final String svcAcct = "svcAcct";
//    private final String password = "Welcome99";
//    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @Override
    public void setRestTemplate(RestOperations restTemplate) {
        restOp = restTemplate;
    }

    @Override
    public RestOperations getRestTemplate() {
        return restOp;
    }

    private void assertApiAccess() {
        //TODO: Try out zuul routing
    }

    @Test
    public void testRoutingToSunapee() throws Exception {
        assertApiAccess();
    }
}

