package com.oz.gateway.test;

import com.oz.gateway.AuthServerApplication;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import java.security.Principal;

/**
 * Created by Ozgur V. Amac on 12/4/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = AuthServerApplication.class)
@WebIntegrationTest(randomPort = true)
@OAuth2ContextConfiguration(ClientTestDetails.class)
public class AuthClientTest implements RestTemplateHolder {
    private RestOperations restOp = new TestRestTemplate();

    @Value("http://localhost:${local.server.port}")
    private String host;

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.standard(this);

    @Override
    public void setRestTemplate(RestOperations restTemplate) {
        restOp = restTemplate;
    }

    @Override
    public RestOperations getRestTemplate() {
        return restOp;
    }

    public String getHost() {
        return host;
    }

    @Test
    public void testUserOAuth2() {
        final ResponseEntity<?> re = getRestTemplate().getForEntity(host + "/user", String.class);
        Assert.assertTrue(re.getStatusCode().is2xxSuccessful());
        System.out.println(re.getBody());
    }
}

class ClientTestDetails extends ResourceOwnerPasswordResourceDetails {
    public ClientTestDetails(final Object obj) {
        final AuthClientTest act = (AuthClientTest) obj;
        setAccessTokenUri(act.getHost() + "/oauth/token");
        setClientId("oz");
        setClientSecret("oursecret");
        setUsername("user");
        setPassword("Welcome99");
    }
}