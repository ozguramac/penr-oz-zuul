package com.oz.gateway.test;

import com.oz.gateway.GatewayApplication;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
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

    private void assertUserApiAccess() {
        //TODO: Try out zuul routing
        final ResponseEntity<String> re = getRestTemplate().getForEntity(host + "/sunapee-mock/user-api", String.class);
        Assert.assertTrue(re.getStatusCode().is2xxSuccessful());
        log.info(re.getBody());
    }

    static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
        public ResourceOwner(final Object target) {
            final GatewayClientTest act = (GatewayClientTest) target;
            setAccessTokenUri(act.host + "/oauth/token");
            setClientId("oz");
            setClientSecret("oursecret");
            setUsername("svcAcct");
            setPassword("Welcome99");
        }
    }

    @Test
    @OAuth2ContextConfiguration(ResourceOwner.class)
    public void testWithResourceOwner() throws Exception {
        assertUserApiAccess();
    }

    static class ClientCredentials extends ClientCredentialsResourceDetails {
        public ClientCredentials(final Object target) {
            final GatewayClientTest act = (GatewayClientTest) target;
            setAccessTokenUri(act.host + "/oauth/token");
            setClientId("oz");
            setClientSecret("oursecret");
        }
    }

    @Test
    @OAuth2ContextConfiguration(ClientCredentials.class)
    public void testWithClientCredentials() throws Exception {
        final OAuth2AccessToken accessToken = context.getAccessToken();
        Assert.assertNotNull(accessToken);
        Assert.assertNull(accessToken.getRefreshToken());
    }

    static class ImplicitResource extends ImplicitResourceDetails {
        public ImplicitResource(final Object target) {
            final GatewayClientTest act = (GatewayClientTest) target;
            setAccessTokenUri(act.host + "/oauth/authorize");
            setUserAuthorizationUri(act.host + "/oauth/authorize");
            setClientId("oz");
            //setClientSecret("oursecret");
            setPreEstablishedRedirectUri(act.host);
        }
    }

    @Test
    @OAuth2ContextConfiguration(ImplicitResource.class)
    public void testWithImplicitResource() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization"
                , "Basic " + new String(Base64.encode("svcAcct:Welcome99".getBytes())));
        context.getAccessTokenRequest().setHeaders(headers);
        context.getAccessTokenRequest().add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");
        final OAuth2AccessToken accessToken = context.getAccessToken();
        Assert.assertNotNull(accessToken);
    }
}

