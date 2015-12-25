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
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import java.util.Arrays;
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

    @Test
    @OAuth2ContextConfiguration(ResourceOwner.class)
    public void testWithResourceOwner() throws Exception {
        assertUserApiAccess();
    }

    @Test
    @OAuth2ContextConfiguration(ClientCredentials.class)
    public void testWithClientCredentials() throws Exception {
        final OAuth2AccessToken accessToken = context.getAccessToken();
        Assert.assertNotNull(accessToken);
        Assert.assertNull(accessToken.getRefreshToken());

        assertUserApiAccess();
    }

    @Test
    @OAuth2ContextConfiguration(resource = ImplicitResource.class, initialize = false)
    public void testWithImplicitResource() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization"
                ,"Basic " + new String(Base64.encode("svcAcct:Welcome99".getBytes())));
        context.getAccessTokenRequest().setHeaders(headers);

        try {
            Assert.assertNotNull(context.getAccessToken());
            Assert.fail("Expected user redirect error");
        }
        catch (UserRedirectRequiredException e) {
            context.getAccessTokenRequest().add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");
            context.getAccessTokenRequest().add("scope.read", "true");

            Assert.assertNotNull(context.getAccessToken());

            assertUserApiAccess();
        }
    }

    @Test
    @OAuth2ContextConfiguration(resource = AuthorizationCode.class, initialize = false)
    public void testWithAuthorizationCode() throws Exception {
        final HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization"
                ,"Basic " + new String(Base64.encode("svcAcct:Welcome99".getBytes())));
        context.getAccessTokenRequest().setHeaders(headers);

        try {
            Assert.assertNotNull(context.getAccessToken());
            Assert.fail("Expected user redirect error to obtain access token");
        }
        catch (UserRedirectRequiredException urre)
        {
            Assert.assertTrue(urre.getRedirectUri().startsWith(
                    ((AbstractRedirectResourceDetails)context.getResource()).getUserAuthorizationUri()));
            Assert.assertNull(context.getAccessTokenRequest().getAuthorizationCode());

            try {
                Assert.assertNotNull(context.getAccessToken());
                Assert.fail("Expected user redirect error for user approval");
            }
            catch (UserApprovalRequiredException uare)
            {
                Assert.assertTrue(uare.getApprovalUri().startsWith(
                        ((AbstractRedirectResourceDetails)context.getResource()).getUserAuthorizationUri()));
                Assert.assertNull(context.getAccessTokenRequest().getAuthorizationCode());

                context.getAccessTokenRequest().add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");

                Assert.assertNotNull(context.getAccessToken());
                Assert.assertNotNull(context.getAccessTokenRequest().getAuthorizationCode());

                assertUserApiAccess();
            }
        }
    }

    static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
        public ResourceOwner(final Object target) {
            final GatewayClientTest test = (GatewayClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");

            setClientId("oz-client-with-secret");
            setId(getClientId());
            setClientSecret("oursecret");

            setUsername("svcAcct");
            setPassword("Welcome99");

            setScope(Arrays.asList("read"));
        }
    }

    static class ClientCredentials extends ClientCredentialsResourceDetails {
        public ClientCredentials(final Object target) {
            final GatewayClientTest test = (GatewayClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");

            setClientId("oz-client-with-secret");
            setId(getClientId());
            setClientSecret("oursecret");

            setScope(Arrays.asList("read"));
        }
    }

    static class ImplicitResource extends ImplicitResourceDetails {
        public ImplicitResource(final Object target) {
            final GatewayClientTest test = (GatewayClientTest) target;
            setAccessTokenUri(test.host + "/oauth/authorize");
            setUserAuthorizationUri(test.host + "/oauth/authorize");

            setClientId("oz-trusted-client");
            setId(getClientId());

            setPreEstablishedRedirectUri("http://sunapee");
        }
    }

    static class AuthorizationCode extends AuthorizationCodeResourceDetails {
        public AuthorizationCode(final Object target) {
            final GatewayClientTest test = (GatewayClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");
            setUserAuthorizationUri(test.host + "/oauth/authorize");

            setClientId("oz-client-with-registered-redirect");
            setId(getClientId());

            setScope(Arrays.asList("read"));

            setPreEstablishedRedirectUri("http://sunapee?key=value");
        }
    }
}

