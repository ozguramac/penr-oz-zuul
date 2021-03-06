package com.oz.oauth.test;

import com.oz.oauth.OauthSvcApplication;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
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
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * Created by Ozgur V. Amac on 12/4/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = OauthSvcApplication.class)
@WebIntegrationTest(randomPort = true)
public class OauthClientTest implements RestTemplateHolder {
    private static final Logger log = Logger.getLogger(OauthClientTest.class.getName());

    private RestOperations restOp = new TestRestTemplate();

    @Value("http://localhost:${local.server.port}")
    private String host;

    @Rule
    public OAuth2ContextSetup context = OAuth2ContextSetup.standard(this);

    @Autowired
    private DataSource dataSource;

    private final String clientWithSecret = "oz-client-with-secret";
    private final String trustedClient = "oz-trusted-client";
    private final String clientWithRedirect = "oz-client-with-registered-redirect";
    private final String secret = "oursecret";

    //private final String anyUser = "anyUser";
    //private final String trustedUser = "trustedUser";

    @Value("${security.user.name}")
    private String svcAcct;
    @Value("${security.user.password}")
    private String password;

    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @BeforeOAuth2Context
    public void setupTestData() throws Exception
    {//TODO: Use spring objects to recreate data
        Connection conn = null;
        try {
            conn = dataSource.getConnection();

            PreparedStatement stmt = null;

            //Remove client data (relies on delete cascade)
            for (final String clientId :
                    new String[] { clientWithSecret, trustedClient, clientWithRedirect})
            {
                try {
                    stmt = conn.prepareStatement("delete from oauth_client_details where client_id=?");
                    stmt.setString(1, clientId);
                    stmt.execute();
                } finally {
                    if (stmt != null) {
                        stmt.close();
                    }
                }
            }
        }
        finally {
            if (conn != null) {
                conn.close();
            }
        }

        //Recreate clients config
        final JdbcClientDetailsServiceBuilder clientBuilder =
                new JdbcClientDetailsServiceBuilder()
                .dataSource(dataSource)
                .passwordEncoder(passwordEncoder)
        ;

        clientBuilder
            .withClient(trustedClient)
                .authorizedGrantTypes(
                     "password"
                    ,"authorization_code"
                    ,"refresh_token"
                    ,"implicit"
                )
                .authorities(
                         "ROLE_CLIENT"
                        ,"ROLE_TRUSTED_CLIENT"
                )
                .scopes(
                         "read"
                        ,"write"
                        ,"trust"
                )
                .resourceIds("sunapee")
                .accessTokenValiditySeconds(60)
            .and()
            .withClient(clientWithRedirect)
                .authorizedGrantTypes("authorization_code")
                .authorities("ROLE_CLIENT")
                .scopes(
                         "read"
                        ,"trust"
                )
                .resourceIds("sunapee")
                .redirectUris("http://sunapee?key=value")
            .and()
            .withClient(clientWithSecret)
                .authorizedGrantTypes(
                         "client_credentials"
                        ,"password"
                )
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .resourceIds("sunapee")
                .secret(secret)
        ;

        clientBuilder.build();
    }

    @Override
    public void setRestTemplate(RestOperations restTemplate) {
        restOp = restTemplate;
    }

    @Override
    public RestOperations getRestTemplate() {
        return restOp;
    }

    private void assertApiAccess() {
        //TODO: Implement this
//        final ResponseEntity<String> re = getRestTemplate().getForEntity(host + "/sunapee-mock/user-api", String.class);
//        Assert.assertTrue(re.getStatusCode().is2xxSuccessful());
//        log.info(re.getBody());
    }

    @Test
    @OAuth2ContextConfiguration(ResourceOwner.class)
    public void testWithResourceOwner() throws Exception {
        assertApiAccess();
    }

    @Test
    @OAuth2ContextConfiguration(ClientCredentials.class)
    public void testWithClientCredentials() throws Exception {
        final OAuth2AccessToken accessToken = context.getAccessToken();
        Assert.assertNotNull(accessToken);
        Assert.assertNull(accessToken.getRefreshToken());

        assertApiAccess();
    }

    @Test
    @OAuth2ContextConfiguration(resource = ImplicitResource.class, initialize = false)
    public void testWithImplicitResource() throws Exception {
        setTokenAuthHeaders(svcAcct);

        try {
            Assert.assertNotNull(context.getAccessToken());
            Assert.fail("Expected user redirect error");
        }
        catch (UserRedirectRequiredException urre) {
            context.getAccessTokenRequest().add(OAuth2Utils.USER_OAUTH_APPROVAL, "true");
            context.getAccessTokenRequest().add("scope.read", "true");

            Assert.assertNotNull(context.getAccessToken());

            assertApiAccess();
        }
    }

    @Test
    @OAuth2ContextConfiguration(resource = AuthorizationCode.class, initialize = false)
    public void testWithAuthorizationCode() throws Exception {
        setTokenAuthHeaders(svcAcct);

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

                assertApiAccess();
            }
        }
    }

    private void setTokenAuthHeaders(final String username) {
        final HttpHeaders headers = new HttpHeaders();
        final String userPswd = username+":"+password;
        headers.set("Authorization"
                ,"Basic " + new String(Base64.encode(userPswd.getBytes())));
        context.getAccessTokenRequest().setHeaders(headers);
    }

    static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
        public ResourceOwner(final Object target) {
            final OauthClientTest test = (OauthClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");

            setClientId(test.clientWithSecret);
            setId(getClientId());
            setClientSecret(test.secret);

            setUsername(test.svcAcct);
            setPassword(test.password);

            setScope(Arrays.asList("read"));
        }
    }

    static class ClientCredentials extends ClientCredentialsResourceDetails {
        public ClientCredentials(final Object target) {
            final OauthClientTest test = (OauthClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");

            setClientId(test.clientWithSecret);
            setId(getClientId());
            setClientSecret(test.secret);

            setScope(Arrays.asList("read"));
        }
    }

    static class ImplicitResource extends ImplicitResourceDetails {
        public ImplicitResource(final Object target) {
            final OauthClientTest test = (OauthClientTest) target;
            setAccessTokenUri(test.host + "/oauth/authorize");
            setUserAuthorizationUri(test.host + "/oauth/authorize");

            setClientId(test.trustedClient);
            setId(getClientId());

            setScope(Arrays.asList("read"));

            setPreEstablishedRedirectUri("http://sunapee");
        }
    }

    static class AuthorizationCode extends AuthorizationCodeResourceDetails {
        public AuthorizationCode(final Object target) {
            final OauthClientTest test = (OauthClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");
            setUserAuthorizationUri(test.host + "/oauth/authorize");

            setClientId(test.clientWithRedirect);
            setId(getClientId());

            setScope(Arrays.asList("read"));

            setPreEstablishedRedirectUri("http://sunapee?key=value");
        }
    }
}

