package com.oz.gateway.test;

import com.oz.gateway.GatewayApplication;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import static org.mockito.Mockito.when;

/**
 * Created by Ozgur V. Amac on 12/4/15.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = GatewayApplication.class)
@WebIntegrationTest(randomPort = true)
public class GatewayClientTest {
    private static final Logger log = Logger.getLogger(GatewayClientTest.class.getName());

    private OAuth2RestTemplate restOp;

    @Value("http://localhost:${local.server.port}")
    private String host;

    @Autowired
    private DataSource dataSource;

    private final String clientWithSecret = "oz-client-with-secret";
    private final String secret = "oursecret";

    private final String svcAcct = "svcAcct";
    private final String password = "Welcome99";
    private final String[] roles = { "ADMIN" };
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private OAuth2AccessToken token;

    @Mock
    private OAuth2ProtectedResourceDetails resource;

    @Before
    public void setup() throws Exception
    {
        MockitoAnnotations.initMocks(this);

        //TODO: Use spring objects to recreate data
        Connection conn = null;
        try {
            conn = dataSource.getConnection();

            PreparedStatement stmt = null;

            for (final String username :
                    new String[] { svcAcct }) {
                //Remove user data (relies on delete cascade)
                try {
                    stmt = conn.prepareStatement("delete from users where username=?");
                    stmt.setString(1, username);
                    stmt.execute();
                } finally {
                    if (stmt != null) {
                        stmt.close();
                    }
                }
            }

            //Recreate user data
            setupUser(conn, svcAcct, roles);

            //Remove client data (relies on delete cascade)
            for (final String clientId :
                    new String[] { clientWithSecret })
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
        final JdbcClientDetailsServiceBuilder clientDetailsServiceBuilder=
                new JdbcClientDetailsServiceBuilder()
                        .dataSource(dataSource)
                        .passwordEncoder(passwordEncoder)
                ;

        clientDetailsServiceBuilder
                .withClient(clientWithSecret)
                .authorizedGrantTypes("password")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .resourceIds("sunapee")
                .secret(secret)
        ;

        final ClientDetailsService clientDetailsService = clientDetailsServiceBuilder.build();

        //Add prepared access token for testing
        final Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        final Authentication userAuthentication =
                new UsernamePasswordAuthenticationToken(svcAcct, password, authorities);

        final ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientWithSecret);

        final Map<String, String> params = new HashMap<String, String>();
        params.put(OAuth2Utils.GRANT_TYPE, "password");

        final OAuth2RequestFactory oauth2RequestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
        final TokenRequest tokenRequest = oauth2RequestFactory.createTokenRequest(params, clientDetails);
        final OAuth2Request oAuth2Request = oauth2RequestFactory.createOAuth2Request(clientDetails, tokenRequest);

        final OAuth2Authentication authentication = new OAuth2Authentication(oAuth2Request, userAuthentication);

        token = new DefaultOAuth2AccessToken("TESTING_TOKEN");

        final JdbcTokenStore tokenStore = new JdbcTokenStore(dataSource);
        tokenStore.storeAccessToken(token, authentication);

        when(resource.getTokenName()).thenReturn(OAuth2AccessToken.ACCESS_TOKEN);
        when(resource.getAuthenticationScheme()).thenReturn(AuthenticationScheme.form);

        restOp = new OAuth2RestTemplate(resource);
    }

    private void setupUser(final Connection conn, final String username, final String... roles)
            throws SQLException
    {
        PreparedStatement stmt = null;

        //Create new one
        try {
            stmt = conn.prepareStatement("insert into users values(?,?,1)");
            stmt.setString(1, username);
            stmt.setString(2, passwordEncoder.encode(password));
            stmt.execute();
        } finally {
            stmt.close();
        }

        for (String role : roles) {
            try {
                stmt = conn.prepareStatement("insert into authorities values(?,?)");
                stmt.setString(1, username);
                stmt.setString(2, "ROLE_"+role);
                stmt.execute();
            } finally {
                stmt.close();
            }
        }
    }

    private void assertApiAccess(final String url) {
        final ResponseEntity<String> re = restOp.getForEntity(url, String.class);
        Assert.assertTrue(re.getStatusCode().is2xxSuccessful());
        log.info(re.getBody());

    }

    @Test
    public void testAuthenticated() throws Exception {
        restOp.getOAuth2ClientContext().setAccessToken(token);
        assertApiAccess(host + "/users");
    }
}

