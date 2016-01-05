package com.oz.gateway.test;

import com.oz.gateway.GatewayApplication;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.boot.test.WebIntegrationTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.test.BeforeOAuth2Context;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.test.RestTemplateHolder;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.RestOperations;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
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

    @Autowired
    private DataSource dataSource;

    private final String clientWithSecret = "oz-client-with-secret";
    private final String secret = "oursecret";

    private final String svcAcct = "svcAcct";
    private final String password = "Welcome99";
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @BeforeOAuth2Context
    public void setupTestData() throws Exception
    {//TODO: Use spring objects to recreate data
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
            setupUser(conn, svcAcct, "ADMIN");

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
        final JdbcClientDetailsServiceBuilder clientBuilder =
                new JdbcClientDetailsServiceBuilder()
                        .dataSource(dataSource)
                        .passwordEncoder(passwordEncoder)
                ;

        clientBuilder
                .withClient(clientWithSecret)
                .authorizedGrantTypes("password")
                .authorities("ROLE_CLIENT")
                .scopes("read")
                .resourceIds("sunapee")
                .secret(secret)
        ;

        clientBuilder.build();
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
    @OAuth2ContextConfiguration(ResourceOwner.class)
    public void testRoutingToSunapee() throws Exception {
        assertApiAccess();
    }

    static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
        public ResourceOwner(final Object target) {
            final GatewayClientTest test = (GatewayClientTest) target;
            setAccessTokenUri(test.host + "/oauth/token");

            setClientId(test.clientWithSecret);
            setId(getClientId());
            setClientSecret(test.secret);

            setUsername(test.svcAcct);
            setPassword(test.password);

            setScope(Arrays.asList("read"));
        }
    }
}

