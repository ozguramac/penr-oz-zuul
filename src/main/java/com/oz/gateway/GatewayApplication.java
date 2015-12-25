package com.oz.gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

/**
 * Created by Ozgur V. Amac on 12/1/15.
 */
@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled = true)
@EnableResourceServer
@EnableZuulProxy
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("svcAcct")
                    .password("Welcome99")
                    .roles("ADMIN")
        ;
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter
    {
        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception
        {
            endpoints.authenticationManager(authenticationManager);
        }

        @Override
        public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient("oz-trusted-client")
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
                    .withClient("oz-client-with-registered-redirect")
                        .authorizedGrantTypes("authorization_code")
                        .authorities("ROLE_CLIENT")
                        .scopes(
                                 "read"
                                ,"trust"
                        )
                        .resourceIds("sunapee")
                        .redirectUris("http://sunapee?key=value")
                    .and()
                    .withClient("oz-client-with-secret")
                        .authorizedGrantTypes(
                                 "client_credentials"
                                ,"password"
                        )
                        .authorities("ROLE_CLIENT")
                        .scopes("read")
                        .resourceIds("sunapee")
                        .secret("oursecret")
            ;
        }
    }
}
