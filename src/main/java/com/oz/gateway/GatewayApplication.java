package com.oz.gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

/**
 * Created by Ozgur V. Amac on 12/1/15.
 */
@SpringBootApplication
@EnableResourceServer
@EnableGlobalMethodSecurity(securedEnabled = true)
@EnableZuulProxy
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .passwordEncoder(passwordEncoder)
        ;
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthServer extends AuthorizationServerConfigurerAdapter
    {
        @Autowired
        private AuthenticationManager authenticationManager;

        @Autowired
        private DataSource dataSource;

        @Autowired
        private PasswordEncoder passwordEncoder;

        @Bean
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        @Bean
        protected AuthorizationCodeServices authorizationCodeServices() {
            return new JdbcAuthorizationCodeServices(dataSource);
        }

        @Override
        public void configure(final AuthorizationServerSecurityConfigurer security) throws Exception {
            security
                    .passwordEncoder(passwordEncoder)
            ;
        }

        @Override
        public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .authorizationCodeServices(authorizationCodeServices())
                    .authenticationManager(authenticationManager)
                    .tokenStore(tokenStore())
                    .approvalStoreDisabled()
            ;
        }

        @Override
        public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
            clients.jdbc(dataSource)
                    .passwordEncoder(passwordEncoder)
            ;
        }
    }
}
