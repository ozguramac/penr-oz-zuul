package com.oz.gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.*;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.WebUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;

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

//    @Configuration
//    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
//    protected static class WebSecurity extends WebSecurityConfigurerAdapter
//    {
////        private final CsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();
////
////        private final Filter csrfHeaderFilter = new OncePerRequestFilter() {
////            @Override
////            protected void doFilterInternal(final HttpServletRequest request,
////                                            final HttpServletResponse response,
////                                            final FilterChain filterChain)
////                    throws ServletException, IOException
////            {
////                CsrfToken csrf = (CsrfToken) request.getAttribute( CsrfToken.class.getName() );
////                if (csrf != null) {
////                    final String name = "XSRF-TOKEN";
////                    Cookie cookie = WebUtils.getCookie(request, name);
////                    String token = csrf.getToken();
////                    if (cookie==null || token!=null && !token.equals(cookie.getValue())) {
////                        cookie = new Cookie(name, token);
////                        cookie.setPath("/");
////                        response.addCookie(cookie);
////                    }
////                }
////                filterChain.doFilter(request, response);
////            }
////        };
//
//        @Override
//        public void configure(final HttpSecurity http) throws Exception {
//            http
//                    .httpBasic() //TODO: Use more secure method to deliver credentials
//                    .and()
//                    .csrf()
//                        .disable()
//            //TODO: Enable CSRF protection
////                        .csrfTokenRepository(csrfTokenRepository)
////                    .and()
////                        .addFilterAfter(csrfHeaderFilter, CsrfFilter.class)
//            ;
//        }
//    }

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
