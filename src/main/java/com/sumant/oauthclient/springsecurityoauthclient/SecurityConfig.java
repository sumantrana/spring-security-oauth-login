package com.sumant.oauthclient.springsecurityoauthclient;

import org.springframework.boot.autoconfigure.task.TaskExecutionProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Spring Boot auto config creates 2 beans for OAuth
     * 1. SecurityFilterChain
     * 2. ClientRegistrationRepository ( from the properties file )
     * Both can be overridden if required.
     * @param http
     * @return
     * @throws Exception
     */

    @Bean
    public SecurityFilterChain filterChain (HttpSecurity http) throws Exception {

        http.authorizeHttpRequests( (authCustomizer) -> authCustomizer
                .requestMatchers(new AntPathRequestMatcher("/test/**")).hasAuthority("ROLE_sumant.test"))
                .csrf(AbstractHttpConfigurer::disable)
                //withDefaults() can be replaced by oauth2 -> oauth2.authorizationEndpoint() etc.
                .oauth2Login(oauth -> oauth
                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(this.customAuthorityMapper())));

        return http.build();

    }

    /**
     * Create a bean of type GrantedAuthoritesMapper to customize the authorities
     * returned from the Oauth Server.
     * @return
     */
    @Bean
    public GrantedAuthoritiesMapper customAuthorityMapper(){
        SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
        simpleAuthorityMapper.setDefaultAuthority("ROLE_sumant.test");
        return simpleAuthorityMapper;
    }

}
