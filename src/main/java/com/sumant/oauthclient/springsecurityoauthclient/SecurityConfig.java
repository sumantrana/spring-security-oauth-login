package com.sumant.oauthclient.springsecurityoauthclient;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

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
                        // The AuthorizationFilter runs not just on every request, but on every dispatch.
                        // This means that the REQUEST dispatch needs authorization, but also FORWARDs, ERRORs, and INCLUDEs
                        /**
                         * @Controller
                         * public class MyController {
                         *     @GetMapping("/endpoint")
                         *     public String endpoint() {
                         *         return "endpoint";
                         *     }
                         * }
                         * In this case, authorization happens twice; once for authorizing /endpoint and once for forwarding to Thymeleaf to render the "endpoint" template.
                         * For that reason, you may want to permit all FORWARD dispatches.
                         *
                         * Same for error. When an exception is raised from a controller method,
                         * boot dispatches it to ERROR dispatcher and authorization happens twice.
                         * For that reason, you may want to permit all ERROR dispatches
                         */
                        .dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
                        /**
                         * AuthorizationManager uses a Supplier<Authentication> which is extracted from SecurityContextHolder
                         * In case we use permitAll() or denyAll(), Authentication lookup is deferred making request processing faster.
                         */
                        .requestMatchers(new AntPathRequestMatcher("/test/**")).hasAuthority("VerifiedUser")
                        .anyRequest().authenticated())
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

        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities
                    if ( idToken.hasClaim("email_verified") && idToken.getClaim("email_verified").equals(Boolean.TRUE)){
                        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("VerifiedUser");
                        mappedAuthorities.add(grantedAuthority);
                    }

                } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;

                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                    // Map the attributes found in userAttributes
                    // to one or more GrantedAuthority's and add it to mappedAuthorities

                }
            });

            return mappedAuthorities;
        };

        /**
         * This becomes a testing problem because all default users will be appended with this
         * role. So a mock user will also be appended with the required role and pass the test.
         * @return
         */
//        SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
//        simpleAuthorityMapper.setDefaultAuthority("ROLE_sumant.test");
//        return simpleAuthorityMapper;

    }

}
