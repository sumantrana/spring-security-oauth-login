package com.sumant.oauthclient.springsecurityoauthclient;

import org.hamcrest.core.StringContains;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.contains;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * @ExtendWith instructs the spring-test module that it should create an ApplicationContext.
 */
@ExtendWith(SpringExtension.class)
/**
 * @ContextConfiguration instructs the spring-test the configuration to use to create the
 * ApplicationContext. Since no configuration is specified, the default configuration
 * locations will be tried. This is no different than using the existing Spring Test support.
 */
@ContextConfiguration(classes = SecurityConfig.class)
@WebMvcTest
public class SecurityConfigTests {

    @Autowired
    FilterChainProxy springSecurityFilterChain;

    MockMvc mockMvc;

    @BeforeEach
    public void setup(){
        mockMvc = MockMvcBuilders
                .standaloneSetup(TestController.class)
                /**
                 * will perform all of the initial setup we need to integrate Spring Security
                 * with Spring MVC Test
                 */
                .apply(springSecurity(springSecurityFilterChain))
                .build();
    }

    @WithMockUser(authorities = "Rana")
    @Test
    public void sayHello_Returns200OK_ForAuthorityRana() throws Exception{
        this.mockMvc.perform(get("/test"))
                .andExpect(status().isOk());
    }

    @WithMockUser
    @Test
    public void sayHello_Returns403Forbidden_ForNonAuthorisedUsers() throws Exception{
        this.mockMvc.perform(get("/test"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void sayHello_Returns302Unauthorised_ForNonAuthenticatedUsers() throws Exception{
        this.mockMvc.perform(get("/test"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", StringContains.containsString("oauth2/authorization/google")));
    }
}
