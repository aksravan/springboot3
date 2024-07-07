package com.example.TEST.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;

@Configuration
@EnableWebSecurity
public class WebConfig {

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Bean
    public AuthSuccessHandler authSuccessHandler() {
        return new AuthSuccessHandler();
    }

    @Bean
    public AuthFailureHandler authFailureHandler() {
        return new AuthFailureHandler();
    }

    @Autowired
    private AuthProvider authProvider;

    // @Bean
    // public AuthProvider authProvider() {
    // return new AuthProvider();
    // }

    // @Bean
    // public AuthenticationManager authenticationManagerBean(HttpSecurity http)
    // throws Exception {
    // AuthenticationManagerBuilder authenticationManagerBuilder = http
    // .getSharedObject(AuthenticationManagerBuilder.class);
    // authenticationManagerBuilder.jdbcAuthentication()
    // .rolePrefix("ROLE_")
    // .dataSource(dataSource)
    // .usersByUsernameQuery("select username,password,enabled from users where
    // username = ?")
    // .passwordEncoder(passwordEncoder());
    // System.out.println("auth manager");
    // return authenticationManagerBuilder.build();
    // }

    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authProvider);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        DelegatingPasswordEncoder delPasswordEncoder = (DelegatingPasswordEncoder) PasswordEncoderFactories
                .createDelegatingPasswordEncoder();
        BCryptPasswordEncoder bcryptPasswordEncoder = new BCryptPasswordEncoder();
        delPasswordEncoder.setDefaultPasswordEncoderForMatches(bcryptPasswordEncoder);
        return delPasswordEncoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.addFilterBefore(new SessionCookieFilter(), UsernamePasswordAuthenticationFilter.class);
        http.authorizeHttpRequests(requests -> requests
                .requestMatchers("/login", "/register")
                .permitAll()
                .anyRequest().authenticated())
                .formLogin(login -> login.loginPage("/login").permitAll()
                        .successHandler(this.authSuccessHandler())
                        .failureHandler(this.authFailureHandler())
                        .failureUrl("/login?error=Not Found"))
                .logout(logout -> logout.clearAuthentication(true).invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessUrl("/login"))
                .exceptionHandling(handling -> handling.accessDeniedPage("/login?error=Access Denied"))
                .headers(headers -> headers.frameOptions(options -> options.sameOrigin().disable())
                        .contentSecurityPolicy(policy -> policy.policyDirectives("form-action 'self'"))
                        .referrerPolicy(refer -> refer.policy(ReferrerPolicy.SAME_ORIGIN)))
                .sessionManagement(management -> management.maximumSessions(3).maxSessionsPreventsLogin(false)
                        .expiredUrl("/login?invalid-session=true"));
        return http.build();
    }

}