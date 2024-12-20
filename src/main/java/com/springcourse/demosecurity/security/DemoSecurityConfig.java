package com.springcourse.demosecurity.security;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig {
        // add support for jdbc authentication
        @Bean
        public UserDetailsManager userDetailsManager(DataSource dataSource) {
                JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

                jdbcUserDetailsManager.setUsersByUsernameQuery(
                                "select user_id, pw, active from members where user_id=?");
                jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                                "select user_id, role from roles where user_id=?");

                return jdbcUserDetailsManager;
        }

        // change the default login page
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http.authorizeHttpRequests(configurer -> configurer
                                .requestMatchers("/").hasRole("EMPLOYEE")
                                .requestMatchers("/leaders/**").hasRole("MANAGER")
                                .requestMatchers("/systems/**").hasRole("ADMIN")
                                .anyRequest().authenticated())
                                .formLogin(form -> form
                                                .loginPage("/showMyLoginPage")
                                                .loginProcessingUrl("/authenticateTheUser")
                                                .permitAll())
                                .logout(logout -> logout
                                                .permitAll())
                                .exceptionHandling(configurer -> configurer
                                                .accessDeniedPage("/access-denied"));

                return http.build();
        }

        // @Bean
        // public InMemoryUserDetailsManager userDetailsManager() {
        // UserDetails john = User.builder()
        // .username("john")
        // .password("{noop}test123")
        // .roles("EMPLOYEE")
        // .build();

        // UserDetails mary = User.builder()
        // .username("mary")
        // .password("{noop}test123")
        // .roles("MANAGER", "EMPLOYEE")
        // .build();

        // UserDetails susan = User.builder()
        // .username("susan")
        // .password("{noop}test123")
        // .roles("ADMIN", "EMPLOYEE", "MANAGER")
        // .build();

        // return new InMemoryUserDetailsManager(john, mary, susan);

        // }
}
