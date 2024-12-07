package com.springcourse.demosecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class DemoSecurityConfig {
        @Bean
        public InMemoryUserDetailsManager userDetailsManager() {
                UserDetails john = User.builder()
                                .username("john")
                                .password("{noop}test123")
                                .roles("EMPLOYEE")
                                .build();

                UserDetails mary = User.builder()
                                .username("mary")
                                .password("{noop}test123")
                                .roles("MANAGER", "EMPLOYEE")
                                .build();

                UserDetails susan = User.builder()
                                .username("susan")
                                .password("{noop}test123")
                                .roles("ADMIN", "EMPLOYEE", "MANAGER")
                                .build();

                return new InMemoryUserDetailsManager(john, mary, susan);

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
                                                .permitAll());

                return http.build();
        }
}
