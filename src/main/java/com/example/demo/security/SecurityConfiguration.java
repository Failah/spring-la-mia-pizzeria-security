package com.example.demo.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		String[] allRoles = { "USER", "ADMIN" };

		http.authorizeHttpRequests()
				// AUTH PER CREARE E MODIFICARE PIZZE: ADMIN
				.requestMatchers("/pizzas/new-pizza", "/pizzas/edit/**").hasAuthority("ADMIN")

				// POST SU PIZZE QUINDI IL DELETE: ADMIN
				.requestMatchers(HttpMethod.POST, "/pizzas/**").hasAuthority("ADMIN")

				// CONTROLLI SUGLI INGREDIENTI: ADMIN
				.requestMatchers("/ingredients", "/ingredients/**").hasAuthority("ADMIN")

				// CONTROLLI SULLE OFFERTE SPECIALI: ADMIN
				.requestMatchers("/special-offers", "/special-offers/**").hasAuthority("ADMIN")

				// ELENCO E DETTAGLIO PIZZE: USER E ADMIN
				.requestMatchers("/pizzas", "/pizzas/**").hasAnyAuthority(allRoles)

				// ACCESSO ALLA HOME: USER E ADMIN
				.requestMatchers("/**").permitAll()

				.and().formLogin().and().logout().and().exceptionHandling()

				// VIEW HTML PERSONALIZZATA PER L'ACCESSO NEGATO
				.accessDeniedPage("/access-denied.html");

		return http.build();
	}

	@Bean
	DatabaseUserDetailsService userDetailsService() {
		return new DatabaseUserDetailsService();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());

		System.out.println(passwordEncoder().encode("ciao"));

		return authProvider;
	}

}
