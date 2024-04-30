package com.kotlin.security.security

import com.kotlin.security.repository.UserRepository
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

@Configuration
class ApplicationSecurityConfig(
        private val userRepository: UserRepository
) {
    @Bean
    fun passwordEncoder() = BCryptPasswordEncoder()

    @Bean
    fun authenticationProvider() = DaoAuthenticationProvider().apply {
        setUserDetailsService(userDetailsService())
        setPasswordEncoder(passwordEncoder())
    }

    @Bean
    fun userDetailsService() = UserDetailsService { userRepository.findByUsername(it) }

    @Bean
    fun authenticationManager(configuration: AuthenticationConfiguration): AuthenticationManager =
            configuration.authenticationManager
}