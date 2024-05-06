package com.kotlin.security.service

import com.kotlin.security.entity.UserEntity
import com.kotlin.security.exception.RestExceptionHandler
import com.kotlin.security.model.authentication.AuthenticationRequest
import com.kotlin.security.model.authentication.AuthenticationResponse
import com.kotlin.security.model.authentication.RegisterRequest
import com.kotlin.security.repository.UserRepository
import com.kotlin.security.security.JwtService
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
        private val userRepository: UserRepository,
        private val passwordEncoder: PasswordEncoder,
        private val authenticationManager: AuthenticationManager,
        private val jwtService: JwtService
) {
    fun register(registerRequest: RegisterRequest): Unit {

        if (userRepository.findByUsernameOrEmail(registerRequest.username, registerRequest.email) != null) {
            throw RestExceptionHandler.RegisteredException()
        }

        val user = UserEntity(
                email = registerRequest.email,
                username = registerRequest.username,
                password = passwordEncoder.encode(registerRequest.password)
        )

        userRepository.save(user)
    }

    fun authenticate(authenticationRequest: AuthenticationRequest): AuthenticationResponse {

        authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(
                        authenticationRequest.username,
                        authenticationRequest.password
                )
        )

        val user = userRepository.findByUsername(authenticationRequest.username)

        return AuthenticationResponse(jwtService.generateToken(user!!))
    }
}