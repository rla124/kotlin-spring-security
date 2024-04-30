package com.kotlin.security.service

import com.kotlin.security.entity.UserEntity
import com.kotlin.security.model.authentication.AuthenticationRequest
import com.kotlin.security.model.authentication.AuthenticationResponse
import com.kotlin.security.model.authentication.RegisterRequest
import com.kotlin.security.repository.UserRepository
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
        private val userRepository: UserRepository,
        private val passwordEncoder: PasswordEncoder,
        private val authenticationManager: AuthenticationManager
) {
    fun register(registerRequest: RegisterRequest): Unit {

        if (userRepository.findByUsernameOrEmail(registerRequest.username, registerRequest.email) != null) {
            // TODO : 전역 예외 처리 - 이미 등록된 유저 CONFICT
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
        // TODO : jwt 발급 로직 구현
        return AuthenticationResponse("")
    }
}