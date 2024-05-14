package com.kotlin.security.service

import com.kotlin.security.entity.UserEntity
import com.kotlin.security.exception.RestExceptionHandler
import com.kotlin.security.model.authentication.AuthenticationRequest
import com.kotlin.security.model.authentication.AuthenticationResponse
import com.kotlin.security.model.authentication.RegisterRequest
import com.kotlin.security.redis.RedisUtil
import com.kotlin.security.repository.UserRepository
import com.kotlin.security.security.JwtService
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
        private val userRepository: UserRepository,
        private val passwordEncoder: PasswordEncoder,
        private val authenticationManager: AuthenticationManager,
        private val jwtService: JwtService,
        private val redisUtil: RedisUtil
) {
    @Value("\${custom.jwt.token.refresh-expiration-time}")
    lateinit var refreshExpirationTime: Number
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

        val accessToken = jwtService.generateAccessToken(user!!)
        val refreshToken = jwtService.generateRefreshToken(user!!)

        redisUtil.setData(user.username, refreshToken, refreshExpirationTime.toLong())

        return AuthenticationResponse(accessToken, refreshToken)
    }

    // TODO: refresh token 이용한 토큰 재발급 함수 추가
}