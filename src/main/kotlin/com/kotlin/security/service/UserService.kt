package com.kotlin.security.service

import com.kotlin.security.entity.UserEntity
import com.kotlin.security.exception.RestExceptionHandler
import com.kotlin.security.model.authentication.AuthenticationRequest
import com.kotlin.security.model.authentication.AuthenticationResponse
import com.kotlin.security.model.authentication.RegisterRequest
import com.kotlin.security.model.authentication.ReissueDto
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

        val accessToken = jwtService.generateAdvancedAccessToken(user!!)
        val refreshToken = jwtService.generateAdvancedRefreshToken(user!!)

        redisUtil.setData(user.username, refreshToken, refreshExpirationTime.toLong())

        return AuthenticationResponse(accessToken, refreshToken)
    }

    fun reissueToken(reissueRequest: ReissueDto): ReissueDto {

        val username = jwtService.extractUsernameFromJWE(reissueRequest.accessToken, jwtService.generateAESKey())
        val userDetails = userRepository.findByUsername(username)

        jwtService.isAdvancedTokenValid(reissueRequest.refreshToken, userDetails!!)

        val redisRefreshToken = redisUtil.getData(username)
        if (redisRefreshToken != reissueRequest.refreshToken) {
            throw RestExceptionHandler.RefreshTokenMismatchException()
        }

        // 이미 위 로직에서 user validation 검증을 했으므로 encryptedToken을 인자로 받아 username을 재추출할 필요가 없음
        val recreateAccessToken = jwtService.generateAdvancedAccessToken(userDetails)
        val recreateRefreshToken = jwtService.generateAdvancedRefreshToken(userDetails)

        redisUtil.setData(userDetails.username, recreateRefreshToken, refreshExpirationTime.toLong()) // 새로운 refresh token으로 갱신

        return ReissueDto(recreateAccessToken, recreateRefreshToken)
    }
}
