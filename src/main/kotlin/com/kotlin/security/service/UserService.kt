package com.kotlin.security.service

import com.kotlin.security.entity.UserEntity
import com.kotlin.security.model.authentication.RegisterRequest
import com.kotlin.security.repository.UserRepository
import org.springframework.stereotype.Service

@Service
class UserService(
        private val userRepository: UserRepository,
) {
    fun register(registerRequest: RegisterRequest): Unit {

        if (userRepository.findByUsernameOrEmail(registerRequest.username, registerRequest.email) != null) {
            // TODO : 전역 예외 처리 - 이미 등록된 유저 CONFICT
        }

        val user = UserEntity(
                email = registerRequest.email,
                username = registerRequest.username,
                password = registerRequest.password
        )

        userRepository.save(user)
    }
}