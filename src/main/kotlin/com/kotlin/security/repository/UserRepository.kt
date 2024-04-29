package com.kotlin.security.repository

import com.kotlin.security.entity.UserEntity
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository: JpaRepository<UserEntity, Int> {

    fun findByUsernameOrEmail(username: String, email: String): UserEntity?

    fun findByUsername(username: String): UserEntity?
}