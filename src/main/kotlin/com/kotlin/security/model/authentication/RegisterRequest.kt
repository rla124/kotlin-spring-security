package com.kotlin.security.model.authentication

data class RegisterRequest(
        val email: String,
        val username: String,
        val password: String
)