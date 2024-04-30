package com.kotlin.security.model.authentication

data class AuthenticationRequest(
        val username: String,
        val password: String
)