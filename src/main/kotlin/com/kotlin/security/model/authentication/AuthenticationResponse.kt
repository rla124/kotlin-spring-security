package com.kotlin.security.model.authentication

data class AuthenticationResponse(
        val accessToken: String,
        val refreshToken: String
)
