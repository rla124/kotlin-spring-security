package com.kotlin.security.model.authentication

data class ReissueDto(
        val accessToken: String,
        val refreshToken: String
)