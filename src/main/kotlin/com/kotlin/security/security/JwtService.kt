package com.kotlin.security.security

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service
import java.security.Key
import java.util.*

@Service
class JwtService {

    @Value("\${custom.jwt.secret}")
    lateinit var secretKey: String

    @Value("\${custom.jwt.expiration}")
    lateinit var expirationTime: Number

    fun generateToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String = Jwts.builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + expirationTime.toLong()))
            .signWith(getSignInKey(),SignatureAlgorithm.HS256)
            .compact()

    fun generateToken(userDetails: UserDetails): String = generateToken(HashMap(), userDetails)
    private fun getSignInKey(): Key {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        return Keys.hmacShaKeyFor(keyBytes)
    }
}