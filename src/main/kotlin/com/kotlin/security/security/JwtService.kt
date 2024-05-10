package com.kotlin.security.security

import io.jsonwebtoken.Claims
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

    @Value("\${custom.jwt.token.access-expiration-time}")
    lateinit var accessExpirationTime: Number

    @Value("\${custom.jwt.token.refresh-expiration-time}")
    lateinit var refreshExpirationTime: Number

    fun generateAccessToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String = Jwts.builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + accessExpirationTime.toLong()))
            .signWith(getSignInKey(),SignatureAlgorithm.HS256)
            .compact()

    fun generateAccessToken(userDetails: UserDetails): String = generateAccessToken(HashMap(), userDetails)

    fun generateRefreshToken(extraClaims: Map<String, Any>, userDetails: UserDetails): String = Jwts.builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.username)
            .setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + refreshExpirationTime.toLong()))
            .signWith(getSignInKey(),SignatureAlgorithm.HS256)
            .compact()

    fun generateRefreshToken(userDetails: UserDetails): String = generateRefreshToken(HashMap(), userDetails)

    fun extractUsername(token: String): String = extractClaim(token, Claims::getSubject)

    fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T): T {
        val claims = extractAllClaims(token)
        return claimsResolver(claims)
    }

    fun isTokenValid(token: String, userDetails: UserDetails): Boolean {
        val username = extractUsername(token)
        return username == userDetails.username && !isTokenExpired(token)
    }

    private fun getSignInKey(): Key {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        return Keys.hmacShaKeyFor(keyBytes)
    }

    private fun extractAllClaims(token: String): Claims = Jwts
            .parserBuilder()
            .setSigningKey(getSignInKey())
            .build()
            .parseClaimsJws(token) //json web signature
            .body

    private fun isTokenExpired(token: String): Boolean = extractExpiration(token).before(Date())

    private fun extractExpiration(token: String): Date = extractClaim(token, Claims::getExpiration)
}