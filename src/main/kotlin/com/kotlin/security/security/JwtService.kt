package com.kotlin.security.security

import com.fasterxml.jackson.databind.ObjectMapper
import com.kotlin.security.repository.UserRepository
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.DirectDecrypter
import com.nimbusds.jose.crypto.DirectEncrypter
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
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

@Service
class JwtService(
        private val userRepository: UserRepository
) {

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

    fun regenerateAccessToken(accessToken: String): String {
        val username = extractUsername(accessToken)
        return generateAccessToken(userRepository.findByUsername(username)!!)
    }

    fun regenerateRefreshToken(accessToken: String): String {
        val username = extractUsername(accessToken)
        return generateRefreshToken(userRepository.findByUsername(username)!!)
    }

    val objectMapper = ObjectMapper()

    fun generateAESKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }

    fun generateEncryptedAccessToken(userDetails: UserDetails, secretKey: SecretKey): String {
        val claims = mapOf(
                "sub" to userDetails.username,
                "exp" to (System.currentTimeMillis() + accessExpirationTime.toLong()) / 1000
        )

        val payloadJson = objectMapper.writeValueAsString(claims) // Java Object -> JSON String으로 변환
        val jweHeader = JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
        val jweObject = JWEObject(jweHeader, Payload(payloadJson))
        jweObject.encrypt(DirectEncrypter(secretKey))
        return jweObject.serialize()
    }

    fun generateEncryptedRefreshToken(userDetails: UserDetails, secretKey: SecretKey): String {
        val claims = mapOf(
                "sub" to userDetails.username,
                "exp" to (System.currentTimeMillis() + refreshExpirationTime.toLong()) / 1000
        )

        val payloadJson = objectMapper.writeValueAsString(claims)
        val jweHeader = JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
        val jweObject = JWEObject(jweHeader, Payload(payloadJson))
        jweObject.encrypt(DirectEncrypter(secretKey))
        return jweObject.serialize()
    }

    fun decryptTokenAndExtractClaims(encryptedToken: String, secretKey: SecretKey): Map<String, Any> {
        val jweObject = JWEObject.parse(encryptedToken)
        jweObject.decrypt(DirectDecrypter(secretKey))

        val payloadJson = jweObject.payload.toString()
        return objectMapper.readValue(payloadJson, Map::class.java) as Map<String, Any>
    }

    fun generateAdvancedAccessToken(userDetails: UserDetails): String {
        return generateEncryptedAccessToken(userDetails, generateAESKey())
    }

    fun generateAdvancedRefreshToken(userDetails: UserDetails): String {
        return generateEncryptedRefreshToken(userDetails, generateAESKey())
    }

    fun extractUsernameFromJWE(encryptedToken: String, secretKey: SecretKey): String {
        val claims = decryptTokenAndExtractClaims(encryptedToken, secretKey)
        return claims["sub"] as String
    }

    fun isJweTokenExpired(encryptedToken: String, secretKey: SecretKey): Boolean {
        val claims = decryptTokenAndExtractClaims(encryptedToken, secretKey)
        val exp = claims["exp"] as Long
        return exp * 1000 < System.currentTimeMillis()
    }

    fun isAdvancedTokenValid(encryptedToken: String, userDetails: UserDetails): Boolean {
        val username = extractUsernameFromJWE(encryptedToken, generateAESKey())
        return username == userDetails.username && !isJweTokenExpired(encryptedToken, generateAESKey())
    }
}
