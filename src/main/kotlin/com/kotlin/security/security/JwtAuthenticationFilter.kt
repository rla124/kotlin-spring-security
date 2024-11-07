package com.kotlin.security.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.http.HttpHeaders
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import javax.crypto.AEADBadTagException

@Component
class JwtAuthenticationFilter(
        private val jwtService: JwtService,
        private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {

        val log = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java.name)

        val authHeader = request.getHeader(HttpHeaders.AUTHORIZATION)

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }

        val lengthOfBearerWithSpace = 7
        val jwtToken = authHeader.substring(lengthOfBearerWithSpace)
        log.info("jwe value: $jwtToken")

        if (SecurityContextHolder.getContext().authentication == null) {

            try {
                val username = jwtService.extractUsernameFromJWE(jwtToken, jwtService.generateAESKey())
                log.info("Extracted Username from jwe: $username")

                if (SecurityContextHolder.getContext().authentication == null) {
                    val userDetails = userDetailsService.loadUserByUsername(username)
                    log.info("UserDetails by loadUserByUsername method: $userDetails")

                    if (jwtService.isAdvancedTokenValid(jwtToken, userDetails)) {
                        val authenticationToken = UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.authorities
                        )
                        authenticationToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                        SecurityContextHolder.getContext().authentication = authenticationToken
                    } else {
                        log.warn("Invalid jwe: $jwtToken")
                    }
                }
            } catch (e: Exception) {
                log.error("Error extracting username from JWE: ", e)
            } catch (e: AEADBadTagException) {
                log.error("Decryption failed due to tag mismatch", e)
                throw e
            }
        }
        filterChain.doFilter(request, response)
    }

}
