package com.kotlin.security.security.oauth2

import com.kotlin.security.config.AppProperties
import com.kotlin.security.exception.RestExceptionHandler.BadRequestException
import com.kotlin.security.repository.UserRepository
import com.kotlin.security.security.JwtService
import com.kotlin.security.util.CookieUtils
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.web.util.UriComponentsBuilder
import java.io.IOException
import java.net.URI

class OAuth2AuthenticationSuccessHandler(
        private val userRepository: UserRepository,
        private val jwtService: JwtService,
        private val appProperties: AppProperties,
        private val httpCookieOAuth2AuthorizationRequestRepository: HttpCookieOAuth2AuthorizationRequestRepository
) : SimpleUrlAuthenticationSuccessHandler() {

    @Throws(IOException::class, ServletException::class)
    override fun onAuthenticationSuccess(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        val targetUrl = determineTargetUrl(request, response, authentication)

        if (response.isCommitted) {
            logger.debug("Response가 이미 commit되어 ${targetUrl}로 redirect될 수 없습니다.")
            return
        }

        clearAuthenticationAttributes(request, response)
        redirectStrategy.sendRedirect(request, response, targetUrl)

    }

    protected override fun determineTargetUrl(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication): String {
        val redirectUri = CookieUtils.getCookie(request, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
                ?.let {
                    if (!isAuthorizedRedirectUri(it.value)) {
                        throw BadRequestException("Unauthorized Redirect URI")
                    }
                    it.value
                }?:defaultTargetUrl

        val token = jwtService.generateAccessToken(userRepository.findByUsername(authentication.name)!!)

        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .build().toUriString()
    }

    protected fun clearAuthenticationAttributes(request: HttpServletRequest, response: HttpServletResponse) {
        super.clearAuthenticationAttributes(request)
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response)
    }

    fun isAuthorizedRedirectUri(uri: String): Boolean =
            URI.create(uri).let { clientRedirectUri ->
                appProperties.oauth2.authorizedRedirectUris.any { authorizedRedirectUri ->
                    val authorizedURI = URI.create(authorizedRedirectUri)
                    authorizedURI.host.equals(clientRedirectUri.host, ignoreCase = true) && authorizedURI.port == clientRedirectUri.port
            }
    }

}