package com.kotlin.security.security.oauth2

import com.kotlin.security.util.CookieUtils
import com.nimbusds.oauth2.sdk.util.StringUtils
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
import org.springframework.stereotype.Component

@Component
class HttpCookieOAuth2AuthorizationRequestRepository : AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    companion object {
        const val OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request" // 인가 요청 저장하는 쿠키 이름
        const val REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri" // redirect uri 저장하는 쿠키 이름
        private const val cookieExpireSeconds = 180
    }

    // http 요청에서 쿠키를 가져와 OAuth2AuthorizationRequest 객체로 역직렬화
    override fun loadAuthorizationRequest(request: HttpServletRequest) =
            CookieUtils.getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)?.let { cookie ->
                CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest::class.java)
            }

    // oauth2 인가 요청 및 리다이렉트 uri를 쿠키에 저장할 수 있도록 직렬화
    override fun saveAuthorizationRequest(authorizationRequest: OAuth2AuthorizationRequest?, request: HttpServletRequest, response: HttpServletResponse) {
        if (authorizationRequest == null) {
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME)
            return
        }

        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtils.serialize(authorizationRequest), cookieExpireSeconds)

        val redirectUriAfterLogin = request.getParameter(REDIRECT_URI_PARAM_COOKIE_NAME)
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds)
        }
    }

    // http 요청에서 OAuth2AuthorizationRequest 객체를 로드하고 쿠키 삭제
    override fun removeAuthorizationRequest(request: HttpServletRequest, response: HttpServletResponse): OAuth2AuthorizationRequest? {
        val authorizationRequest = this.loadAuthorizationRequest(request)
        removeAuthorizationRequestCookies(request, response)
        return authorizationRequest
    }

    // oauth2 인가 요청과 리다이렉트 uri를 저장하는 쿠키 삭제
    private fun removeAuthorizationRequestCookies(request: HttpServletRequest, response: HttpServletResponse) {
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME)
    }
}