package com.kotlin.security.security.oauth2

import org.springframework.security.core.AuthenticationException
import jakarta.servlet.ServletException
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.stereotype.Component
import org.springframework.web.util.UriComponentsBuilder
import java.io.IOException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import com.kotlin.security.util.CookieUtils

@Component
class OAuth2AuthenticationFailureHandler(
        var httpCookieOAuth2AuthorizationRequestRepository: HttpCookieOAuth2AuthorizationRequestRepository
) : SimpleUrlAuthenticationFailureHandler() {

    @Throws(IOException::class, ServletException::class)
    override fun onAuthenticationFailure(request: HttpServletRequest, response: HttpServletResponse, exception: AuthenticationException) {

        // 리다이렉트 uri를 가지고 있는 쿠키를 통해 uriComponentsBuilder로 url error 쿼리 파라미터 추가
        // 실패한 이유를 포함한 targetUrl 생성
        var targetUrl = CookieUtils.getCookie(request, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)?.value?:"/"

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.localizedMessage)
                .build().toUriString()

        // 인증 실패 시 oauth2 인가 요청 쿠키 삭제(보안)
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response)

        // targetUrl로 리다이렉트
        redirectStrategy.sendRedirect(request, response, targetUrl)
    }
}