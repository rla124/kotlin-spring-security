package com.kotlin.security.util

import org.springframework.util.SerializationUtils
import java.util.*
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

object CookieUtils {

    fun getCookie(request: HttpServletRequest, name: String): Cookie? =
            request.cookies.find { cookie ->
                cookie.name==name
            }

    fun addCookie(response: HttpServletResponse, name: String, value: String, maxAge: Int) =
            response.addCookie(Cookie(name, value).apply {
                path = "/"
                isHttpOnly = true
                this.maxAge = maxAge
            })

    fun deleteCookie(request: HttpServletRequest, response: HttpServletResponse, name: String) =
            request.cookies?.filter { cookie ->
                cookie.name==name
            }?.forEach { cookie: Cookie ->
                cookie.value = ""
                cookie.path = "/"
                cookie.maxAge = 0
                response.addCookie(cookie)
            }

    // 객체를 직렬화하여 Base64 인코딩된 문자열로 변환 -> 쿠키에 저장 가능해짐
    fun serialize(obj: Any): String =
            Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(obj))

    // 쿠키에서 값을 읽어와 Base64 디코딩 이후 직렬화된 바이트 배열을 객체로 역직렬화
    fun <T> deserialize(cookie: Cookie, cls: Class<T>): T? =
            cls.cast(SerializationUtils.deserialize(Base64.getUrlDecoder().decode(cookie.value)))
}