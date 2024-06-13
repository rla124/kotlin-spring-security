package com.kotlin.security.exception

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class RestExceptionHandler {

    val log: Logger = LoggerFactory.getLogger(RestExceptionHandler::class.java.name)

    @ExceptionHandler
    @ResponseStatus(HttpStatus.CONFLICT)
    fun handleRegisteredException(e: RegisteredException): ResponseError {
        log.error(e.message, e) // msg: String!, t: Throwable!
        return ResponseError.ALREADY_REGISTERED
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    fun handleBadCredentialsException(e: BadCredentialsException): ResponseError {
        log.error(e.message, e)
        return ResponseError.BAD_CREDENTIALS
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    fun handleBadRequestException(e: BadRequestException): ResponseError {
        log.error(e.message, e)
        return ResponseError.BAD_REQUEST
    }

    class RegisteredException: Exception()
    class BadRequestException(message: String) : RuntimeException(message)
}