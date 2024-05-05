package com.kotlin.security.exception

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class RestExceptionHandler {

    val log: Logger = LoggerFactory.getLogger(RestExceptionHandler::class.java.name)

    // TODO: ExceptionHandler 처리
}