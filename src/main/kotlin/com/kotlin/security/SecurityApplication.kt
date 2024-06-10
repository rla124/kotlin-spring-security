package com.kotlin.security

import com.kotlin.security.config.AppProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(AppProperties::class)
class SecurityApplication

fun main(args: Array<String>) {
	runApplication<SecurityApplication>(*args)
}
