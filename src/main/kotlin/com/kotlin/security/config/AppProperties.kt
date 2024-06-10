package com.kotlin.security.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "app")
class AppProperties {
    val oauth2 = OAuth2()
    class OAuth2 {
        var authorizedRedirectUris: List<String> = ArrayList()
            private set
    }
}