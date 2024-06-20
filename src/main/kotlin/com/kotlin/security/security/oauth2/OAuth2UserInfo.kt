package com.kotlin.security.security.oauth2

abstract class OAuth2UserInfo(var attributes: MutableMap<String, Any>) {

    abstract val id: String

    abstract val name: String

    abstract val email: String

    abstract val imageUrl: String?

}