package com.kotlin.security.controller

import com.kotlin.security.model.authentication.AuthenticationRequest
import com.kotlin.security.model.authentication.RegisterRequest
import com.kotlin.security.model.authentication.ReissueDto
import com.kotlin.security.service.UserService
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/auth")
class AuthenticationController(
        private val userService: UserService,
) {

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")
    fun register(@RequestBody registerRequest: RegisterRequest) = userService.register(registerRequest)

    @ResponseStatus(HttpStatus.OK)
    @PostMapping("/authenticate")
    fun authenticate(@RequestBody authenticationRequest: AuthenticationRequest) =
            userService.authenticate(authenticationRequest)

    @ResponseStatus(HttpStatus.OK)
    @PostMapping("/reissue")
    fun reissue(@RequestBody reissueRequest: ReissueDto) =
            userService.reissueToken(reissueRequest)
}