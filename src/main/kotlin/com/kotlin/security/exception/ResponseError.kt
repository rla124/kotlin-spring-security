package com.kotlin.security.exception

import com.fasterxml.jackson.annotation.JsonFormat

@JsonFormat(shape = JsonFormat.Shape.OBJECT)
enum class ResponseError(val statusCode: Int, val message: String) {

    ALREADY_REGISTERED(409, "Already registered."),

    BAD_CREDENTIALS(401, "Bad credentials"),

    REFRESH_TOKEN_MISMATCH(400, "Refresh token mismatch"),

    BAD_REQUEST(400, "Bad request")
}