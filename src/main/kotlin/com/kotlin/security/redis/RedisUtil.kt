package com.kotlin.security.redis

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import java.util.concurrent.TimeUnit
import java.time.Duration

@Service
class RedisUtil(private val template: StringRedisTemplate) {

    fun setData(key: String, value: String, duration: Long) {
        val valueOperations = template.opsForValue()
        val expireDuration = Duration.ofSeconds(duration)
        valueOperations.set(key, value, expireDuration)
        template.expire(key, duration, TimeUnit.MILLISECONDS)
    }

    fun getData(key: String): String? {
        return template.opsForValue().get(key)
    }

    fun deleteData(key: String) {
        template.delete(key)
    }

    fun existData(key: String): Boolean {
        return template.hasKey(key)
    }
}