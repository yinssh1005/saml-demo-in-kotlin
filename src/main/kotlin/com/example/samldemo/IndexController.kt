package com.example.samldemo

import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class IndexController {

    @GetMapping("/")
    fun index(@AuthenticationPrincipal principal: UserDetails?): String {
        return if (principal != null) {
            "Hello, ${principal.username}! This is SAML IdP service."
        } else {
            "Hello, guest!"
        }
    }
}
