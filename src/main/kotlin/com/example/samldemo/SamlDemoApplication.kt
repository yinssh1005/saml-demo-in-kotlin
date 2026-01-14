package com.example.samldemo

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class SamlDemoApplication

fun main(args: Array<String>) {
    runApplication<SamlDemoApplication>(*args)
}
