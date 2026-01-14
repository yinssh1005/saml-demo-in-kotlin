package com.example.samldemo

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

@SpringBootTest
@AutoConfigureMockMvc
class MetadataTest {

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `metadata should be accessible without authentication`() {
        mockMvc.get("/saml2/idp/metadata")
            .andExpect {
                status { isOk() }
                content { contentTypeCompatibleWith("application/xml") }
                content { string(org.hamcrest.Matchers.containsString("EntityDescriptor")) }
                content { string(org.hamcrest.Matchers.containsString("IDPSSODescriptor")) }
            }
    }
}
