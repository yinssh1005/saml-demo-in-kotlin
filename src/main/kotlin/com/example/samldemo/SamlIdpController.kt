package com.example.samldemo

import jakarta.annotation.PostConstruct
import jakarta.servlet.http.HttpServletResponse
import org.opensaml.core.config.InitializationService
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.core.xml.util.XMLObjectSupport
import org.opensaml.saml.saml2.core.*
import org.opensaml.saml.saml2.core.impl.*
import org.opensaml.security.x509.BasicX509Credential
import org.opensaml.xmlsec.signature.support.SignatureConstants
import org.opensaml.xmlsec.signature.support.Signer
import org.springframework.core.io.ClassPathResource
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.saml2.core.Saml2X509Credential
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringWriter
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.*
import java.util.zip.Inflater
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

@RestController
class SamlIdpController {

    @PostConstruct
    fun init() {
        InitializationService.initialize()
    }

    private val signingCredential: Saml2X509Credential by lazy { loadSigningCredential() }
    private val authnRequestConsumer = OpenSaml4AuthenticationRequestConsumer()

    @GetMapping("/saml2/idp/metadata", produces = ["application/xml"])
    fun metadata(): String {
        val certificate = Base64.getEncoder().encodeToString(signingCredential.certificate.encoded)

        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="http://localhost:8080/saml2/idp/metadata">
                <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:KeyDescriptor use="signing">
                        <ds:KeyInfo>
                            <ds:X509Data>
                                <ds:X509Certificate>$certificate</ds:X509Certificate>
                            </ds:X509Data>
                        </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:8080/saml2/idp/sso"/>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8080/saml2/idp/sso"/>
                </md:IDPSSODescriptor>
            </md:EntityDescriptor>
        """.trimIndent()
    }

    @GetMapping("/saml2/idp/sso")
    fun ssoRedirect(
        @RequestParam("SAMLRequest") samlRequest: String,
        @RequestParam(value = "RelayState", required = false) relayState: String?,
        @AuthenticationPrincipal user: UserDetails,
        response: HttpServletResponse
    ) {
        val authnRequest = authnRequestConsumer.consume(samlRequest)
        val samlResponse = buildSamlResponse(authnRequest, user)
        val encodedResponse = marshalAndEncodeResponse(samlResponse)

        response.contentType = "text/html"
        response.writer.write(
            generateAutoSubmitForm(
                authnRequest.assertionConsumerServiceURL, encodedResponse, relayState
            )
        )
    }

    private fun loadSigningCredential(): Saml2X509Credential {
        val privateKeyResource = ClassPathResource("credentials/rp-private.key")
        val privateKeyPem = privateKeyResource.inputStream.bufferedReader().use { it.readText() }
            .replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", "")
            .replace("\r", "").trim()
        val privateKeyBytes = Base64.getDecoder().decode(privateKeyPem)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(keySpec) as java.security.interfaces.RSAPrivateKey

        val certificateResource = ClassPathResource("credentials/rp-certificate.crt")
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certificate =
            certificateFactory.generateCertificate(certificateResource.inputStream) as java.security.cert.X509Certificate

        return Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING)
    }

    class OpenSaml4AuthenticationRequestConsumer {
        fun consume(samlRequest: String): AuthnRequest {
            val decodedBytes = Base64.getDecoder().decode(samlRequest)
            val inflater = Inflater(true)
            inflater.setInput(decodedBytes)
            val outputStream = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (!inflater.finished()) {
                val count = inflater.inflate(buffer)
                outputStream.write(buffer, 0, count)
            }
            val decodedRequest = outputStream.toByteArray()

            return XMLObjectSupport.unmarshallFromInputStream(
                XMLObjectProviderRegistrySupport.getParserPool(), ByteArrayInputStream(decodedRequest)
            ) as AuthnRequest
        }
    }

    private fun buildSamlResponse(authnRequest: AuthnRequest, user: UserDetails): Response {
        val responseBuilder = ResponseBuilder()
        val samlResponse = responseBuilder.buildObject()
        samlResponse.id = "_" + UUID.randomUUID().toString()
        samlResponse.issueInstant = Instant.now()
        samlResponse.destination = authnRequest.assertionConsumerServiceURL
        samlResponse.inResponseTo = authnRequest.id

        val issuerBuilder = IssuerBuilder()
        val responseIssuer = issuerBuilder.buildObject()
        responseIssuer.value = "http://localhost:8080/saml2/idp/metadata"
        samlResponse.issuer = responseIssuer

        val statusBuilder = StatusBuilder()
        val status = statusBuilder.buildObject()
        val statusCodeBuilder = StatusCodeBuilder()
        val statusCode = statusCodeBuilder.buildObject()
        statusCode.value = StatusCode.SUCCESS
        status.statusCode = statusCode
        samlResponse.status = status

        val assertion = buildAssertion(authnRequest, user)
        samlResponse.assertions.add(assertion)

        return samlResponse
    }

    private fun buildAssertion(authnRequest: AuthnRequest, user: UserDetails): Assertion {
        val assertionBuilder = AssertionBuilder()
        val assertion = assertionBuilder.buildObject()
        assertion.id = "_" + UUID.randomUUID().toString()
        assertion.issueInstant = Instant.now()

        val issuerBuilder = IssuerBuilder()
        val assertionIssuer = issuerBuilder.buildObject()
        assertionIssuer.value = "http://localhost:8080/saml2/idp/metadata"
        assertion.issuer = assertionIssuer

        assertion.subject = buildSubject(authnRequest, user)

        // Add Conditions
        val conditionsBuilder = ConditionsBuilder()
        val conditions = conditionsBuilder.buildObject()
        conditions.notBefore = Instant.now()
        conditions.notOnOrAfter = Instant.now().plusSeconds(300)

        // 添加 AudienceRestriction
        val audienceRestrictionBuilder = AudienceRestrictionBuilder()
        val audienceRestriction = audienceRestrictionBuilder.buildObject()
        val audienceBuilder = AudienceBuilder()
        val audience = audienceBuilder.buildObject()
        // 通常设置为 SP 的 EntityID，可以从 authnRequest.issuer.value 获取
        audience.uri = authnRequest.issuer.value 
        audienceRestriction.audiences.add(audience)
        conditions.audienceRestrictions.add(audienceRestriction)

        assertion.conditions = conditions

        // Add AuthnStatement
        val authnStatementBuilder = AuthnStatementBuilder()
        val authnStatement = authnStatementBuilder.buildObject()
        authnStatement.authnInstant = Instant.now()

        val authnContextBuilder = AuthnContextBuilder()
        val authnContext = authnContextBuilder.buildObject()

        val authnContextClassRefBuilder = AuthnContextClassRefBuilder()
        val authnContextClassRef = authnContextClassRefBuilder.buildObject()
        authnContextClassRef.uri = AuthnContext.PASSWORD_AUTHN_CTX
        authnContext.authnContextClassRef = authnContextClassRef

        authnStatement.authnContext = authnContext
        assertion.authnStatements.add(authnStatement)

        assertion.attributeStatements.add(buildAttributeStatement(user))

        // Sign the assertion
        val signatureBuilder = org.opensaml.xmlsec.signature.impl.SignatureBuilder()
        val signature = signatureBuilder.buildObject()
        signature.signingCredential = BasicX509Credential(signingCredential.certificate, signingCredential.privateKey)
        signature.signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256
        signature.canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        assertion.signature = signature

        return assertion
    }

    private fun buildSubject(authnRequest: AuthnRequest, user: UserDetails): Subject {
        val subjectBuilder = SubjectBuilder()
        val subject = subjectBuilder.buildObject()

        val nameIdBuilder = NameIDBuilder()
        val nameId = nameIdBuilder.buildObject()
        nameId.format = NameIDType.EMAIL
        nameId.value = user.username + "@example.com"
        subject.nameID = nameId

        val subjectConfirmationBuilder = SubjectConfirmationBuilder()
        val subjectConfirmation = subjectConfirmationBuilder.buildObject()
        subjectConfirmation.method = SubjectConfirmation.METHOD_BEARER

        val subjectConfirmationDataBuilder = SubjectConfirmationDataBuilder()
        val subjectConfirmationData = subjectConfirmationDataBuilder.buildObject()
        subjectConfirmationData.inResponseTo = authnRequest.id
        subjectConfirmationData.notOnOrAfter = Instant.now().plusSeconds(300)
        subjectConfirmationData.recipient = authnRequest.assertionConsumerServiceURL
        subjectConfirmation.subjectConfirmationData = subjectConfirmationData

        subject.subjectConfirmations.add(subjectConfirmation)
        return subject
    }

    private fun buildAttributeStatement(user: UserDetails): AttributeStatement {
        val attributeStatementBuilder = AttributeStatementBuilder()
        val attributeStatement = attributeStatementBuilder.buildObject()

        val attributeBuilder = AttributeBuilder()
        val usernameAttribute = attributeBuilder.buildObject()
        usernameAttribute.name = "username"
        usernameAttribute.nameFormat = Attribute.BASIC

        val stringBuilder = org.opensaml.core.xml.schema.impl.XSStringBuilder()
        val usernameValue = stringBuilder.buildObject(
            AttributeValue.DEFAULT_ELEMENT_NAME, org.opensaml.core.xml.schema.XSString.TYPE_NAME
        )
        usernameValue.value = user.username
        usernameAttribute.attributeValues.add(usernameValue)

        val emailAttribute = attributeBuilder.buildObject()
        emailAttribute.name = "email"
        emailAttribute.nameFormat = Attribute.BASIC
        val emailValue = stringBuilder.buildObject(
            AttributeValue.DEFAULT_ELEMENT_NAME, org.opensaml.core.xml.schema.XSString.TYPE_NAME
        )
        emailValue.value = user.username + "@example.com"
        emailAttribute.attributeValues.add(emailValue)

        attributeStatement.attributes.add(usernameAttribute)
        attributeStatement.attributes.add(emailAttribute)
        return attributeStatement
    }

    private fun marshalAndEncodeResponse(samlResponse: Response): String {
            // 1. 先进行 Marshalling (编组)，将 XMLObject 转换为 DOM Element
            val element = XMLObjectSupport.marshall(samlResponse)

            // 2. 编组后，对包含签名信息的对象执行签名
            samlResponse.assertions.forEach { assertion ->
                assertion.signature?.let { Signer.signObject(it) }
            }

            // 3. 将包含签名后的 DOM 树转换为字符串
            val writer = StringWriter()
            val transformer = TransformerFactory.newInstance().newTransformer()
            transformer.transform(DOMSource(element), StreamResult(writer))
            val samlResponseString = writer.toString()

            return Base64.getEncoder().encodeToString(samlResponseString.toByteArray())
        }

    private fun generateAutoSubmitForm(
        assertionConsumerServiceURL: String, encodedResponse: String, relayState: String?
    ): String {
        return """
            <!DOCTYPE html>
            <html>
            <head><title>SAML Response</title></head>
            <body onload="document.forms[0].submit()">
                <form method="post" action="$assertionConsumerServiceURL">
                    <input type="hidden" name="SAMLResponse" value="$encodedResponse" />
                    ${if (relayState != null) "<input type=\"hidden\" name=\"RelayState\" value=\"$relayState\" />" else ""}
                    <noscript><input type="submit" value="Continue" /></noscript>
                </form>
            </body>
            </html>
        """.trimIndent()
    }

    @PostMapping("/saml2/idp/sso")
    fun ssoPost(
        @RequestParam("SAMLRequest") samlRequest: String,
        @RequestParam(value = "RelayState", required = false) relayState: String?,
        @AuthenticationPrincipal user: UserDetails,
        response: HttpServletResponse
    ) {
        response.writer.write("SAML SSO POST Request received for user ${user.username}.")
    }
}
