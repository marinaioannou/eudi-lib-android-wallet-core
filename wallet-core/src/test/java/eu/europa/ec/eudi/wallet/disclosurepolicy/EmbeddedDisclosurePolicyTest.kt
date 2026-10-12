/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.wallet.disclosurepolicy

import eu.europa.ec.eudi.iso18013.transfer.response.RequestProcessor.ProcessedRequest
import eu.europa.ec.eudi.iso18013.transfer.response.ResponseResult
import eu.europa.ec.eudi.iso18013.transfer.response.WrpRegistrationInfo
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate.Reason
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NoPolicy
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NotSatisfied
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.Satisfied
import eu.europa.ec.eudi.wallet.document.Document
import eu.europa.ec.eudi.wallet.document.metadata.IssuerMetadata
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificate
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificateResult
import eu.europa.ec.eudi.wallet.registration.RegistrationFailureReason
import io.mockk.every
import io.mockk.mockk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Test
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.fromJavaX509Certificates
import org.multipaz.presentment.CredentialSelection
import org.multipaz.request.OpenID4VPRequesterIdentity
import org.multipaz.request.Requester
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.trustmanagement.TrustMetadata
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Date

class EmbeddedDisclosurePolicyTest {

    @Test
    fun `a document without a policy has no restriction`() {
        assertEquals(NoPolicy, evaluateDisclosurePolicy(null, "LEIXG-1", null))
    }

    @Test
    fun `a no_policy policy sets no restriction`() {
        assertEquals(NoPolicy, evaluate("""{"id": "$POLICY_ID", "type": "no_policy"}"""))
    }

    @Test
    fun `a policy that is not a JSON object is malformed`() {
        val result = evaluateDisclosurePolicy(JsonPrimitive(POLICY_ID), "LEIXG-1", null)

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY, null), result)
    }

    @Test
    fun `a subject without an identifier makes the policy malformed`() {
        val result = evaluate(authorisedRelyingParties("""{"subject_dn": "CN=Shop, O=Shop SA, C=GR"}"""))

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY, null), result)
    }

    @Test
    fun `a subject with two serial numbers makes the policy malformed`() {
        // OpenSSL prints the surname as SN, which a policy reads as the serial number.
        val result = evaluate(
            authorisedRelyingParties(
                """{"subject_dn": "CN=Jo Doe, SN=Doe, GN=Jo, serialNumber=TINGR-123, C=GR"}"""
            ),
            identifier = "TINGR-123",
        )

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY, null), result)
    }

    @Test
    fun `an authorised relying parties policy without a list is malformed`() {
        val result = evaluate("""{"id": "$POLICY_ID", "type": "authorised_relying_parties"}""")

        assertEquals(CannotEvaluate(Reason.MALFORMED_POLICY, null), result)
    }

    @Test
    fun `an unknown policy type is not supported`() {
        val result = evaluate("""{"id": "$POLICY_ID", "type": "specific_roots_of_trust"}""")

        assertEquals(Reason.UNSUPPORTED_POLICY_TYPE, (result as CannotEvaluate).reason)
    }

    @Test
    fun `a matching subject is enough when entitlements cannot be checked`() {
        val policy = authorisedRelyingParties(
            """{"subject_dn": "ORGID=LEIXG-1"}""",
            """{"entitlement": "$ENTITLEMENT"}""",
        )

        assertEquals(Satisfied, evaluate(policy, identifier = "LEIXG-1", entitlements = null))
    }

    @Test
    fun `a relying party that matches no entry does not satisfy the policy`() {
        val policy = authorisedRelyingParties(
            """{"subject_dn": "ORGID=LEIXG-2"}""",
            """{"entitlement": "$ENTITLEMENT"}""",
        )

        val result = evaluate(policy, identifier = "LEIXG-1", entitlements = listOf("$ENTITLEMENT/Other"))

        assertEquals(LAYMAN_URI, (result as NotSatisfied).policy.laymanUri)
    }

    @Test
    fun `SN in a policy is the serial number of a natural person`() {
        val document = documentWithPolicy(
            authorisedRelyingParties("""{"subject_dn": "CN=Jo Doe, GN=Jo, surname=Doe, SN=TINGR-123, C=GR"}""")
        )

        val result = document.evaluateDisclosurePolicy(
            request(listOf(certificate(BCStyle.SERIALNUMBER, "TINGR-123")))
        )

        assertEquals(Satisfied, result)
    }

    @Test
    fun `an untrusted access certificate does not identify the relying party`() {
        val document = documentWithPolicy(authorisedRelyingParties("""{"subject_dn": "ORGID=LEIXG-1"}"""))

        val result = document.evaluateDisclosurePolicy(
            request(listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")), trusted = false)
        )

        assertEquals(Reason.RELYING_PARTY_NOT_IDENTIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `several requester identities do not identify the relying party`() {
        val document = documentWithPolicy(authorisedRelyingParties("""{"subject_dn": "ORGID=LEIXG-1"}"""))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(
                    certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1"),
                    certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-2"),
                )
            )
        )

        assertEquals(Reason.RELYING_PARTY_NOT_IDENTIFIED, (result as CannotEvaluate).reason)
    }

    @Test
    fun `an entitlement in a verified registration certificate satisfies the policy`() {
        val document = documentWithPolicy(authorisedRelyingParties("""{"entitlement": "$ENTITLEMENT"}"""))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")),
                registration = RegistrationCertificateResult.Verified(
                    RegistrationCertificate(entitlements = listOf(ENTITLEMENT))
                ),
            )
        )

        assertEquals(Satisfied, result)
    }

    @Test
    fun `the entitlements of a failed registration certificate are not used`() {
        val document = documentWithPolicy(authorisedRelyingParties("""{"entitlement": "$ENTITLEMENT"}"""))

        val result = document.evaluateDisclosurePolicy(
            request(
                listOf(certificate(BCStyle.ORGANIZATION_IDENTIFIER, "LEIXG-1")),
                registration = RegistrationCertificateResult.Failed(
                    reason = RegistrationFailureReason.EXPIRED,
                    registration = RegistrationCertificate(entitlements = listOf(ENTITLEMENT)),
                ),
            )
        )

        assertEquals(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED, (result as CannotEvaluate).reason)
    }
}

private const val POLICY_ID = "https://issuer.example.com/edp/v1"
private const val LAYMAN_URI = "https://issuer.example.com/edp"
private const val ENTITLEMENT = "https://uri.etsi.org/19475/Entitlement/Service_Provider"

private fun authorisedRelyingParties(vararg entries: String): String =
    """
    {
      "id": "$POLICY_ID",
      "type": "authorised_relying_parties",
      "authorised_relying_parties": [${entries.joinToString()}],
      "layman_uri": "$LAYMAN_URI"
    }
    """

private fun policyJson(policy: String): JsonObject = Json.parseToJsonElement(policy).jsonObject

private fun evaluate(
    policy: String,
    identifier: String? = "LEIXG-1",
    entitlements: List<String>? = null,
): DisclosurePolicyResult = evaluateDisclosurePolicy(policyJson(policy), identifier, entitlements)

private fun documentWithPolicy(policy: String): Document = mockk {
    every { issuerMetadata } returns IssuerMetadata(
        documentConfigurationIdentifier = "employee_card",
        display = emptyList(),
        claims = null,
        credentialIssuerIdentifier = "https://issuer.example.com",
        issuerDisplay = null,
        embeddedDisclosurePolicy = policyJson(policy),
    )
}

private fun request(
    accessCertificates: List<X509Certificate>,
    trusted: Boolean = true,
    registration: WrpRegistrationInfo? = null,
): ProcessedRequest.Success = object : ProcessedRequest.Success(
    presentmentData = mockk(),
    requester = Requester(
        requesterIdentities = accessCertificates.map {
            OpenID4VPRequesterIdentity(X509CertChain.fromJavaX509Certificates(listOf(it)), "verifier.example.com")
        }
    ),
    trustMetadata = if (trusted) TrustMetadata() else null,
    wrpRegistration = registration,
) {
    override suspend fun generateResponse(
        selection: CredentialSelection,
        keyUnlockData: Map<String, KeyUnlockData>,
    ): ResponseResult = error("not used")
}

private fun certificate(identifierType: ASN1ObjectIdentifier, identifier: String): X509Certificate {
    val subject = X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.CN, "Test Relying Party")
        .addRDN(identifierType, identifier)
        .build()
    val keyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair()
    val now = Instant.now()
    val builder = JcaX509v3CertificateBuilder(
        subject,
        BigInteger(64, SecureRandom()),
        Date.from(now.minusSeconds(3600)),
        Date.from(now.plusSeconds(86400)),
        subject,
        keyPair.public,
    )
    val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private)
    return JcaX509CertificateConverter().getCertificate(builder.build(signer))
}
