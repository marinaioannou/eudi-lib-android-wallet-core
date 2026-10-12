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
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.CannotEvaluate.Reason
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NoPolicy
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.NotSatisfied
import eu.europa.ec.eudi.wallet.disclosurepolicy.DisclosurePolicyResult.Satisfied
import eu.europa.ec.eudi.wallet.document.Document
import eu.europa.ec.eudi.wallet.registration.RegistrationCertificateResult
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import org.bouncycastle.asn1.x500.X500Name
import org.multipaz.crypto.javaX509Certificates

/**
 * The result of evaluating the embedded disclosure policy of a document for a presentation
 * request. The result informs the user; the user decides whether to present the document.
 */
sealed interface DisclosurePolicyResult {

    /** The document has no embedded disclosure policy, or its policy sets no restriction. */
    data object NoPolicy : DisclosurePolicyResult

    /** The relying party meets the policy. */
    data object Satisfied : DisclosurePolicyResult

    /**
     * The relying party does not meet the policy.
     *
     * @property policy the evaluated policy
     */
    data class NotSatisfied(val policy: EmbeddedDisclosurePolicy) : DisclosurePolicyResult

    /**
     * The policy could not be evaluated.
     *
     * @property reason the reason the policy could not be evaluated
     * @property policy the policy, or `null` when it could not be read
     */
    data class CannotEvaluate(
        val reason: Reason,
        val policy: EmbeddedDisclosurePolicy?,
    ) : DisclosurePolicyResult {

        /** The reasons a policy cannot be evaluated. */
        enum class Reason {
            /** The policy does not follow the expected JSON form. */
            MALFORMED_POLICY,

            /** The policy type is not supported. */
            UNSUPPORTED_POLICY_TYPE,

            /** The relying party has no trusted access certificate with an identifier. */
            RELYING_PARTY_NOT_IDENTIFIED,

            /** The policy lists entitlements and the relying party has no verified registration certificate. */
            REGISTRATION_CERTIFICATE_NOT_VERIFIED,
        }
    }
}

/**
 * Evaluates the embedded disclosure policy of this document for a presentation request.
 *
 * @param request the processed presentation request
 * @return the result to show to the user before the user approves the presentation
 */
fun Document.evaluateDisclosurePolicy(request: ProcessedRequest.Success): DisclosurePolicyResult =
    evaluateDisclosurePolicy(
        policyJson = issuerMetadata?.embeddedDisclosurePolicy,
        relyingPartyIdentifier = request.trustedRelyingPartyIdentifier(),
        verifiedEntitlements = (request.wrpRegistration as? RegistrationCertificateResult.Verified)
            ?.registration
            ?.entitlements,
    )

/**
 * Evaluates an embedded disclosure policy.
 *
 * @param policyJson the policy as stored with the document, or `null` when there is none
 * @param relyingPartyIdentifier the identifier in the trusted access certificate of the relying party
 * @param verifiedEntitlements the entitlements in the verified registration certificate of the
 * relying party, or `null` when there is no verified registration certificate
 */
internal fun evaluateDisclosurePolicy(
    policyJson: JsonElement?,
    relyingPartyIdentifier: String?,
    verifiedEntitlements: List<String>?,
): DisclosurePolicyResult {
    if (policyJson == null) return NoPolicy
    val policy = (policyJson as? JsonObject)?.let { EmbeddedDisclosurePolicy.fromJson(it) }
        ?: return CannotEvaluate(Reason.MALFORMED_POLICY, null)
    return when (policy.type) {
        EmbeddedDisclosurePolicy.NO_POLICY -> NoPolicy
        EmbeddedDisclosurePolicy.AUTHORISED_RELYING_PARTIES ->
            evaluateAuthorisedRelyingParties(policy, relyingPartyIdentifier, verifiedEntitlements)

        else -> CannotEvaluate(Reason.UNSUPPORTED_POLICY_TYPE, policy)
    }
}

private fun evaluateAuthorisedRelyingParties(
    policy: EmbeddedDisclosurePolicy,
    relyingPartyIdentifier: String?,
    verifiedEntitlements: List<String>?,
): DisclosurePolicyResult {
    if (relyingPartyIdentifier == null) return CannotEvaluate(Reason.RELYING_PARTY_NOT_IDENTIFIED, policy)
    val subjects = policy.authorisedRelyingParties.filterIsInstance<AuthorisedRelyingParty.Subject>()
    val entitlements = policy.authorisedRelyingParties.filterIsInstance<AuthorisedRelyingParty.Entitlement>()

    if (subjects.any { it.identifier == relyingPartyIdentifier }) return Satisfied
    if (verifiedEntitlements != null && entitlements.any { it.uri in verifiedEntitlements }) return Satisfied
    if (verifiedEntitlements == null && entitlements.isNotEmpty()) {
        return CannotEvaluate(Reason.REGISTRATION_CERTIFICATE_NOT_VERIFIED, policy)
    }
    return NotSatisfied(policy)
}

/**
 * Returns the identifier in the access certificate of the relying party, when the request has a
 * single requester identity and its certificate chain is trusted.
 */
private fun ProcessedRequest.Success.trustedRelyingPartyIdentifier(): String? {
    if (trustMetadata == null) return null
    val identity = requester.requesterIdentities.singleOrNull() ?: return null
    val accessCertificate = identity.certChain.javaX509Certificates.firstOrNull() ?: return null
    return X500Name.getInstance(accessCertificate.subjectX500Principal.encoded).relyingPartyIdentifier()
}
