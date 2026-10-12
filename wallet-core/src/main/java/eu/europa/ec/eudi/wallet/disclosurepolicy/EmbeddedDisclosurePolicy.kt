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

import android.annotation.SuppressLint
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils

/**
 * An embedded disclosure policy: the conditions that the attestation provider sets for the
 * relying parties that may receive a document (ETSI TS 119 472-3, clause 4.2.5).
 *
 * @property id the URI that identifies the policy
 * @property type the policy type, for example [AUTHORISED_RELYING_PARTIES]
 * @property authorisedRelyingParties the relying parties that an [AUTHORISED_RELYING_PARTIES]
 * policy allows
 * @property laymanUri the address of a page that explains the policy to the user
 */
data class EmbeddedDisclosurePolicy(
    val id: String,
    val type: String,
    val authorisedRelyingParties: List<AuthorisedRelyingParty> = emptyList(),
    val laymanUri: String? = null,
) {
    companion object {
        /** A policy that sets no restriction. */
        const val NO_POLICY = "no_policy"

        /** A policy that allows only the listed relying parties. */
        const val AUTHORISED_RELYING_PARTIES = "authorised_relying_parties"

        /** The member of `credential_metadata` in the issuer metadata that holds the policy. */
        internal const val CREDENTIAL_METADATA_PARAMETER = "embedded_disclosure_policy"

        private val json = Json { ignoreUnknownKeys = true }

        /**
         * Reads a policy from its JSON form.
         *
         * @param policy the JSON object of the policy
         * @return the policy, or `null` when the JSON is not a valid policy
         */
        fun fromJson(policy: JsonObject): EmbeddedDisclosurePolicy? =
            runCatching { json.decodeFromJsonElement(PolicyDto.serializer(), policy) }
                .getOrNull()
                ?.toPolicy()
    }
}

/**
 * A relying party, or a group of relying parties, that an embedded disclosure policy allows.
 */
sealed interface AuthorisedRelyingParty {

    /**
     * A relying party identified by the subject of its access certificate.
     *
     * @property subjectDn the subject distinguished name, as an RFC 4514 string
     * @property identifier the organization identifier, or for a natural person the serial
     * number, taken from [subjectDn]
     */
    data class Subject(val subjectDn: String, val identifier: String) : AuthorisedRelyingParty

    /**
     * The relying parties whose registration certificate holds an entitlement.
     *
     * @property uri the entitlement URI
     */
    data class Entitlement(val uri: String) : AuthorisedRelyingParty
}

/**
 * Returns the identifier of a relying party in this name: the organization identifier, or for a
 * natural person the serial number. Returns `null` when the name has more than one value for the
 * identifier.
 */
internal fun X500Name.relyingPartyIdentifier(): String? {
    val organizationIdentifiers = values(BCStyle.ORGANIZATION_IDENTIFIER)
    if (organizationIdentifiers.isNotEmpty()) return organizationIdentifiers.singleOrNull()
    return values(BCStyle.SERIALNUMBER).singleOrNull()
}

private fun X500Name.values(type: ASN1ObjectIdentifier): List<String> =
    getRDNs(type)
        .flatMap { it.typesAndValues.asIterable() }
        .filter { it.type == type }
        .map { IETFUtils.valueToString(it.value) }

/**
 * The RFC 4514 attribute names used in embedded disclosure policies: `ORGID` is the
 * organizationIdentifier and `SN` is the serialNumber (ETSI TS 119 472-3, clause 4.2.5.2), and
 * `GN` is the givenName. The surname is written as `surname`.
 */
private object PolicyNameStyle : BCStyle() {
    override fun attrNameToOID(attrName: String): ASN1ObjectIdentifier =
        when (attrName.uppercase()) {
            "ORGID" -> BCStyle.ORGANIZATION_IDENTIFIER
            "SN" -> BCStyle.SERIALNUMBER
            "GN" -> BCStyle.GIVENNAME
            else -> super.attrNameToOID(attrName)
        }
}

@SuppressLint("UnsafeOptInUsageError")
@Serializable
private data class PolicyDto(
    val id: String,
    val type: String,
    @SerialName("authorised_relying_parties")
    val authorisedRelyingParties: List<AuthorisedRelyingPartyDto>? = null,
    @SerialName("layman_uri")
    val laymanUri: String? = null,
)

@SuppressLint("UnsafeOptInUsageError")
@Serializable
private data class AuthorisedRelyingPartyDto(
    @SerialName("subject_dn")
    val subjectDn: String? = null,
    val entitlement: String? = null,
)

private fun PolicyDto.toPolicy(): EmbeddedDisclosurePolicy? {
    val relyingParties = authorisedRelyingParties?.map { it.toAuthorisedRelyingParty() ?: return null }
    if (type == EmbeddedDisclosurePolicy.AUTHORISED_RELYING_PARTIES && relyingParties == null) return null
    return EmbeddedDisclosurePolicy(
        id = id,
        type = type,
        authorisedRelyingParties = relyingParties.orEmpty(),
        laymanUri = laymanUri,
    )
}

private fun AuthorisedRelyingPartyDto.toAuthorisedRelyingParty(): AuthorisedRelyingParty? =
    when {
        subjectDn != null && entitlement == null -> {
            val identifier = runCatching { X500Name(PolicyNameStyle, subjectDn) }
                .getOrNull()
                ?.relyingPartyIdentifier()
            identifier?.let { AuthorisedRelyingParty.Subject(subjectDn, it) }
        }

        entitlement != null && subjectDn == null -> AuthorisedRelyingParty.Entitlement(entitlement)
        else -> null
    }
