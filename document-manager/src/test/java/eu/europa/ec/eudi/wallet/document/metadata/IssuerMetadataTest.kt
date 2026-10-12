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
package eu.europa.ec.eudi.wallet.document.metadata

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class IssuerMetadataTest {

    @Test
    fun `the embedded disclosure policy is kept when the metadata is stored and read`() {
        val policy = Json.parseToJsonElement(
            """{"id":"https://issuer.example.com/edp/v1","type":"no_policy"}"""
        ).jsonObject
        val metadata = IssuerMetadata(
            documentConfigurationIdentifier = "eu.europa.ec.eudi.pid_mdoc",
            display = emptyList(),
            claims = null,
            credentialIssuerIdentifier = "https://issuer.example.com",
            issuerDisplay = null,
            embeddedDisclosurePolicy = policy,
        )

        val read = IssuerMetadata.fromJson(metadata.toJson()).getOrThrow()

        assertEquals(policy, read.embeddedDisclosurePolicy)
    }

    @Test
    fun `metadata stored without an embedded disclosure policy is read with none`() {
        val stored = """
            {
              "documentConfigurationIdentifier": "eu.europa.ec.eudi.pid_mdoc",
              "display": [],
              "claims": null,
              "credentialIssuerIdentifier": "https://issuer.example.com",
              "issuerDisplay": null
            }
        """.trimIndent()

        val read = IssuerMetadata.fromJson(stored).getOrThrow()

        assertNull(read.embeddedDisclosurePolicy)
    }
}
