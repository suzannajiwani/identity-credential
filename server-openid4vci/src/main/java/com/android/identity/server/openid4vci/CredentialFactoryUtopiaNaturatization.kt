package com.android.identity.server.openid4vci

import com.android.identity.cbor.Cbor
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.EcPrivateKey
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.X509Cert
import com.android.identity.documenttype.knowntypes.EUPersonalID
import com.android.identity.documenttype.knowntypes.UtopiaNaturalization
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.flow.server.Resources
import com.android.identity.sdjwt.Issuer
import com.android.identity.sdjwt.SdJwtVcGenerator
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

internal class CredentialFactoryUtopiaNaturatization : CredentialFactory {
    override val offerId: String
        get() = "utopia_naturalization"

    override val scope: String
        get() = "utopia_naturalization_sd_jwt"

    override val format: Openid4VciFormat
        get() = FORMAT

    override val proofSigningAlgorithms: List<String>
        get() = listOf()  // keyless

    override val cryptographicBindingMethods: List<String>
        get() = listOf()  // keyless

    override val credentialSigningAlgorithms: List<String>
        get() = CredentialFactory.DEFAULT_CREDENTIAL_SIGNING_ALGORITHMS

    override val name: String
        get() = "Utopia Naturalization Certificate"

    override val logo: String
        get() = "naturalization.png"

    override suspend fun makeCredential(
        environment: FlowEnvironment,
        state: IssuanceState,
        authenticationKey: EcPublicKey?
    ): String {
        check(authenticationKey == null)
        val data = state.credentialData!!
        val birthdateDataElement = euPidDocumentType.mdocDocumentType!!
            .namespaces[EUPersonalID.EUPID_NAMESPACE]!!.dataElements["birth_date"]!!
        val birthdate = birthdateDataElement.renderValue(Cbor.decode(
            data.getDataElement(EUPersonalID.EUPID_NAMESPACE, "birth_date")))
        val identityAttributes = buildJsonObject {
            put("given_name", data.getDataElementString(EUPersonalID.EUPID_NAMESPACE, "given_name"))
            put("family_name", data.getDataElementString(EUPersonalID.EUPID_NAMESPACE, "family_name"))
            put("birth_date", birthdate)
            put("naturalization_date", "2024-04-01")  // Utopia Naturalization Day (aka April Fools)
        }

        val sdJwtVcGenerator = SdJwtVcGenerator(
            random = Random,
            payload = identityAttributes,
            docType = UtopiaNaturalization.VCT,
            issuer = Issuer("https://example-issuer.com", Algorithm.ES256, "key-1")
        )

        val now = Clock.System.now()

        val timeSigned = now
        val validFrom = Instant.parse("2024-04-01T12:00:00Z")
        val validUntil = Instant.parse("2034-04-01T12:00:00Z")

        sdJwtVcGenerator.timeSigned = timeSigned
        sdJwtVcGenerator.timeValidityBegin = validFrom
        sdJwtVcGenerator.timeValidityEnd = validUntil

        val resources = environment.getInterface(Resources::class)!!
        val documentSigningKeyCert =
            X509Cert.fromPem(resources.getStringResource("ds_certificate.pem")!!)
        val documentSigningKey = EcPrivateKey.fromPem(
            resources.getStringResource("ds_private_key.pem")!!,
            documentSigningKeyCert.ecPublicKey)
        val sdJwt = sdJwtVcGenerator.generateSdJwt(documentSigningKey)

        return sdJwt.toString()
    }

    companion object {
        private val FORMAT = Openid4VciFormatSdJwt(UtopiaNaturalization.VCT)

        // to decode attributes
        private val euPidDocumentType = EUPersonalID.getDocumentType()
    }
}