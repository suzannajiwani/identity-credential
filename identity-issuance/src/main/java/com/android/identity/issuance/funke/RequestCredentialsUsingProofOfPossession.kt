package com.android.identity.issuance.funke

import com.android.identity.cbor.annotation.CborSerializable
import com.android.identity.flow.annotation.FlowMethod
import com.android.identity.flow.annotation.FlowState
import com.android.identity.flow.server.FlowEnvironment
import com.android.identity.issuance.CredentialConfiguration
import com.android.identity.issuance.CredentialFormat
import com.android.identity.issuance.CredentialRequest
import com.android.identity.issuance.KeyPossessionChallenge
import com.android.identity.issuance.KeyPossessionProof
import com.android.identity.issuance.RequestCredentialsFlow
import com.android.identity.util.toBase64Url
import kotlinx.datetime.Clock
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@FlowState(
    flowInterface = RequestCredentialsFlow::class
)
@CborSerializable
class RequestCredentialsUsingProofOfPossession(
    val issuanceClientId: String,
    documentId: String,
    credentialConfiguration: CredentialConfiguration,
    nonce: String,
    val credentialIssuerUri: String,
    format: CredentialFormat? = null,
    var credentialRequests: List<ProofOfPossessionCredentialRequest>? = null,
) : AbstractRequestCredentials(documentId, credentialConfiguration, nonce, format) {
    companion object

    @FlowMethod
    fun getCredentialConfiguration(
        env: FlowEnvironment,
        format: CredentialFormat
    ): CredentialConfiguration {
        this.format = format
        return credentialConfiguration
    }

    @FlowMethod
    fun sendCredentials(
        env: FlowEnvironment,
        newCredentialRequests: List<CredentialRequest>
    ): List<KeyPossessionChallenge> {
        if (credentialRequests != null) {
            throw IllegalStateException("Credentials were already sent")
        }
        val requests = newCredentialRequests.map { request ->
            val header = JsonObject(mapOf(
                "typ" to JsonPrimitive("openid4vci-proof+jwt"),
                "alg" to JsonPrimitive("ES256"),
                "jwk" to request.secureAreaBoundKeyAttestation.publicKey.toJson(null)
            )).toString().toByteArray().toBase64Url()
            val body = JsonObject(mapOf(
                "iss" to JsonPrimitive(issuanceClientId),
                "aud" to JsonPrimitive(credentialIssuerUri),
                "iat" to JsonPrimitive(Clock.System.now().epochSeconds),
                "nonce" to JsonPrimitive(nonce)
            )).toString().toByteArray().toBase64Url()
            ProofOfPossessionCredentialRequest(request, format!!, "$header.$body")
        }
        credentialRequests = requests
        return requests.map {
            KeyPossessionChallenge(ByteString(it.proofOfPossessionJwtHeaderAndBody.toByteArray()))
        }
    }

    @FlowMethod
    fun sendPossessionProofs(env: FlowEnvironment, keyPossessionProofs: List<KeyPossessionProof>) {
        if (keyPossessionProofs.size != credentialRequests?.size) {
            throw IllegalStateException("wrong number of key possession proofs: ${keyPossessionProofs.size}")
        }
        credentialRequests!!.zip(keyPossessionProofs).map {
            it.first.proofOfPossessionJwtSignature = it.second.signature.toByteArray().toBase64Url()
        }
    }
}