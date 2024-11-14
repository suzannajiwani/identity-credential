package com.android.identity.issuance

import com.android.identity.cbor.annotation.CborSerializable

@CborSerializable
data class SdJwtVcDocumentConfiguration(
    /**
     * The Verifiable Credential Type for SD-JWT VC credentials.
     */
    val vct: String,
    /**
     * If true or missing, credentials are bound to a key; if present and false credentials
     * are keyless.
     */
    val keyBound: Boolean?
)
