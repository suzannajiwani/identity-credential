package com.android.identity.android.direct_access

import com.android.identity.android.direct_access.DocumentDataParser.validateCredentialData
import com.android.identity.android.util.NfcUtil.createApduApplicationSelect
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor.encode
import com.android.identity.cbor.CborBuilder
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.MapBuilder
import com.android.identity.credential.Credential
import com.android.identity.crypto.javaX509Certificate
import com.android.identity.direct_access.DirectAccessTransport
import com.android.identity.document.Document
import com.android.identity.util.Logger.d
import com.android.identity.util.Timestamp
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.time.Duration

class DirectAccessCredential: Credential {
    companion object {
        private const val TAG = "DirectAccessCredential"

        val DIRECT_ACCESS_PROVISIONING_APPLET_ID =
            byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x02, 0x48, 0x00, 0x01, 0x01, 0x01)
        private const val CREDENTIAL_KEY_VALID_DURATION = (365 * 24 * 60 * 60 * 1000).toLong()
        private const val PROVISION_BEGIN: Byte = 0
        private const val PROVISION_UPDATE: Byte = 1
        private const val PROVISION_FINISH: Byte = 2
        private const val SLOT_0 = 0
    }

    /**
     * Constructs a new [DirectAccessCredential].
     *
     * @param document the document to add the credential to.
     * @param asReplacementFor the credential this credential will replace, if not null
     * @param domain the domain of the credential
     *  TODO
     */
    constructor(
        document: Document,
        asReplacementFor: Credential?,
        domain: String,
        docType: String,
        challenge: ByteArray,
        signingKeyMinValidDuration: Duration,
    ) : super(document, asReplacementFor, domain) {
        this.docType = docType
        this.signingKeyMinValidDuration = signingKeyMinValidDuration
        slot = getNextAvailableSlot()

        if (document.directAccessTransport == null) {
            throw IllegalStateException("In order to use DirectAccessCredentials, " +
                    "the transport must be set via the DocumentStore")
        }
        this.transport = document.directAccessTransport!!

        // TODO Remove below dummy code.
        val notBefore = System.currentTimeMillis()
        val notAfter = notBefore + CREDENTIAL_KEY_VALID_DURATION

        // Create credential key
        val apdu: ByteArray?
        val response: ByteArray?

        try {
            selectProvisionApplet()
            apdu = apduHelper.createCredentialAPDU(
                slot,
                challenge,
                notBefore,
                notAfter
            )
            response = transport.sendData(apdu)
        } catch (e: IOException) {
            throw java.lang.IllegalStateException("Failed to send createCredential APDU command")
        }

        attestation = cborHelper.decodeCredentialKeyResponse(response)
        presentationPackage = createPresentationPackage(slot)

        // Only the leaf constructor should add the credential to the document.
        if (this::class == DirectAccessCredential::class) {
            addToDocument()
        }
    }

    /**
     * Constructs a Credential from serialized data.
     *
     * @param document the [Document] that the credential belongs to.
     * @param dataItem the serialized data.
     */
    constructor(
        document: Document,
        dataItem: DataItem,
    ) : super(document, dataItem) {
        docType = dataItem["docType"].asTstr
        slot = dataItem["slot"].asNumber.toInt()
        signingKeyMinValidDuration = Duration.ofMillis(dataItem["signingKeyMinValidDuration"].asNumber)
        attestation = parseAttestation(dataItem["attestation"])
        presentationPackage = parsePresentationPackage(dataItem["presentationPackage"])

        if (document.directAccessTransport == null) {
            throw IllegalStateException("In order to use DirectAccessCredentials, " +
                    "the transport must be set via the DocumentStore")
        }
        transport = document.directAccessTransport!!
    }

    /**
     * The docType of the credential as defined in
     * [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html).
     */
    val docType: String

    private val apduHelper = DirectAccessAPDUHelper()
    private val cborHelper = DirectAccessCborHelper()
    private val signingKeyMinValidDuration: Duration
    private val transport: DirectAccessTransport
    private val slot: Int
    private val attestation: List<X509Certificate>
    val presentationPackage: PresentationPackage // todo examine whether to make private

    private fun getNextAvailableSlot(): Int {
        // Currently Applet supports only one slot.
        return SLOT_0
    }

    private fun selectProvisionApplet() {
        try {
            val selectApdu =
                createApduApplicationSelect(DIRECT_ACCESS_PROVISIONING_APPLET_ID)
            val response: ByteArray = transport.sendData(selectApdu)
            check(cborHelper.isOkResponse(response)) { "Failed to select Provision Applet" }
        } catch (e: IOException) {
            throw java.lang.IllegalStateException("Failed to send select Provision Applet APDU command")
        }
    }

    private fun createPresentationPackage(slot: Int): PresentationPackage {
        val response: ByteArray?
        val presentationPackage: PresentationPackage
        try {
            val apdu: ByteArray =
                apduHelper.createPresentationPackageAPDU(slot, signingKeyMinValidDuration)
            response = transport.sendData(apdu)
            presentationPackage = cborHelper.decodePresentationPackage(response)
        } catch (e: IOException) {
            d(TAG, "Failed to create presentation package")
            throw java.lang.IllegalStateException("Failed to create presentation package", e)
        }
        return presentationPackage
    }

    private fun parseAttestation(dataItem: DataItem) : List<X509Certificate> {
        val attestations: ArrayList<X509Certificate> = ArrayList()
        for (item in dataItem.asArray) {
            attestations.add(item.asCertificate.javaX509Certificate)
        }
        return attestations
    }

    private fun parsePresentationPackage(dataItem: DataItem) : PresentationPackage {
        val presentationPackage = PresentationPackage()
        val usageCount = dataItem["usageCount"].asNumber.toInt() // TODO ?
        presentationPackage.signingCert = parseAttestation(dataItem["authenticationKeys"])
        presentationPackage.encryptedData = dataItem["encryptedData"].asBstr
        return presentationPackage
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("docType", docType)
        builder.put("signingKeyMinValidDuration", signingKeyMinValidDuration.toMillis())
        val attestationBuilder = builder.putArray("attestation")
        for (certificate in attestation) {
            try {
                attestationBuilder.add(certificate.encoded)
            } catch (e: CertificateEncodingException) {
                throw java.lang.IllegalStateException("Error encoding certificate chain", e)
            }
        }

        val presentationPackageMap = builder.putMap("presentationPackage")
        presentationPackageMap.put("usageCount", 0) // TODO looks sus lol
        val signCertBuilder = presentationPackageMap.putArray("authenticationKeys") // TODO why multiple keys per package?
        for (certificate in presentationPackage.signingCert) {
            try {
                signCertBuilder.add(certificate.encoded)
            } catch (e: CertificateEncodingException) {
                throw java.lang.IllegalStateException("Error encoding certificate chain", e)
            }
        }
        signCertBuilder.end()
        presentationPackageMap.put("encryptedData", presentationPackage.encryptedData)
        presentationPackageMap.end()
    }

    @Throws(IOException::class)
    private fun sendApdu(
        cmd: Int,
        slot: Int,
        data: ByteArray,
        offset: Int,
        length: Int,
        operation: Byte
    ): ByteArray? {
        val beginApdu: ByteArray = apduHelper.createProvisionSwapInApdu(
            cmd, slot, data, offset, length, operation)
        val response: ByteArray = transport.sendData(beginApdu)
        return cborHelper.decodeProvisionResponse(response)
    }

    // Provisions credential data for a specific signing key request.
    //
    // The |credentialData| parameter must be CBOR conforming to the following CDDL:
    //
    //   CredentialData = {
    //     "docType": tstr,
    //     "issuerNameSpaces": IssuerNameSpaces,
    //     "issuerAuth" : IssuerAuth,
    //     "readerAccess" : ReaderAccess
    //   }
    //
    //   IssuerNameSpaces = {
    //     NameSpace => [ + IssuerSignedItemBytes ]
    //   }
    //
    //   ReaderAccess = [ * COSE_Key ]
    //
    // This data will stored on the Secure Area and used for MDOC presentations
    // using NFC data transfer in low-power mode.
    //
    // The `readerAccess` field contains a list of keys used for implementing
    // reader authentication. If this list is non-empty, reader authentication
    // is not required. Otherwise the request must be be signed and the request is
    // authenticated if, and only if, a public keys from the X.509 certificate
    // chain for the key signing the request exists in the `readerAccess` list.
    //
    // If reader authentication fails, the returned DeviceResponse shall return
    // error code 10 for the requested docType in the "documentErrors" field.
    //
    override fun certify(
        issuerProvidedAuthenticationData: ByteArray,
        validFrom: Timestamp,
        validUntil: Timestamp
    ) {
        selectProvisionApplet()
        validateCredentialData(issuerProvidedAuthenticationData)
        val bao = ByteArrayOutputStream()
        try {
            // BEGIN
            val encryptedData = presentationPackage.encryptedData
            bao.write(sendApdu(
                cmd = DirectAccessAPDUHelper.CMD_MDOC_PROVISION_DATA,
                slot = SLOT_0,
                data = encryptedData,
                offset = 0,
                length = encryptedData.size,
                operation= PROVISION_BEGIN
            ))

            // UPDATE
            val encodedCredData = encode(Bstr(issuerProvidedAuthenticationData))
            var remaining = encodedCredData.size
            var start = 0
            val maxTransmitBufSize = 512
            while (remaining > maxTransmitBufSize) {
                bao.write(sendApdu(
                    cmd = DirectAccessAPDUHelper.CMD_MDOC_PROVISION_DATA,
                    slot = SLOT_0,
                    data = encodedCredData,
                    offset = start,
                    length = maxTransmitBufSize,
                    operation = PROVISION_UPDATE
                ))
                start += maxTransmitBufSize
                remaining -= maxTransmitBufSize
            }

            // Finish
            bao.write(sendApdu(
                cmd = DirectAccessAPDUHelper.CMD_MDOC_PROVISION_DATA,
                slot = SLOT_0,
                data = encodedCredData,
                offset = start,
                length = remaining,
                operation = PROVISION_FINISH
            ))
        } catch (e: IOException) {
            throw java.lang.IllegalStateException("Failed to provision credential data $e")
        }

        // update presentation package
        presentationPackage.encryptedData = bao.toByteArray()
        // TODO expiration date + provisioned slot
        super.certify(issuerProvidedAuthenticationData, validFrom, validUntil)
    }

    fun swapIn() {
        try {
            selectProvisionApplet()
            val encryptedData = presentationPackage.encryptedData
            var remaining = encryptedData.size
            var start = 0
            val maxTransmitBufSize = 512
            // BEGIN
            sendApdu(
                DirectAccessAPDUHelper.CMD_MDOC_SWAP_IN,
                SLOT_0,
                encryptedData,
                0,
                maxTransmitBufSize,
                PROVISION_BEGIN
            )
            start += maxTransmitBufSize
            remaining -= maxTransmitBufSize

            // UPDATE
            while (remaining > maxTransmitBufSize) {
                sendApdu(
                    DirectAccessAPDUHelper.CMD_MDOC_SWAP_IN,
                    SLOT_0,
                    encryptedData,
                    start,
                    maxTransmitBufSize,
                    PROVISION_UPDATE
                )
                start += maxTransmitBufSize
                remaining -= maxTransmitBufSize
            }

            // Finish
            sendApdu(
                DirectAccessAPDUHelper.CMD_MDOC_SWAP_IN,
                SLOT_0,
                encryptedData,
                start,
                remaining,
                PROVISION_FINISH
            )
        } catch (e: IOException) {
            throw java.lang.IllegalStateException("Failed to provision credential data $e")
        }
    }
}