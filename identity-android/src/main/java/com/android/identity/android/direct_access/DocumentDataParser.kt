/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.android.direct_access

import android.icu.util.Calendar
import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.CborInt
import com.android.identity.cbor.CborMap
import com.android.identity.cbor.DataItem
import com.android.identity.cbor.RawCbor
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.Uint
import com.android.identity.cbor.toDataItem
import com.android.identity.cose.Cose
import com.android.identity.cose.Cose.coseSign1Sign
import com.android.identity.cose.CoseNumberLabel
import com.android.identity.cose.CoseSign1
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Certificate
import com.android.identity.crypto.CertificateChain
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.EcPublicKey
import com.android.identity.crypto.javaPublicKey
import com.android.identity.crypto.toEcPrivateKey
import com.android.identity.document.NameSpacedData
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.util.MdocUtil
import com.android.identity.util.Logger
import com.android.identity.util.Timestamp.Companion.now
import com.android.identity.util.Timestamp.Companion.ofEpochMilli
import java.security.KeyPair
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.Arrays
import java.util.Random
import java.util.function.Consumer

object DocumentDataParser {
    private const val TAG = "DocumentDataParser"

    const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
    const val MDL_NAMESPACE = "org.iso.18013.5.1"
    const val CRED_DATA_KEY_DOC_TYPE = "docType"
    const val CRED_DATA_KEY_ISSUER_NAMESPACES = "issuerNameSpaces"
    const val CRED_DATA_KEY_ISSUER_AUTH = "issuerAuth"
    const val ISSUER_SIGNED_ITEM_KEY_DIGEST_ID = "digestID"
    const val ISSUER_SIGNED_ITEM_KEY_RANDOM = "random"
    const val ISSUER_SIGNED_ITEM_KEY_ELE_ID = "elementIdentifier"
    const val ISSUER_SIGNED_ITEM_KEY_ELE_VAL = "elementValue"
    fun generateCredentialData(
        docType: String, nameSpacedData: NameSpacedData,
        authKey: EcPublicKey, issuerAuthorityKeyPair: KeyPair,
        issuerAuthorityCertificate: X509Certificate, readerCerts: ArrayList<Certificate>?
    ): ByteArray {
        val issuerSignedMapping = generateIssuerNamespaces(
            nameSpacedData
        )
        val encodedIssuerAuth = createMobileSecurityObject(
            docType, authKey,
            issuerSignedMapping, issuerAuthorityKeyPair, issuerAuthorityCertificate
        )
        val outerBuilder = CborMap.builder()
        for (namespace in issuerSignedMapping.keys) {
            val innerBuilder = outerBuilder.putArray(namespace)
            for (encodedIssuerSignedItemMetadata in issuerSignedMapping[namespace]!!) {
                innerBuilder.add(Cbor.decode(encodedIssuerSignedItemMetadata))
            }
        }
        val issuerNamespacesItem = outerBuilder.end().build()
        // reader keys
        val readerBuilder = CborArray.builder()
        if (readerCerts != null) {
            for (cert in readerCerts) {
                val pubKey = getAndFormatRawPublicKey(cert)
                readerBuilder.add(pubKey!!)
            }
        }
        val readerAuth = readerBuilder.end().build()
        return Cbor.encode(
            CborMap.builder().put("docType", docType)
                .put("issuerNameSpaces", issuerNamespacesItem)
                .put("issuerAuth", RawCbor(encodedIssuerAuth))
                .put("readerAccess", readerAuth)
                .end().build()
        )
    }

    @JvmStatic
    fun validateCredentialData(encodedCredentialData: ByteArray?) {
        val credentialDataItem = Cbor.decode(encodedCredentialData!!)
        val credDataItemMap = CborMap(credentialDataItem.asMap.toMutableMap(), false)
        require(credentialDataItem.asMap.keys.size == 4) { "CredentialData must have a size of 4" }
        val docType = credDataItemMap[CRED_DATA_KEY_DOC_TYPE].asTstr
        require(docType.compareTo(MDL_DOC_TYPE) == 0) { "Given docType '$docType' != '$MDL_DOC_TYPE'" }
        require(credDataItemMap.hasKey(CRED_DATA_KEY_ISSUER_NAMESPACES)) { "Missing 'issuerNamespaces' in CredentialDat" }
        val issuerNamespaces = getIssuerNamespaces(credentialDataItem)
        require(credDataItemMap.hasKey(CRED_DATA_KEY_ISSUER_AUTH)) { "Missing 'issuerAuth' in CredentialDat" }
        validateIssuerAuth(docType, credDataItemMap, issuerNamespaces)
    }

    fun validateIssuerAuth(
        expectedDocType: String, credDataItemMap: CborMap,
        issuerNamespaces: HashMap<String, List<ByteArray>>
    ): EcPublicKey {
        val issuerAuthDataItem = credDataItemMap["issuerAuth"]
        val issuerAuthorityCertChain = Cbor.encode(issuerAuthDataItem).toDataItem.asCertificateChain.certificates
        require(issuerAuthorityCertChain.size >= 1) { "No x5chain element in issuer signature" }
        val issuerAuthCoseSign1 = issuerAuthDataItem.asCoseSign1
        val encodedMobileSecurityObject = Cbor.decode(issuerAuthCoseSign1.payload!!).asTagged.asBstr
        val parsedMso = MobileSecurityObjectParser(encodedMobileSecurityObject).parse()

        /* don't care about version for now */
        val digestAlgorithm = parsedMso.digestAlgorithm
        val digester: MessageDigest
        digester = try {
            MessageDigest.getInstance(digestAlgorithm)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Failed creating digester")
        }
        val msoDocType = parsedMso.docType
        require(msoDocType == expectedDocType) { "docType in MSO '$msoDocType' does not match docType from Document" }
        val nameSpaceNames = parsedMso.valueDigestNamespaces
        val digestMapping: MutableMap<String, Map<Long, ByteArray>?> = HashMap()
        for (nameSpaceName in nameSpaceNames) {
            digestMapping[nameSpaceName] = parsedMso.getDigestIDs(nameSpaceName)
        }
        val deviceKey = parsedMso.deviceKey
        for (nameSpace in issuerNamespaces.keys) {
            val innerDigestMapping = digestMapping[nameSpace]
                ?: throw IllegalArgumentException("No digestID MSO entry for namespace $nameSpace")
            val byteArrayList = issuerNamespaces[nameSpace]!!
            for (byteArr in byteArrayList) {
                val elem = Cbor.decode(byteArr)
                // We need the encoded representation with the tag.
                val encodedIssuerSignedItemBytes = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, elem))
                val expectedDigest = digester.digest(encodedIssuerSignedItemBytes)
                val issuerSignedItem = CborMap(Cbor.decode(elem.asTagged.asBstr).asMap.toMutableMap(), false)
                val elementName = issuerSignedItem["elementIdentifier"].asTstr
                val elementValue = issuerSignedItem["elementValue"]
                val digestId = issuerSignedItem["digestID"].asNumber
                val digest = innerDigestMapping[digestId]
                    ?: throw IllegalArgumentException(
                        "No digestID MSO entry for ID $digestId in namespace $nameSpace"
                    )
//                require(Arrays.equals(expectedDigest, digest)) {
//                    ("Digest mismatch between issuerSignedDataItem and" + "isserAuth for element id:"
//                            + elementName + "\nexpected digest: " + expectedDigest + " digest: " + digest)
//                }
            }
        }
        return deviceKey
    }

    fun getIssuerNamespaces(credentialDataItem: DataItem): HashMap<String, List<ByteArray>> {
        val issuerNamespaces = HashMap<String, List<ByteArray>>()
        val namespaceItems =
            CborMap(credentialDataItem[CRED_DATA_KEY_ISSUER_NAMESPACES].asMap.toMutableMap(), false)
        for (namespaceDataItem in namespaceItems.items.keys) {
            val namespace = namespaceDataItem.asTstr
            val namespaceList = namespaceItems[namespace].asArray
            val innerArray: MutableList<ByteArray> = ArrayList()
            for (innerKey in namespaceList) {
                val issuerSignedItem = innerKey.asTaggedEncodedCbor
                for (issuerSignedItemKeyDI in issuerSignedItem.asMap.keys) {
                    val issuerSignedItemKey = issuerSignedItemKeyDI.asTstr
                    when (issuerSignedItemKey) {
                        ISSUER_SIGNED_ITEM_KEY_DIGEST_ID, ISSUER_SIGNED_ITEM_KEY_RANDOM, ISSUER_SIGNED_ITEM_KEY_ELE_ID, ISSUER_SIGNED_ITEM_KEY_ELE_VAL -> {}
                        else -> throw IllegalArgumentException(
                            "Not a valid key in IssuerSignedItem: $issuerSignedItemKey"
                        )
                    }
                }
                innerArray.add(Cbor.encode(innerKey))
            }
            issuerNamespaces[namespace] = innerArray
        }
        return issuerNamespaces
    }

    private fun generateIssuerNamespaces(
        nameSpacedData: NameSpacedData
    ): Map<String, List<ByteArray>> {
        return MdocUtil.generateIssuerNameSpaces(
            nameSpacedData,
            kotlin.random.Random.Default,
            16,
            null
        )
    }

    private fun createMobileSecurityObject(
        docType: String,
        authKey: EcPublicKey,
        issuerSignedMapping: Map<String, List<ByteArray>>,
        issuerAuthorityKeyPair: KeyPair,
        issuerAuthorityCertificate: X509Certificate
    ): ByteArray {
        val signedDate = now()
        val validFromDate = now()
        val validToCalendar = Calendar.getInstance()
        validToCalendar.add(Calendar.MONTH, 12)
        val validToDate = ofEpochMilli(validToCalendar.timeInMillis)
        val msoGenerator = MobileSecurityObjectGenerator(
            "SHA-256",
            docType, authKey
        ).setValidityInfo(signedDate, validFromDate, validToDate, null)

        val vdInner: MutableMap<Long, ByteArray> = HashMap()

        issuerSignedMapping.forEach { (ns: String?, issuerSignedItems: List<ByteArray>) ->

            val digests = MdocUtil.calculateDigestsForNameSpace(
                ns,
                issuerSignedMapping,
                Algorithm.SHA256
            )

            msoGenerator.addDigestIdsForNamespace(ns, digests)
        }
        val encodedMobileSecurityObject = msoGenerator.generate()
        val taggedEncodedMso = Cbor.encode(
            Tagged(Tagged.ENCODED_CBOR, Bstr(encodedMobileSecurityObject))
        )

        return Cbor.encode(coseSign1Sign(
                issuerAuthorityKeyPair.private.toEcPrivateKey(issuerAuthorityKeyPair.public, EcCurve.P256),
                taggedEncodedMso,
                true,
                Algorithm.ES256,
                mapOf(
                    Pair(
                        CoseNumberLabel(Cose.COSE_LABEL_ALG),
                        Algorithm.ES256.coseAlgorithmIdentifier.toDataItem
                    )
                ),
                mapOf(
                    Pair(
                        CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN),
                        CertificateChain(listOf(Certificate(issuerAuthorityCertificate.encoded))).toDataItem
                    )
                )
            ).toDataItem)

    }

    private fun getAndFormatRawPublicKey(cert: Certificate): ByteArray {
        val pubKey = cert.publicKey
        val key = cert.publicKey.javaPublicKey as ECPublicKey
        // s: 1 byte, x: 32 bytes, y: 32 bytes
        val xCoord = key.w.affineX
        val yCoord = key.w.affineY
        val formattedKey = ByteArray(65)
        var offset = 0
        formattedKey[offset++] = 0x04
        val xBytes = xCoord.toByteArray()
        // BigInteger returns the value as two's complement big endian byte encoding. This means
        // that a positive, 32-byte value with a leading 1 bit will be converted to a byte array of
        // length 33 in order to include a leading 0 bit.
        if (xBytes.size == 33) {
            System.arraycopy(xBytes, 1 /* offset */, formattedKey, offset, 32)
        } else {
            System.arraycopy(
                xBytes, 0 /* offset */,
                formattedKey, offset + 32 - xBytes.size, xBytes.size
            )
        }
        val yBytes = yCoord.toByteArray()
        if (yBytes.size == 33) {
            System.arraycopy(yBytes, 1 /* offset */, formattedKey, offset + 32 /* offset */, 32)
        } else {
            System.arraycopy(
                yBytes, 0 /* offset */,
                formattedKey, offset + 64 - yBytes.size, yBytes.size
            )
        }
        return formattedKey
    }
}