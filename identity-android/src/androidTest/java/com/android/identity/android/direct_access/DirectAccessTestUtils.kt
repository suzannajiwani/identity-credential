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

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.security.keystore.KeyProperties
import com.android.identity.R
import com.android.identity.cbor.Cbor
import com.android.identity.cbor.CborArray
import com.android.identity.cbor.Tagged
import com.android.identity.cbor.Tstr
import com.android.identity.crypto.Algorithm
import com.android.identity.crypto.Certificate
import com.android.identity.crypto.CertificateChain
import com.android.identity.crypto.EcCurve
import com.android.identity.crypto.toEcPrivateKey
import com.android.identity.crypto.toEcPublicKey
import com.android.identity.document.NameSpacedData
import com.android.identity.mdoc.request.DeviceRequestGenerator
import com.android.identity.mdoc.response.DeviceResponseParser
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.EncodedKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Date
import javax.security.auth.x500.X500Principal

class DirectAccessTestUtils {
    private val TAG = "DirectAccessTest"
    @get:Throws(
        NoSuchAlgorithmException::class,
        InvalidKeySpecException::class
    )
    private val readerCAPrivateKey: PrivateKey
        private get() {
            // TODO: should get private key from KeysAndCertificates class instead of
            //  hard-coding it here.
            val keyBytes = Base64.getDecoder()
                .decode(
                    "ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDCI6BG/yRDzi307Rqq2Ndw5mYi2y4MR+n6IDqjl2Qw/Sdy8D5eCzp8mlcL/vCWnEq0="
                )
            val spec: EncodedKeySpec = PKCS8EncodedKeySpec(keyBytes)
            val kf = KeyFactory.getInstance("EC")
            return kf.generatePrivate(spec)
        }

    @Throws(CertificateException::class)
    private fun getGoogleRootCa(context: Context): X509Certificate {
        val certInputStream = context.resources.openRawResource(R.raw.google_reader_ca)
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(certInputStream) as X509Certificate
    }

    @Throws(Exception::class)
    private fun generateEcdsaKeyPair(): KeyPair {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME)
        val ecSpec = ECGenParameterSpec(EcCurve.P256.SECGName)
        kpg.initialize(ecSpec)
        return kpg.generateKeyPair()
    }

    @Throws(Exception::class)
    fun generateReaderKeyPair(): KeyPair {
        return generateEcdsaKeyPair()
    }

    @Throws(Exception::class)
    private fun generateIssuingAuthorityKeyPair(): KeyPair {
        return generateEcdsaKeyPair()
    }

    @Throws(Exception::class)
    private fun getSelfSignedIssuerAuthorityCertificate(
        issuerAuthorityKeyPair: KeyPair
    ): X509Certificate {
        val issuer =
            X500Name("CN=State Of Utopia")
        val subject =
            X500Name("CN=State Of Utopia Issuing Authority Signing Key")

        // Valid from now to five years from now.
        val now = Date()
        val kMilliSecsInOneYear = 365L * 24 * 60 * 60 * 1000
        val expirationDate = Date(now.time + 5 * kMilliSecsInOneYear)
        val serial = BigInteger("42")
        val builder = JcaX509v3CertificateBuilder(
            issuer, serial, now,
            expirationDate, subject, issuerAuthorityKeyPair.public
        )
        val signer: ContentSigner =
            JcaContentSignerBuilder("SHA256withECDSA").build(
                issuerAuthorityKeyPair.private
            )
        val encodedCert: ByteArray = builder.build(signer).encoded
        val cf =
            CertificateFactory.getInstance("X.509")
        val bais = ByteArrayInputStream(encodedCert)
        return cf.generateCertificate(bais) as X509Certificate
    }

    private fun getDocumentData(context: Context): HashMap<String, FieldMdl> {
        val bitmapPortrait = BitmapFactory.decodeResource(
            context.resources,
            R.drawable.img_erika_portrait
        )
        val baos = ByteArrayOutputStream()
        bitmapPortrait.compress(Bitmap.CompressFormat.JPEG, 50, baos)
        val portrait = baos.toByteArray()
        val bitmapSignature = BitmapFactory.decodeResource(
            context.resources,
            R.drawable.img_erika_signature
        )
        baos.reset()
        bitmapSignature.compress(Bitmap.CompressFormat.JPEG, 50, baos)
        val signature = baos.toByteArray()
        val biometric_template = Bitmap.createBitmap(200, 200, Bitmap.Config.ARGB_8888)
        baos.reset()
        biometric_template.compress(Bitmap.CompressFormat.JPEG, 50, baos)
        val biometric = baos.toByteArray()
        val fieldsMdl = HashMap<String, FieldMdl>()
        fieldsMdl["given_name"] = FieldMdl("given_name", FieldTypeMdl.STRING, "Erika")
        fieldsMdl["family_name"] = FieldMdl("family_name", FieldTypeMdl.STRING, "Mustermann")
        fieldsMdl["birth_date"] = FieldMdl("birth_date", FieldTypeMdl.STRING, "1971-09-01")
        fieldsMdl["issue_date"] = FieldMdl("issue_date", FieldTypeMdl.STRING, "2021-04-18")
        fieldsMdl["expiry_date"] = FieldMdl("expiry_date", FieldTypeMdl.STRING, "2026-04-18")
        fieldsMdl["portrait"] = FieldMdl("portrait", FieldTypeMdl.STRING, portrait)
        fieldsMdl["issuing_country"] = FieldMdl("issuing_country", FieldTypeMdl.STRING, "US")
        fieldsMdl["issuing_authority"] =
            FieldMdl("issuing_authority", FieldTypeMdl.STRING, "Google")
        fieldsMdl["document_number"] = FieldMdl("document_number", FieldTypeMdl.STRING, "987654321")
        fieldsMdl["signature_usual_mark"] =
            FieldMdl("signature_usual_mark", FieldTypeMdl.BITMAP, signature)
        fieldsMdl["biometric_template_signature_sign"] =
            FieldMdl("biometric_template_signature_sign", FieldTypeMdl.BITMAP, biometric)
        fieldsMdl["biometric_template_iris"] =
            FieldMdl("biometric_template_iris", FieldTypeMdl.BITMAP, biometric)
        fieldsMdl["un_distinguishing_sign"] =
            FieldMdl("un_distinguishing_sign", FieldTypeMdl.STRING, "US")
        fieldsMdl["age_over_18"] = FieldMdl("age_over_18", FieldTypeMdl.BOOLEAN, "true")
        fieldsMdl["age_over_21"] = FieldMdl("age_over_21", FieldTypeMdl.BOOLEAN, "true")
        fieldsMdl["sex"] = FieldMdl("sex", FieldTypeMdl.STRING, "2")
        fieldsMdl["vehicle_category_code_1"] =
            FieldMdl("vehicle_category_code_1", FieldTypeMdl.STRING, "A")
        fieldsMdl["issue_date_1"] = FieldMdl("issue_date_1", FieldTypeMdl.DATE, "2018-08-09")
        fieldsMdl["expiry_date_1"] = FieldMdl("expiry_date_1", FieldTypeMdl.DATE, "2024-10-20")
        fieldsMdl["vehicle_category_code_2"] =
            FieldMdl("vehicle_category_code_2", FieldTypeMdl.STRING, "B")
        fieldsMdl["issue_date_2"] = FieldMdl("issue_date_2", FieldTypeMdl.DATE, "2017-02-23")
        fieldsMdl["expiry_date_2"] = FieldMdl("expiry_date_2", FieldTypeMdl.DATE, "2024-10-20")
        return fieldsMdl
    }

    private fun getNameSpacedData(
        context: Context,
    ): NameSpacedData {
        val nsBuilder = NameSpacedData.Builder()
        val hashMap = getDocumentData(context)

        val birthDate = Tagged(1004, Tstr(hashMap["birth_date"]!!.valueString))
        val issueDate = Tagged(1004, Tstr(hashMap["issue_date"]!!.valueString))
        val expiryDate = Tagged(1004, Tstr(hashMap["expiry_date"]!!.valueString))

        val issueDateCatA = Tagged(1004, Tstr(hashMap["issue_date_1"]!!.valueString))
        val expiryDateCatA = Tagged(1004, Tstr(hashMap["expiry_date_1"]!!.valueString))
        val issueDateCatB = Tagged(1004, Tstr(hashMap["issue_date_2"]!!.valueString))
        val expiryDateCatB = Tagged(1004, Tstr(hashMap["expiry_date_2"]!!.valueString))

        val drivingPrivileges = CborArray.Companion.builder().addMap()
            .put("vehicle_category_code", hashMap["vehicle_category_code_1"]!!.valueString)
            .put("issue_date", issueDateCatA)
            .put("expiry_date", expiryDateCatA).end()
            .addMap()
            .put("vehicle_category_code", hashMap["vehicle_category_code_2"]!!.valueString)
            .put("issue_date", issueDateCatB)
            .put("expiry_date", expiryDateCatB).end().end().build()

        nsBuilder.putEntryString(
            DocumentDataParser.MDL_NAMESPACE,
            "given_name",
            hashMap["given_name"]!!.valueString
        )
        nsBuilder.putEntryString(
            DocumentDataParser.MDL_NAMESPACE,
            "family_name",
            hashMap["family_name"]!!.valueString
        )
        nsBuilder.putEntry(DocumentDataParser.MDL_NAMESPACE, "birth_date", Cbor.encode(birthDate))
        nsBuilder.putEntryByteString(
            DocumentDataParser.MDL_NAMESPACE,
            "portrait",
            hashMap["portrait"]!!.valueBitmapBytes
        )
        nsBuilder.putEntry(DocumentDataParser.MDL_NAMESPACE, "issue_date", Cbor.encode(issueDate))
        nsBuilder.putEntry(DocumentDataParser.MDL_NAMESPACE, "expiry_date", Cbor.encode(expiryDate))
        nsBuilder.putEntryString(
            DocumentDataParser.MDL_NAMESPACE,
            "issuing_country",
            hashMap["issuing_country"]!!.valueString
        )
        nsBuilder.putEntryString(
            DocumentDataParser.MDL_NAMESPACE,
            "issuing_authority",
            hashMap["issuing_authority"]!!.valueString
        )
        nsBuilder.putEntryString(
            DocumentDataParser.MDL_NAMESPACE,
            "document_number",
            hashMap["document_number"]!!.valueString
        )
        nsBuilder.putEntry(
            DocumentDataParser.MDL_NAMESPACE,
            "driving_privileges",
            Cbor.encode(drivingPrivileges)
        )
        nsBuilder.putEntryString(
            DocumentDataParser.MDL_NAMESPACE,
            "un_distinguishing_sign",
            hashMap["un_distinguishing_sign"]!!.valueString
        )
        nsBuilder.putEntryBoolean(
            DocumentDataParser.MDL_NAMESPACE,
            "age_over_18",
            hashMap["age_over_18"]!!.valueBoolean
        )
        nsBuilder.putEntryBoolean(
            DocumentDataParser.MDL_NAMESPACE,
            "age_over_21",
            hashMap["age_over_21"]!!.valueBoolean
        )
        nsBuilder.putEntryByteString(
            DocumentDataParser.MDL_NAMESPACE,
            "signature_usual_mark",
            hashMap["signature_usual_mark"]!!.valueBitmapBytes
        )
        nsBuilder.putEntryByteString(
            DocumentDataParser.MDL_NAMESPACE,
            "biometric_template_iris",
            hashMap["biometric_template_iris"]!!.valueBitmapBytes
        )
        nsBuilder.putEntryByteString(
            DocumentDataParser.MDL_NAMESPACE,
            "biometric_template_signature_sign",
            hashMap["biometric_template_signature_sign"]!!.valueBitmapBytes
        )
        nsBuilder.putEntryNumber(
            DocumentDataParser.MDL_NAMESPACE,
            "sex",
            Integer.valueOf(hashMap["sex"]!!.valueString).toLong()
        )

        return nsBuilder.build()
    }

    fun createTestIssuerAuthData(
        context: Context,
        credential: DirectAccessCredential,
        docType: String, readerPublicKeys: ArrayList<Certificate>?
    ): ByteArray {
        return try {
            val issuerKeypair = generateIssuingAuthorityKeyPair()
            DocumentDataParser.generateTestIssuerAuthData(
                docType,
                getNameSpacedData(context),
                credential.presentationPackage.signingCert[0].publicKey.toEcPublicKey(EcCurve.P256),
                issuerKeypair,
                getSelfSignedIssuerAuthorityCertificate(issuerKeypair),
                readerPublicKeys
            )
        } catch (e: Exception) {
            throw IllegalStateException("Failed to create CredentialData error: " + e.message)
        }
    }

    fun validateMdocResponse(response: DeviceResponseParser.DeviceResponse, entries: Array<String>): Boolean {
        val documentList: List<DeviceResponseParser.Document> = response.documents
        for (doc in documentList) {
            for (eleId in entries) {
                doc.getIssuerEntryData(DocumentDataParser.MDL_NAMESPACE, eleId)
            }
        }
        return true
    }

    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    fun createMdocRequest(
        readerKey: KeyPair,
        readerKeyCertChain: CertificateChain,
        reqIds: Array<String>,
        sessionTranscript: ByteArray
    ): ByteArray {
        val mdlNamespace: MutableMap<String, Map<String, Boolean>> = HashMap()
        val entries: MutableMap<String, Boolean> = HashMap()
        for (eleId in reqIds) {
            entries[eleId] = false
        }
        // entries.put("sex", false);
        // entries.put("portrait", false);
        // entries.put("given_name", false);
        // entries.put("issue_date", false);
        // entries.put("expiry_date", false);
        // entries.put("family_name", false);
        // entries.put("document_number", false);
        // entries.put("issuing_authority", false);
        mdlNamespace[DocumentDataParser.MDL_NAMESPACE] = entries
        var signature: Signature? = null
        if (readerKey != null) {
            signature = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider())
            signature.initSign(readerKey.private)
        }
        val generator = DeviceRequestGenerator(sessionTranscript)
        generator.addDocumentRequest(
            DocumentDataParser.MDL_DOC_TYPE,
            mdlNamespace,
            null,
            readerKey.private.toEcPrivateKey(readerKey.public, EcCurve.P256),
            Algorithm.ES256,
            readerKeyCertChain
        )
        return generator.generate()
    }

    @Throws(Exception::class)
    fun getReaderCertificateChain(
        context: Context?,
        readerKey: KeyPair, isSelfSigned: Boolean
    ): CertificateChain? {
        var certChain: CertificateChain? = null
        // TODO support for signing with Google root CA.
        val issuer = X500Principal("CN=SelfSigned, O=Android, C=US")
        val subject = X500Principal("CN=Subject, O=Android, C=US")
        // Make the certificate valid for two days.
        val millisPerDay = (24 * 60 * 60 * 1000).toLong()
        val now = System.currentTimeMillis()
        val start = Date(now - millisPerDay)
        val end = Date(now + millisPerDay)
        val serialBytes = ByteArray(16)
        SecureRandom().nextBytes(serialBytes)
        val serialNumber = BigInteger(1, serialBytes)
        val x509cg = X509v3CertificateBuilder(
            X500Name.getInstance(issuer.encoded),
            serialNumber,
            start,
            end,
            X500Name.getInstance(subject.encoded),
            SubjectPublicKeyInfo.getInstance(readerKey.public.encoded)
        )
        val x509holder: X509CertificateHolder = x509cg.build(
            JcaContentSignerBuilder("SHA256withECDSA")
                .build(readerKey.private)
        )
        val certFactory = CertificateFactory.getInstance("X.509")
        val x509c = certFactory.generateCertificate(
            ByteArrayInputStream(x509holder.encoded)
        ) as X509Certificate
        certChain = CertificateChain(listOf(Certificate(x509c.encoded)))
        return certChain
    }
}