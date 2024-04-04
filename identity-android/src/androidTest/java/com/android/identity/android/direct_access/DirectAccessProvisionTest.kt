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

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.android.identity.document.DocumentStore
import com.android.identity.util.Timestamp
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.charset.StandardCharsets
import java.time.Duration

@RunWith(AndroidJUnit4::class)
class DirectAccessProvisionTest : DirectAccessTest() {
    @Before
    fun setup() {
        super.init(TransportType.SMARTCARDIO)
        documentStore = DocumentStore(storageEngine, secureAreaRepository, credentialFactory, mTransport)
        waitForConnection()
    }

    @After
    public override fun reset() {
        super.reset()
    }

    @Test
    fun provisionSuccess() {
        val challenge = "challenge".toByteArray()
        val document = documentStore.createDocument(mDocName)
        val pendingCredential = DirectAccessCredential(
            document,
            null,
            CREDENTIAL_DOMAIN,
            DocumentDataParser.MDL_DOC_TYPE,
            challenge,
            Duration.ofDays(365)
        )
        Assert.assertEquals(1, document.pendingCredentials.size)

        // Provision
        val issuerAuthData = DirectAccessTestUtils().createTestIssuerAuthData(
            context,
            document.pendingCredentials[0] as DirectAccessCredential, DocumentDataParser.MDL_DOC_TYPE, null
        )

        val validFrom = Timestamp.now()
        pendingCredential.certify(issuerAuthData,
            validFrom,
            Timestamp.ofEpochMilli(validFrom.toEpochMilli() + 50))
    }

    // todo is it required to fail for other doctypes?
//    @Test
//    fun createCredentialWithInvalidDocTypeThrowsIllegalArgumentException() {
//        mDocName = "myDoc"
//        val invalidDocType = "invalid-docType"
//        val challenge = "challenge".toByteArray()
//        val document = documentStore.createDocument(mDocName)
//        Assert.assertThrows("Expected to fail when invalid docType is passed.",
//            IllegalArgumentException::class.java) {
//            val pendingCredential = DirectAccessCredential(
//                document,
//                null,
//                CREDENTIAL_DOMAIN,
//                invalidDocType,
//                challenge,
//                Duration.ofDays(365)
//            )
//        }
//    }

    @Test
    fun certifyWithEmptyIssuerAuthDataThrowsIllegalArgumentException() {
        val challenge = "challenge".toByteArray()
        val document = documentStore.createDocument(mDocName)
        val pendingCredential = DirectAccessCredential(
            document,
            null,
            CREDENTIAL_DOMAIN,
            DocumentDataParser.MDL_DOC_TYPE,
            challenge,
            Duration.ofDays(365)
        )
        Assert.assertEquals(1, document.pendingCredentials.size)

        val issuerAuthData = byteArrayOf()
        val validFrom = Timestamp.now()
        Assert.assertThrows("Expected to fail when empty issuer auth is passed.",
            IllegalArgumentException::class.java) {
            pendingCredential.certify(issuerAuthData,
                validFrom,
                Timestamp.ofEpochMilli(validFrom.toEpochMilli() + 50))
        }
    }

    @Test
    fun provisionWithInvalidCredentialDataThrowsIllegalArgumentException() {
        val challenge = "challenge".toByteArray()
        val document = documentStore.createDocument(mDocName)
        val pendingCredential = DirectAccessCredential(
            document,
            null,
            CREDENTIAL_DOMAIN,
            DocumentDataParser.MDL_DOC_TYPE,
            challenge,
            Duration.ofDays(365)
        )
        Assert.assertEquals(1, document.pendingCredentials.size)

        // TODO loop through different types of invalid cbor data.
        val issuerAuthData = "invalid-cred-data".toByteArray(StandardCharsets.UTF_8)
        val validFrom = Timestamp.now()
        Assert.assertThrows("Expected to fail when empty credential data is passed.",
            IllegalArgumentException::class.java) {
            pendingCredential.certify(issuerAuthData,
                validFrom,
                Timestamp.ofEpochMilli(validFrom.toEpochMilli() + 50))
        }
    }

    @Test
    fun createCredentialWithLargeChallenge() {
        val challenge = "A".repeat(30).toByteArray()
        val document = documentStore.createDocument(mDocName)
        val pendingCredential = DirectAccessCredential(
            document,
            null,
            CREDENTIAL_DOMAIN,
            DocumentDataParser.MDL_DOC_TYPE,
            challenge,
            Duration.ofDays(365)
        )
        Assert.assertNotNull(pendingCredential)
        Assert.assertNull(documentStore.lookupDocument("_"))
    }
}