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
import com.android.identity.android.mdoc.deviceretrieval.IsoDepWrapper
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper
import com.android.identity.android.mdoc.transport.DataTransportOptions
import com.android.identity.crypto.Certificate
import com.android.identity.crypto.CertificateChain
import com.android.identity.document.DocumentStore
import com.android.identity.mdoc.connectionmethod.ConnectionMethod
import com.android.identity.mdoc.connectionmethod.ConnectionMethod.Companion.disambiguate
import com.android.identity.mdoc.response.DeviceResponseParser
import com.android.identity.mdoc.response.DeviceResponseParser.DeviceResponse
import com.android.identity.util.Constants
import com.android.identity.util.Logger
import com.android.identity.util.Timestamp
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.security.KeyPair
import java.time.Duration
import java.util.concurrent.CountDownLatch

@RunWith(AndroidJUnit4::class)
class DirectAccessPresentationTest : DirectAccessTest() {
    private var mDeviceConnectStatus = 0
    private var mError: Throwable? = null
    private var mCountDownLatch: CountDownLatch? = null
    private var mVerificationHelper: VerificationHelper? = null
    private var mConnectionMethods: List<ConnectionMethod>? = null
    private lateinit var mDeviceResponse: ByteArray
    @Before
    fun setup() {
        super.init(TransportType.SMARTCARDIO)
        mConnectionMethods = null
        mDeviceConnectStatus = DEVICE_CONNECT_STATUS_DISCONNECTED
        mError = null
        documentStore = DocumentStore(storageEngine, secureAreaRepository, credentialFactory, mTransport)
        waitForConnection()
    }

    @After
    public override fun reset() {
        Logger.d(TAG, "reset")
        documentStore.deleteDocument(mDocName)
        try {
            mTransport.closeConnection()
            mTransport.unInit()
        } catch (e: IOException) {
            Assert.fail("Unexpected Exception $e")
        }
    }

    var mResponseListener: VerificationHelper.Listener = object : VerificationHelper.Listener {
        override fun onDeviceEngagementReceived(connectionMethods: List<ConnectionMethod>) {
            mConnectionMethods = disambiguate(connectionMethods)
            mCountDownLatch!!.countDown()
        }

        override fun onReaderEngagementReady(readerEngagement: ByteArray) {}
        override fun onMoveIntoNfcField() {}
        override fun onDeviceConnected() {
            mDeviceConnectStatus = DEVICE_CONNECT_STATUS_CONNECTED
        }

        override fun onDeviceDisconnected(transportSpecificTermination: Boolean) {
            mDeviceConnectStatus = DEVICE_CONNECT_STATUS_DISCONNECTED
            mCountDownLatch!!.countDown()
        }

        override fun onResponseReceived(deviceResponseBytes: ByteArray) {
            mDeviceResponse = deviceResponseBytes
            mCountDownLatch!!.countDown()
        }

        override fun onError(error: Throwable) {
            mError = error
            mCountDownLatch!!.countDown()
        }
    }

    private fun parseDeviceResponse(deviceResponse: ByteArray): DeviceResponse {
        val parser = DeviceResponseParser(deviceResponse, mVerificationHelper!!.sessionTranscript)
        parser.setEphemeralReaderKey(mVerificationHelper!!.eReaderKey)
        return parser.parse()
    }

    private fun resetLatch() {
        mCountDownLatch = CountDownLatch(1)
    }

    private fun waitForResponse(expectedDeviceConnectionStatus: Int) {
        try {
            mCountDownLatch!!.await()
        } catch (e: InterruptedException) {
            // do nothing
        }
        checkSessionStatus(expectedDeviceConnectionStatus)
    }

    private fun checkSessionStatus(expectedDeviceStatus: Int) {
        Assert.assertEquals(
            "Device connection status ",
            expectedDeviceStatus.toLong(),
            mDeviceConnectStatus.toLong()
        )
        if (mError != null) {
            Assert.fail(mError!!.message)
        }
    }

    private fun generateReaderCerts(isSelfSigned: Boolean) {
        try {
            val keyPair = DirectAccessTestUtils().generateReaderKeyPair()
            val readerCertChain =
                DirectAccessTestUtils().getReaderCertificateChain(context, keyPair, isSelfSigned)
            mReaderKeys = ArrayList()
            mReaderKeys.add(keyPair)
            mReaderCertChain = HashMap()
            mReaderCertChain[keyPair] = readerCertChain
        } catch (e: Exception) {
            Assert.fail(e.message)
        }
    }

    private fun provisionAndSwapIn() {
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
        var cert: ArrayList<Certificate>? = null
        if (mReaderCertChain != null) {
            cert = ArrayList()
            for ((key, certChain) in mReaderCertChain) {
                if (certChain != null && certChain.certificates.size > 0) {
                    cert.add(certChain.certificates[0]) // Add leaf public key
                }
            }
        }
        val issuerAuthData = DirectAccessTestUtils().createTestIssuerAuthData(
            context,
            document.pendingCredentials[0] as DirectAccessCredential, DocumentDataParser.MDL_DOC_TYPE, cert
        )
        val validFrom = Timestamp.now()
        pendingCredential.certify(issuerAuthData,
            validFrom,
            Timestamp.ofEpochMilli(validFrom.toEpochMilli() + 50))

        // Set data
        pendingCredential.swapIn()
    }

    @Test
    fun testPresentation() {
        generateReaderCerts(true)
        provisionAndSwapIn()
        val builder = VerificationHelper.Builder(
            context, mResponseListener,
            context.mainExecutor
        )
        val options = DataTransportOptions.Builder().setBleClearCache(false)
            .setBleClearCache(false).build()
        builder.setDataTransportOptions(options)
        mVerificationHelper = builder.build()
        val wrapper: IsoDepWrapper = ShadowIsoDep(mTransport)
        resetLatch()
        mVerificationHelper!!.mockTagDiscovered(wrapper)
        // Wait till the device engagement is received.
        waitForResponse(DEVICE_CONNECT_STATUS_DISCONNECTED)
        Assert.assertNotNull(mConnectionMethods)
        Assert.assertTrue(mConnectionMethods!!.size > 0)
        mVerificationHelper!!.connect(mConnectionMethods!![0])
        var devReq: ByteArray? = null
        try {
            var readerKeypair: KeyPair? = null
            var certChain: CertificateChain? = null
            if (mReaderKeys != null) {
                readerKeypair = mReaderKeys[0]
                certChain = mReaderCertChain[mReaderKeys[0]]
            }
            devReq = DirectAccessTestUtils().createMdocRequest(
                readerKeypair!!,
                certChain!!,
                entries,
                mVerificationHelper!!.sessionTranscript
            )
        } catch (e: Exception) {
            Assert.fail(e.message)
        }
        resetLatch()
        mVerificationHelper!!.sendRequest(devReq!!)
        // Wait till the mdoc response is received.
        waitForResponse(DEVICE_CONNECT_STATUS_CONNECTED)
        Assert.assertNotNull(mDeviceResponse)
        val dr = parseDeviceResponse(mDeviceResponse)
        Assert.assertNotNull(dr)
        Assert.assertEquals(Constants.DEVICE_RESPONSE_STATUS_OK, dr.status)
        DirectAccessTestUtils().validateMdocResponse(dr, entries)
        resetLatch()
        mVerificationHelper!!.disconnect()
    }

    companion object {
        private const val TAG = "DirectAccessPresentationTest"
        private const val DEVICE_CONNECT_STATUS_DISCONNECTED = 0
        private const val DEVICE_CONNECT_STATUS_CONNECTED = 1
        private val entries = arrayOf<String>(
            "sex", "portrait", "given_name", "issue_date",
            "expiry_date", "family_name", "document_number", "issuing_authority"
        )
    }
}