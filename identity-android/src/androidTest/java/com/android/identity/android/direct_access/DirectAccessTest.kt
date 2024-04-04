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
import android.se.omapi.SEService
import com.android.identity.android.securearea.AndroidKeystoreSecureArea
import com.android.identity.android.storage.AndroidStorageEngine
import com.android.identity.credential.CredentialFactory
import com.android.identity.credential.SecureAreaBoundCredential
import com.android.identity.crypto.CertificateChain
import com.android.identity.direct_access.DirectAccessSocketTransport
import com.android.identity.direct_access.DirectAccessTransport
import com.android.identity.document.DocumentStore
import com.android.identity.securearea.SecureArea
import com.android.identity.securearea.SecureAreaRepository
import com.android.identity.storage.StorageEngine
import com.android.identity.util.Logger.d
import org.junit.Assert
import java.io.File
import java.io.IOException
import java.lang.IllegalArgumentException
import java.security.KeyPair
import java.util.Timer
import java.util.TimerTask
import java.util.concurrent.Executor
import java.util.concurrent.TimeoutException
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

abstract class DirectAccessTest {
    companion object {
        private const val TAG = "DirectAccessTest"
    }

    enum class TransportType {
        OMAPI, SOCKET, SMARTCARDIO
    }

    protected val CREDENTIAL_DOMAIN = "da_test"
    private val SERVICE_CONNECTION_TIME_OUT: Long = 3000
    private var connected = false
    private lateinit var connectionTimer: Timer
    private val mTimerTask = ServiceConnectionTimerTask()
    private lateinit var mSEService: SEService
    protected lateinit var mTransport: DirectAccessTransport
    protected lateinit var storageEngine: StorageEngine
    private lateinit var secureArea: SecureArea
    protected lateinit var secureAreaRepository: SecureAreaRepository
    protected lateinit var credentialFactory: CredentialFactory
    protected lateinit var documentStore: DocumentStore
    protected lateinit var mDocName: String
    protected lateinit var context: Context
    protected lateinit var mReaderKeys: ArrayList<KeyPair>
    protected lateinit var mReaderCertChain: HashMap<KeyPair, CertificateChain?>

    private val lock = ReentrantLock()
    private val condition = lock.newCondition()
    private val mListener = SEService.OnConnectedListener {
        lock.withLock {
            connected = true
            condition.signal()
        }
    }

    internal inner class SynchronousExecutor : Executor {
        override fun execute(r: Runnable) {
            r.run()
        }
    }

    internal inner class ServiceConnectionTimerTask : TimerTask() {
        override fun run() {
            lock.withLock { condition.signalAll() }
        }
    }

    @Throws(TimeoutException::class)
    protected fun waitForConnection() {
        if (mTransport is DirectAccessSocketTransport ||
            mTransport is DirectAccessSmartCardTransport
        ) {
            return
        }
        lock.withLock {
            if (!connected) {
                try {
                    condition.await()
                } catch (e: InterruptedException) {
                    e.printStackTrace()
                }
            }
            if (!connected) {
                throw TimeoutException(
                    "Service could not be connected after $SERVICE_CONNECTION_TIME_OUT ms"
                )
            }
            if (connectionTimer != null) {
                connectionTimer!!.cancel()
            }
        }
    }

    private fun getDirectAccessTransport(transType: TransportType?): DirectAccessTransport {
        return when (transType) {
            TransportType.SOCKET -> DirectAccessSocketTransport()
            TransportType.OMAPI -> DirectAccessOmapiTransport(mSEService)
            TransportType.SMARTCARDIO -> DirectAccessSmartCardTransport()
            else -> throw IllegalArgumentException("invalid transport type")
        }
    }

    protected open fun init(type: TransportType) {
        mDocName = "mDL"
        context = androidx.test.InstrumentationRegistry.getTargetContext()
        val storageDir = File(context.dataDir, "ic-testing")
        storageEngine = AndroidStorageEngine.Builder(context, storageDir).build()
        secureAreaRepository = SecureAreaRepository()
        secureArea = AndroidKeystoreSecureArea(context, storageEngine)
        secureAreaRepository.addImplementation(secureArea)
        credentialFactory = CredentialFactory()
        credentialFactory.addCredentialImplementation(SecureAreaBoundCredential::class)

        connectionTimer = Timer()
        connectionTimer.schedule(mTimerTask, SERVICE_CONNECTION_TIME_OUT)
        mTransport = getDirectAccessTransport(type)
        try {
            mTransport.init()
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    protected open fun reset() {
        d(TAG, "reset")
        documentStore.deleteDocument(mDocName)
        try {
            mTransport.closeConnection()
            mTransport.unInit()
        } catch (e: IOException) {
            Assert.fail("Unexpected Exception $e")
        }
    }
}