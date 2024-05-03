package com.android.identity.direct_access

import java.io.IOException

interface DirectAccessTransport {
    @Throws(IOException::class)
    fun init()

    @Throws(IOException::class)
    fun openConnection()

    @Throws(IOException::class)
    fun sendData(input: ByteArray): ByteArray

    @Throws(IOException::class)
    fun closeConnection()

    @get:Throws(IOException::class)
    val isConnected: Boolean
    val maxTransceiveLength: Int

    @Throws(IOException::class)
    fun unInit()
}