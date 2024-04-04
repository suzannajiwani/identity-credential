package com.android.identity.direct_access

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.Socket

class DirectAccessSocketTransport : DirectAccessTransport {
    private val PORT = 8080
    private val IPADDR = "192.168.9.112"
    private val MAX_RECV_BUFFER_SIZE = 700
    private var mSocket: Socket? = null
    private var socketStatus = false

    @Throws(IOException::class)
    override fun init() {
    }

    @Throws(IOException::class)
    override fun openConnection() {
        if (!isConnected) {
            val serverAddress = InetAddress.getByName(IPADDR)
            mSocket = Socket(serverAddress, PORT)
            socketStatus = true
        }
    }

    @Throws(IOException::class)
    override fun sendData(inData: ByteArray): ByteArray {
        var count = 1
        while (!socketStatus && count++ < 5) {
            try {
                Thread.sleep(1000)
                println("SocketTransport Trying to open socket connection... count: $count")
                openConnection()
            } catch (e: InterruptedException) {
                e.printStackTrace()
            }
        }
        if (count >= 5) {
            throw IOException("SocketTransport Failed to open socket connection")
        }

        // Prepend the input length to the inputData before sending.
        val length = ByteArray(2)
        length[0] = (inData.size shr 8 and 0xFF).toByte()
        length[1] = (inData.size and 0xFF).toByte()
        try {
            val bs = ByteArrayOutputStream()
            bs.write(length)
            bs.write(inData)
            val outputStream = mSocket!!.getOutputStream()
            outputStream.write(bs.toByteArray())
            outputStream.flush()
        } catch (e: IOException) {
            throw IOException("SocketTransport Failed to send data over socket. Error: " + e.message)
        }
        return readData()
    }

    @Throws(IOException::class)
    override fun closeConnection() {
        if (mSocket != null) {
            mSocket!!.close()
            mSocket = null
        }
        socketStatus = false
    }

    override val isConnected: Boolean
        get() = socketStatus

    override val maxTransceiveLength: Int
        get() = MAX_RECV_BUFFER_SIZE

    @Throws(IOException::class)
    override fun unInit() {
    }

    private fun readData(): ByteArray {
        val buffer = ByteArray(MAX_RECV_BUFFER_SIZE)
        var expectedResponseLen = 0
        var totalBytesRead = 0
        val bs = ByteArrayOutputStream()
        do {
            var offset: Short = 0
            val inputStream = mSocket!!.getInputStream()
            var numBytes = inputStream.read(buffer, 0, MAX_RECV_BUFFER_SIZE)
            if (numBytes < 0) {
                throw IOException("SocketTransport Failed to read data from socket.")
            }
            totalBytesRead += numBytes
            if (expectedResponseLen == 0) {
                expectedResponseLen = (buffer[1].toInt() and 0xFF)
                expectedResponseLen = (expectedResponseLen or (buffer[0].toInt() shl 8 and 0xFF00))
                expectedResponseLen += 2
                numBytes -= 2
                offset = 2
            }
            bs.write(buffer, offset.toInt(), numBytes)
        } while (totalBytesRead < expectedResponseLen)
        return bs.toByteArray()
    }
}