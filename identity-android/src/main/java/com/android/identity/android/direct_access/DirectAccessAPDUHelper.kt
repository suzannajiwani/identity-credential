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

import com.android.identity.cbor.Bstr
import com.android.identity.cbor.Cbor
import org.bouncycastle.asn1.ASN1UTCTime
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.time.Duration
import java.util.Calendar

class DirectAccessAPDUHelper {
    private fun setShort(buf: ByteArray, offset: Int, value: Short) {
        buf[offset] = (value.toInt() shr 8 and 0xFF).toByte()
        buf[offset + 1] = (value.toInt() and 0xFF).toByte()
    }

    private fun longToByteArray(`val`: Long): ByteArray {
        val bb = ByteBuffer.allocate(8)
        bb.putLong(`val`)
        return bb.array()
    }

    private fun intToByteArray(`val`: Int): ByteArray {
        val bb = ByteBuffer.allocate(4)
        bb.putInt(`val`)
        return bb.array()
    }

    @Throws(IOException::class)
    private fun makeCommandApdu(ins: Byte, data: ByteArray): ByteArray {
        // TODO Handle non extended length.
        val bos = ByteArrayOutputStream()
        bos.write(0) // CLS
        bos.write(ins.toInt()) // INS
        bos.write(0) // P1
        bos.write(0) // P2
        // Send extended length APDU always as response size is not known to HAL.
        // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le
        // all set to 00.
        // Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
        bos.write(0x00)
        // Extended length 3 bytes, starts with 0x00
        if (data.size > 0) {
            bos.write(data.size shr 8)
            bos.write(data.size and 0xFF)
            // Data
            bos.write(data)
        }
        bos.write(0)
        bos.write(0)
        return bos.toByteArray()
    }

    @Throws(IOException::class)
    private fun makeCommandApdu(data: ByteArray): ByteArray {
        return makeCommandApdu(INS_ENVELOPE, data)
    }

    fun getAPDUResponseStatus(input: ByteArray): Int {
        // Last two bytes are the status SW0SW1
        val SW0 = input[input.size - 2]
        val SW1 = input[input.size - 1]
        return SW0.toInt() shl 8 or SW1.toInt() and 0xFFFF
    }

    @Throws(IOException::class)
    fun encodeValidityTime(milliseconds: Long): ByteArray {
        val calendar = Calendar.getInstance()
        calendar.timeInMillis = milliseconds
        var formatStr = "yyMMddHHmmss'Z'"
        if (calendar[Calendar.YEAR] >= 2050) {
            formatStr = "yyyyMMddHHmmss'Z'"
        }
        val sdf = SimpleDateFormat(formatStr)
        val str = sdf.format(calendar.time)
        println(str)
        val asn1UtcTime = ASN1UTCTime(str)
        return asn1UtcTime.encoded
    }

    @Throws(IOException::class)
    fun createCredentialAPDU(
        slot: Int,
        challenge: ByteArray,
        notBefore: Long,
        notAfter: Long
    ): ByteArray {
        val osVersion = 2
        val systemPatchLevel = 2
        val attAppId = byteArrayOf(0x00)
        val scratchpad = ByteArray(2)
        val bos = ByteArrayOutputStream()
        // set instruction
        setShort(scratchpad, 0, CMD_MDOC_CREATE.toShort())
        bos.write(scratchpad)
        // set slot
        bos.write(slot)
        // TODO Currently there is no way to provision the test credential.
        // set non-test credential
        bos.write(0)
        val osVersionBytes = intToByteArray(osVersion)
        val patchLevelBytes = intToByteArray(systemPatchLevel)

        // Set OS Version
        setShort(scratchpad, 0, osVersionBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(osVersionBytes)

        // Set System patch level
        setShort(scratchpad, 0, patchLevelBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(patchLevelBytes)

        // set challenge
        setShort(scratchpad, 0, challenge.size.toShort())
        bos.write(scratchpad)
        bos.write(challenge)
        val notBeforeBytes = encodeValidityTime(notBefore)
        val notAfterBytes = encodeValidityTime(notAfter)

        // Set Not Before
        setShort(scratchpad, 0, notBeforeBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(notBeforeBytes)

        // Set Not After
        setShort(scratchpad, 0, notAfterBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(notAfterBytes)

        // Set creation time
        val creationTimeMs = System.currentTimeMillis()
        val creationTimeMsBytes = longToByteArray(creationTimeMs)
        setShort(scratchpad, 0, creationTimeMsBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(creationTimeMsBytes)

        // set attestation application id
        setShort(scratchpad, 0, attAppId.size.toShort())
        bos.write(scratchpad)
        bos.write(attAppId)
        val result = bos.toByteArray()
        println("MDOC_REQUEST:<><><============<><><>")
        print(result, 0.toShort(), result.size.toShort())
        return makeCommandApdu(bos.toByteArray())
    }

    @Throws(IOException::class)
    fun createPresentationPackageAPDU(slot: Int, duration: Duration): ByteArray {
        val notBefore = System.currentTimeMillis()
        val notAfter = System.currentTimeMillis() + duration.toMillis()
        val scratchpad = ByteArray(2)
        val bos = ByteArrayOutputStream()
        // set instruction
        setShort(scratchpad, 0, CMD_MDOC_CREATE_PRESENTATION_PKG.toShort())
        bos.write(scratchpad)
        bos.write(slot)
        val notBeforeBytes = encodeValidityTime(notBefore)
        val notAfterBytes = encodeValidityTime(notAfter)

        // Set Not Before
        setShort(scratchpad, 0, notBeforeBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(notBeforeBytes)

        // Set Not After
        setShort(scratchpad, 0, notAfterBytes.size.toShort())
        bos.write(scratchpad)
        bos.write(notAfterBytes)
        return makeCommandApdu(bos.toByteArray())
    }

    @Throws(IOException::class)
    fun createProvisionSwapInApdu(
        cmd: Int,
        slot: Int,
        data: ByteArray?,
        offset: Int,
        length: Int,
        operation: Byte
    ): ByteArray {
        val bb = ByteBuffer.allocate(length)
        bb.put(data, offset, length)
        val scratchpad = ByteArray(2)
        val bos = ByteArrayOutputStream()
        // set instruction
        setShort(scratchpad, 0, cmd.toShort())
        bos.write(scratchpad)
        bos.write(slot)
        bos.write(operation.toInt())

        bos.write(Cbor.encode((Bstr(bb.array()))));
        return makeCommandApdu(bos.toByteArray())
    }

    @Throws(IOException::class)
    fun deleteMDocAPDU(slot: Int): ByteArray {
        val scratchpad = ByteArray(2)
        val bos = ByteArrayOutputStream()
        // set instruction
        setShort(scratchpad, 0, CMD_MDOC_DELETE_CREDENTIAL.toShort())
        bos.write(scratchpad)
        bos.write(slot)
        return makeCommandApdu(bos.toByteArray())
    }

    // Used for only testing purpose.
    @Throws(IOException::class)
    fun createFactoryProvisionApdu(
        ins: Byte, tagCert: Short, certData: ByteArray,
        tagKey: Short, keyData: ByteArray
    ): ByteArray {
        val scratchpad = ByteArray(2)
        val bos = ByteArrayOutputStream()
        // set Tag cert
        setShort(scratchpad, 0, tagCert)
        bos.write(scratchpad)

        // set cert length
        setShort(scratchpad, 0, certData.size.toShort())

        // set cert data
        bos.write(certData)

        // set tag key
        setShort(scratchpad, 0, tagKey)
        bos.write(scratchpad)

        // set key length
        setShort(scratchpad, 0, keyData.size.toShort())

        // set cert data
        bos.write(keyData)
        return makeCommandApdu(ins, bos.toByteArray())
    }

    companion object {
        const val CMD_MDOC_CREATE = 0x01
        const val CMD_MDOC_CREATE_PRESENTATION_PKG = 0x07
        const val CMD_MDOC_DELETE_CREDENTIAL = 0x08
        const val CMD_MDOC_PROVISION_DATA = 0x09
        const val CMD_MDOC_SWAP_IN = 0x06
        const val INS_ENVELOPE = 0xC3.toByte()
        const val APDU_RESPONSE_STATUS_OK = 0x9000
        private val notBefore1 = byteArrayOf(
            0x17, 0x0D, 0x31, 0x36, 0x30, 0x31,
            0x31, 0x31, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A
        )

        //notAfter Time UTCTime 2026-01-08 00:46:09 UTC
        private val notAfter1 = byteArrayOf(
            0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30,
            0x38, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A
        )

        fun print(buf: ByteArray, start: Short, length: Short) {
            val sb = StringBuilder()
            println("----")
            for (i in start until start + length) {
                sb.append(String.format("%02X", buf[i]))
            }
            println(sb)
        }
    }
}