package com.ecliptix.protocol

import java.io.Closeable

enum class EppEnvelopeType(val value: Int) {
    REQUEST(0),
    RESPONSE(1),
    NOTIFICATION(2),
    HEARTBEAT(3),
    ERROR_RESPONSE(4)
}

class EppSession private constructor(
    private var handle: Long
) : Closeable {

    fun encrypt(
        plaintext: ByteArray,
        envelopeType: EppEnvelopeType = EppEnvelopeType.REQUEST,
        envelopeId: Int = 0,
        correlationId: String? = null
    ): ByteArray {
        check(handle != 0L) { "Session has been closed" }
        return EppNative.sessionEncrypt(
            handle, plaintext, envelopeType.value, envelopeId, correlationId
        )
    }

    fun decrypt(encrypted: ByteArray): ByteArray {
        check(handle != 0L) { "Session has been closed" }
        return EppNative.sessionDecrypt(handle, encrypted)
    }

    fun serialize(): ByteArray {
        check(handle != 0L) { "Session has been closed" }
        return EppNative.sessionSerialize(handle)
    }

    override fun close() {
        if (handle != 0L) {
            EppNative.sessionDestroy(handle)
            handle = 0L
        }
    }

    protected fun finalize() {
        close()
    }

    companion object {
        fun deserialize(state: ByteArray): EppSession {
            val handle = EppNative.sessionDeserialize(state)
            return EppSession(handle)
        }

        internal fun fromHandle(handle: Long): EppSession {
            return EppSession(handle)
        }
    }
}
