package com.ecliptix.protocol

import java.io.Closeable

class EppHandshakeInitiator private constructor(
    private var handle: Long,
    val initMessage: ByteArray
) : Closeable {

    fun finish(ackMessage: ByteArray): EppSession {
        check(handle != 0L) { "Handshake has been closed" }
        val sessionHandle = EppNative.handshakeInitiatorFinish(handle, ackMessage)
        handle = 0L // Consumed by finish
        return EppSession.fromHandle(sessionHandle)
    }

    override fun close() {
        if (handle != 0L) {
            EppNative.handshakeInitiatorDestroy(handle)
            handle = 0L
        }
    }

    protected fun finalize() {
        close()
    }

    companion object {
        fun start(
            identity: EppIdentity,
            peerPrekeyBundle: ByteArray,
            maxMessagesPerChain: Int = 100
        ): EppHandshakeInitiator {
            val result = EppNative.handshakeInitiatorStart(
                identity.nativeHandle,
                peerPrekeyBundle,
                maxMessagesPerChain
            )
            return EppHandshakeInitiator(result.handle, result.initMessage)
        }
    }
}
