package com.ecliptix.protocol

internal object EppNative {
    init {
        System.loadLibrary("epp_agent")
    }

    @JvmStatic external fun version(): String
    @JvmStatic external fun init()
    @JvmStatic external fun shutdown()

    @JvmStatic external fun identityCreate(): Long
    @JvmStatic external fun identityCreateFromSeed(seed: ByteArray): Long
    @JvmStatic external fun identityDestroy(handle: Long)
    @JvmStatic external fun identityGetX25519Public(handle: Long): ByteArray
    @JvmStatic external fun identityGetEd25519Public(handle: Long): ByteArray
    @JvmStatic external fun prekeyBundleCreate(identityHandle: Long): ByteArray

    @JvmStatic external fun handshakeInitiatorStart(
        identityHandle: Long,
        peerBundle: ByteArray,
        maxMessagesPerChain: Int
    ): HandshakeStartResult

    @JvmStatic external fun handshakeInitiatorFinish(handle: Long, ack: ByteArray): Long
    @JvmStatic external fun handshakeInitiatorDestroy(handle: Long)

    @JvmStatic external fun sessionEncrypt(
        handle: Long,
        plaintext: ByteArray,
        envelopeType: Int,
        envelopeId: Int,
        correlationId: String?
    ): ByteArray

    @JvmStatic external fun sessionDecrypt(handle: Long, encrypted: ByteArray): ByteArray
    @JvmStatic external fun sessionSerialize(handle: Long): ByteArray
    @JvmStatic external fun sessionDeserialize(state: ByteArray): Long
    @JvmStatic external fun sessionDestroy(handle: Long)
}

data class HandshakeStartResult(
    val handle: Long,
    val initMessage: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HandshakeStartResult) return false
        return handle == other.handle && initMessage.contentEquals(other.initMessage)
    }

    override fun hashCode(): Int = 31 * handle.hashCode() + initMessage.contentHashCode()
}
