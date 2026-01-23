package com.ecliptix.protocol

import java.io.Closeable

class EppIdentity private constructor(
    private var handle: Long
) : Closeable {

    val x25519PublicKey: ByteArray
        get() {
            check(handle != 0L) { "Identity has been closed" }
            return EppNative.identityGetX25519Public(handle)
        }

    val ed25519PublicKey: ByteArray
        get() {
            check(handle != 0L) { "Identity has been closed" }
            return EppNative.identityGetEd25519Public(handle)
        }

    fun createPrekeyBundle(): ByteArray {
        check(handle != 0L) { "Identity has been closed" }
        return EppNative.prekeyBundleCreate(handle)
    }

    internal val nativeHandle: Long
        get() = handle

    override fun close() {
        if (handle != 0L) {
            EppNative.identityDestroy(handle)
            handle = 0L
        }
    }

    protected fun finalize() {
        close()
    }

    companion object {
        fun create(): EppIdentity {
            val handle = EppNative.identityCreate()
            return EppIdentity(handle)
        }

        fun createFromSeed(seed: ByteArray): EppIdentity {
            val handle = EppNative.identityCreateFromSeed(seed)
            return EppIdentity(handle)
        }
    }
}
