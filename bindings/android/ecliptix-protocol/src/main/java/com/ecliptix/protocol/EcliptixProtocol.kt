package com.ecliptix.protocol

object EcliptixProtocol {

    val version: String
        get() = EppNative.version()

    @Volatile
    private var initialized = false

    @Synchronized
    fun initialize() {
        if (!initialized) {
            EppNative.init()
            initialized = true
        }
    }

    fun shutdown() {
        if (initialized) {
            EppNative.shutdown()
            initialized = false
        }
    }
}
