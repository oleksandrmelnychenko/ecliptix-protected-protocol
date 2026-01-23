package com.ecliptix.protocol

class EppException(
    val errorCode: Int,
    message: String
) : Exception(message) {

    companion object {
        const val SUCCESS = 0
        const val ERROR_GENERIC = 1
        const val ERROR_INVALID_INPUT = 2
        const val ERROR_KEY_GENERATION = 3
        const val ERROR_DERIVE_KEY = 4
        const val ERROR_HANDSHAKE = 5
        const val ERROR_ENCRYPTION = 6
        const val ERROR_DECRYPTION = 7
        const val ERROR_DECODE = 8
        const val ERROR_ENCODE = 9
        const val ERROR_BUFFER_TOO_SMALL = 10
        const val ERROR_OBJECT_DISPOSED = 11
        const val ERROR_PREPARE_LOCAL = 12
        const val ERROR_OUT_OF_MEMORY = 13
        const val ERROR_SODIUM_FAILURE = 14
        const val ERROR_NULL_POINTER = 15
        const val ERROR_INVALID_STATE = 16
        const val ERROR_REPLAY_ATTACK = 17
        const val ERROR_SESSION_EXPIRED = 18
        const val ERROR_PQ_MISSING = 19
    }
}
