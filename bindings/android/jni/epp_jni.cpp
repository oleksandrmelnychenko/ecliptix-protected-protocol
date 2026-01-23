#include <jni.h>
#include <cstring>
#include "ecliptix/c_api/epp_api.h"

static void throwException(JNIEnv* env, EppErrorCode code, const char* message) {
    jclass exClass = env->FindClass("com/ecliptix/protocol/EppException");
    if (exClass == nullptr) return;

    jmethodID ctor = env->GetMethodID(exClass, "<init>", "(ILjava/lang/String;)V");
    if (ctor == nullptr) return;

    jstring jmsg = message ? env->NewStringUTF(message) : env->NewStringUTF(epp_error_string(code));
    jthrowable ex = (jthrowable)env->NewObject(exClass, ctor, (jint)code, jmsg);
    env->Throw(ex);
}

static void checkError(JNIEnv* env, EppErrorCode code, EppError* error) {
    if (code != EPP_SUCCESS) {
        const char* msg = error && error->message ? error->message : nullptr;
        throwException(env, code, msg);
        if (error && error->message) {
            epp_error_free(error);
        }
    }
}

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_ecliptix_protocol_EppNative_version(JNIEnv* env, jclass) {
    return env->NewStringUTF(epp_version());
}

JNIEXPORT void JNICALL
Java_com_ecliptix_protocol_EppNative_init(JNIEnv* env, jclass) {
    EppErrorCode code = epp_init();
    if (code != EPP_SUCCESS) {
        throwException(env, code, nullptr);
    }
}

JNIEXPORT void JNICALL
Java_com_ecliptix_protocol_EppNative_shutdown(JNIEnv*, jclass) {
    epp_shutdown();
}

JNIEXPORT jlong JNICALL
Java_com_ecliptix_protocol_EppNative_identityCreate(JNIEnv* env, jclass) {
    EppIdentityHandle* handle = nullptr;
    EppError error = {};
    EppErrorCode code = epp_identity_create(&handle, &error);
    checkError(env, code, &error);
    return reinterpret_cast<jlong>(handle);
}

JNIEXPORT jlong JNICALL
Java_com_ecliptix_protocol_EppNative_identityCreateFromSeed(JNIEnv* env, jclass, jbyteArray seed) {
    jsize len = env->GetArrayLength(seed);
    jbyte* data = env->GetByteArrayElements(seed, nullptr);

    EppIdentityHandle* handle = nullptr;
    EppError error = {};
    EppErrorCode code = epp_identity_create_from_seed(
        reinterpret_cast<const uint8_t*>(data), len, &handle, &error);

    env->ReleaseByteArrayElements(seed, data, JNI_ABORT);
    checkError(env, code, &error);
    return reinterpret_cast<jlong>(handle);
}

JNIEXPORT void JNICALL
Java_com_ecliptix_protocol_EppNative_identityDestroy(JNIEnv*, jclass, jlong handle) {
    if (handle != 0) {
        epp_identity_destroy(reinterpret_cast<EppIdentityHandle*>(handle));
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_ecliptix_protocol_EppNative_identityGetX25519Public(JNIEnv* env, jclass, jlong handle) {
    uint8_t key[32];
    EppError error = {};
    EppErrorCode code = epp_identity_get_x25519_public(
        reinterpret_cast<EppIdentityHandle*>(handle), key, 32, &error);
    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, reinterpret_cast<jbyte*>(key));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ecliptix_protocol_EppNative_identityGetEd25519Public(JNIEnv* env, jclass, jlong handle) {
    uint8_t key[32];
    EppError error = {};
    EppErrorCode code = epp_identity_get_ed25519_public(
        reinterpret_cast<EppIdentityHandle*>(handle), key, 32, &error);
    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jbyteArray result = env->NewByteArray(32);
    env->SetByteArrayRegion(result, 0, 32, reinterpret_cast<jbyte*>(key));
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ecliptix_protocol_EppNative_prekeyBundleCreate(JNIEnv* env, jclass, jlong identityHandle) {
    EppBuffer buffer = {};
    EppError error = {};
    EppErrorCode code = epp_prekey_bundle_create(
        reinterpret_cast<EppIdentityHandle*>(identityHandle), &buffer, &error);
    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jbyteArray result = env->NewByteArray(static_cast<jsize>(buffer.length));
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(buffer.length),
        reinterpret_cast<jbyte*>(buffer.data));
    epp_buffer_release(&buffer);
    return result;
}

JNIEXPORT jobject JNICALL
Java_com_ecliptix_protocol_EppNative_handshakeInitiatorStart(
    JNIEnv* env, jclass, jlong identityHandle, jbyteArray peerBundle, jint maxMessagesPerChain) {

    jsize bundleLen = env->GetArrayLength(peerBundle);
    jbyte* bundleData = env->GetByteArrayElements(peerBundle, nullptr);

    EppSessionConfig config = { static_cast<uint32_t>(maxMessagesPerChain) };
    EppHandshakeInitiatorHandle* handle = nullptr;
    EppBuffer initMsg = {};
    EppError error = {};

    EppErrorCode code = epp_handshake_initiator_start(
        reinterpret_cast<EppIdentityHandle*>(identityHandle),
        reinterpret_cast<const uint8_t*>(bundleData), bundleLen,
        &config, &handle, &initMsg, &error);

    env->ReleaseByteArrayElements(peerBundle, bundleData, JNI_ABORT);
    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jclass resultClass = env->FindClass("com/ecliptix/protocol/HandshakeStartResult");
    jmethodID ctor = env->GetMethodID(resultClass, "<init>", "(J[B)V");

    jbyteArray initMsgArray = env->NewByteArray(static_cast<jsize>(initMsg.length));
    env->SetByteArrayRegion(initMsgArray, 0, static_cast<jsize>(initMsg.length),
        reinterpret_cast<jbyte*>(initMsg.data));
    epp_buffer_release(&initMsg);

    return env->NewObject(resultClass, ctor, reinterpret_cast<jlong>(handle), initMsgArray);
}

JNIEXPORT jlong JNICALL
Java_com_ecliptix_protocol_EppNative_handshakeInitiatorFinish(
    JNIEnv* env, jclass, jlong handle, jbyteArray ack) {

    jsize ackLen = env->GetArrayLength(ack);
    jbyte* ackData = env->GetByteArrayElements(ack, nullptr);

    EppSessionHandle* session = nullptr;
    EppError error = {};
    EppErrorCode code = epp_handshake_initiator_finish(
        reinterpret_cast<EppHandshakeInitiatorHandle*>(handle),
        reinterpret_cast<const uint8_t*>(ackData), ackLen,
        &session, &error);

    env->ReleaseByteArrayElements(ack, ackData, JNI_ABORT);
    checkError(env, code, &error);
    return reinterpret_cast<jlong>(session);
}

JNIEXPORT void JNICALL
Java_com_ecliptix_protocol_EppNative_handshakeInitiatorDestroy(JNIEnv*, jclass, jlong handle) {
    if (handle != 0) {
        epp_handshake_initiator_destroy(reinterpret_cast<EppHandshakeInitiatorHandle*>(handle));
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_ecliptix_protocol_EppNative_sessionEncrypt(
    JNIEnv* env, jclass, jlong handle, jbyteArray plaintext,
    jint envelopeType, jint envelopeId, jstring correlationId) {

    jsize ptLen = env->GetArrayLength(plaintext);
    jbyte* ptData = env->GetByteArrayElements(plaintext, nullptr);

    const char* corrId = correlationId ? env->GetStringUTFChars(correlationId, nullptr) : nullptr;
    size_t corrIdLen = corrId ? strlen(corrId) : 0;

    EppBuffer encrypted = {};
    EppError error = {};
    EppErrorCode code = epp_session_encrypt(
        reinterpret_cast<EppSessionHandle*>(handle),
        reinterpret_cast<const uint8_t*>(ptData), ptLen,
        static_cast<EppEnvelopeType>(envelopeType),
        static_cast<uint32_t>(envelopeId),
        corrId, corrIdLen,
        &encrypted, &error);

    env->ReleaseByteArrayElements(plaintext, ptData, JNI_ABORT);
    if (corrId) env->ReleaseStringUTFChars(correlationId, corrId);

    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jbyteArray result = env->NewByteArray(static_cast<jsize>(encrypted.length));
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(encrypted.length),
        reinterpret_cast<jbyte*>(encrypted.data));
    epp_buffer_release(&encrypted);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ecliptix_protocol_EppNative_sessionDecrypt(
    JNIEnv* env, jclass, jlong handle, jbyteArray encrypted) {

    jsize encLen = env->GetArrayLength(encrypted);
    jbyte* encData = env->GetByteArrayElements(encrypted, nullptr);

    EppBuffer plaintext = {};
    EppBuffer metadata = {};
    EppError error = {};
    EppErrorCode code = epp_session_decrypt(
        reinterpret_cast<EppSessionHandle*>(handle),
        reinterpret_cast<const uint8_t*>(encData), encLen,
        &plaintext, &metadata, &error);

    env->ReleaseByteArrayElements(encrypted, encData, JNI_ABORT);
    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jbyteArray result = env->NewByteArray(static_cast<jsize>(plaintext.length));
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(plaintext.length),
        reinterpret_cast<jbyte*>(plaintext.data));
    epp_buffer_release(&plaintext);
    epp_buffer_release(&metadata);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ecliptix_protocol_EppNative_sessionSerialize(JNIEnv* env, jclass, jlong handle) {
    EppBuffer state = {};
    EppError error = {};
    EppErrorCode code = epp_session_serialize(
        reinterpret_cast<EppSessionHandle*>(handle), &state, &error);
    checkError(env, code, &error);
    if (code != EPP_SUCCESS) return nullptr;

    jbyteArray result = env->NewByteArray(static_cast<jsize>(state.length));
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(state.length),
        reinterpret_cast<jbyte*>(state.data));
    epp_buffer_release(&state);
    return result;
}

JNIEXPORT jlong JNICALL
Java_com_ecliptix_protocol_EppNative_sessionDeserialize(JNIEnv* env, jclass, jbyteArray state) {
    jsize stateLen = env->GetArrayLength(state);
    jbyte* stateData = env->GetByteArrayElements(state, nullptr);

    EppSessionHandle* handle = nullptr;
    EppError error = {};
    EppErrorCode code = epp_session_deserialize(
        reinterpret_cast<const uint8_t*>(stateData), stateLen, &handle, &error);

    env->ReleaseByteArrayElements(state, stateData, JNI_ABORT);
    checkError(env, code, &error);
    return reinterpret_cast<jlong>(handle);
}

JNIEXPORT void JNICALL
Java_com_ecliptix_protocol_EppNative_sessionDestroy(JNIEnv*, jclass, jlong handle) {
    if (handle != 0) {
        epp_session_destroy(reinterpret_cast<EppSessionHandle*>(handle));
    }
}

} // extern "C"
