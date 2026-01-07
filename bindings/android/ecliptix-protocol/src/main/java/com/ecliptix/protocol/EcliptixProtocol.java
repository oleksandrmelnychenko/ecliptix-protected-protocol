package com.ecliptix.protocol;

public final class EcliptixProtocol {
    static {
        System.loadLibrary("epp_agent");
    }

    private EcliptixProtocol() {
    }
}
