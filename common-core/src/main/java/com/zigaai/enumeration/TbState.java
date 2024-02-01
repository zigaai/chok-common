package com.zigaai.enumeration;

import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public enum TbState {

    /**
     * 正常
     */
    NORMAL(true),

    /**
     * 删除
     */
    DELETE(false);

    private final boolean val;

    public byte getVal() {
        return val ? (byte) 0 : 1;
    }

    public boolean booleanVal() {
        return val;
    }

    private static final Map<Byte, TbState> VALUE_MAP = Collections.unmodifiableMap(Arrays.stream(values()).collect(Collectors.toMap(TbState::getVal, Function.identity())));


}
