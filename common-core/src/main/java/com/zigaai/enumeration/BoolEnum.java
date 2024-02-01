package com.zigaai.enumeration;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Getter
@ToString
@RequiredArgsConstructor
public enum BoolEnum {
    FALSE((byte) 0),
    TRUE((byte) 1);

    private final byte val;

    private static final Map<Byte, BoolEnum> MAP = Collections.unmodifiableMap(Arrays.stream(values()).collect(Collectors.toMap(BoolEnum::getVal, Function.identity())));

    public static boolean contains(Byte val) {
        return MAP.containsKey(val);
    }

    public static BoolEnum getByVal(Byte val) {
        if (!contains(val)) {
            throw new IllegalArgumentException("非法的布尔枚举值: " + val);
        }
        return MAP.get(val);
    }
}
