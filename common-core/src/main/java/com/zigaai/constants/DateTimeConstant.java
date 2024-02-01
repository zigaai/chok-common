package com.zigaai.constants;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class DateTimeConstant {
    private DateTimeConstant() {
    }

    public static final ZoneId UTC_ZONE_ID = ZoneId.of("UTC");

    public static final DateTimeFormatter YYYY_MM_DD = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    public static final DateTimeFormatter YYYY_MM_DD_HH_MM_SS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static final DateTimeFormatter HH_MM_SS = DateTimeFormatter.ofPattern("HH:mm:ss");
}
