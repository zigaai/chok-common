package com.zigaai.serializers;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.zigaai.constants.DateTimeConstant;

import java.io.IOException;
import java.time.LocalDate;

public class LocalDateSerializer extends BaseDateSerializer<LocalDate> {

    @Override
    public void serialize(LocalDate value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        if (value != null) {
            long millis = value.atStartOfDay(DateTimeConstant.UTC_ZONE_ID).toInstant().toEpochMilli();
            gen.writeNumber(millis);
        }
    }

}