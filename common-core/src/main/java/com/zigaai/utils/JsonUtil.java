package com.zigaai.utils;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.zigaai.serializers.*;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.TimeZone;

@UtilityClass
public final class JsonUtil {

    public static String toJson(Object obj) throws JsonProcessingException {
        return INNER.INSTANCE.DEFAULT_OBJECT_MAPPER.writeValueAsString(obj);
    }

    public static <T> T readValue(String json, Class<T> clazz) throws JsonProcessingException {
        return INNER.INSTANCE.DEFAULT_OBJECT_MAPPER.readValue(json, clazz);
    }

    public static ObjectMapper getInstance() {
        return INNER.INSTANCE.DEFAULT_OBJECT_MAPPER;
    }

    @SuppressWarnings({"squid:S116", "squid:S125"})
    private enum INNER {
        INSTANCE;

        private final ObjectMapper DEFAULT_OBJECT_MAPPER = new ObjectMapper();

        INNER() {
            // datetime parse
            SimpleModule dateModule = new SimpleModule();
            // 配置序列化
            dateModule.addSerializer(LocalDateTime.class, new LocalDateTimeSerializer());
            dateModule.addSerializer(LocalDate.class, new LocalDateSerializer());
            dateModule.addSerializer(LocalTime.class, new LocalTimeSerializer());
            dateModule.addSerializer(Instant.class, new InstantSerializer());
            // 配置反序列化
            dateModule.addDeserializer(LocalDateTime.class, new LocalDateTimeDeserializer());
            dateModule.addDeserializer(LocalDate.class, new LocalDateDeserializer());
            dateModule.addDeserializer(LocalTime.class, new LocalTimeDeserializer());
            dateModule.addDeserializer(Instant.class, new InstantDeserializer());
            DEFAULT_OBJECT_MAPPER.registerModule(dateModule);
            // 允许属性名称没有引号
            DEFAULT_OBJECT_MAPPER.configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
            // 序列化时结果不包含值为null的属性
            // DEFAULT_OBJECT_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            // 反序列化时忽略在json字符串中存在但在java对象实际没有的属性，不抛出异常
            DEFAULT_OBJECT_MAPPER.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            // 允许json=""的空字符换入参
            DEFAULT_OBJECT_MAPPER.enable(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT);
            DEFAULT_OBJECT_MAPPER.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
            // 设置时区
            DEFAULT_OBJECT_MAPPER.setTimeZone(TimeZone.getDefault());
        }

    }
}
