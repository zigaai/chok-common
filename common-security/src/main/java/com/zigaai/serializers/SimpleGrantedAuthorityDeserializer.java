package com.zigaai.serializers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.*;

public class SimpleGrantedAuthorityDeserializer extends JsonDeserializer<Collection<? extends GrantedAuthority>> {
    @Override
    public Collection<? extends GrantedAuthority> deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        ObjectCodec oc = p.getCodec();
        JsonNode jsonNode = oc.readTree(p);
        Iterator<JsonNode> elements = jsonNode.elements();
        if (elements != null) {
            List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
            while (elements.hasNext()) {
                JsonNode next = elements.next();
                JsonNode authority = next.get("authority");
                grantedAuthorities.add(new SimpleGrantedAuthority(authority.asText()));
            }
            return grantedAuthorities;
        }
        return Collections.emptyList();
    }
}
