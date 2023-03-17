package io.shikhsaidov.secureaccess.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.log4j.Log4j2;

@Log4j2
public class Utility {
    public static boolean isNull(Object... objects) {
        for (Object o: objects) {
            if (java.util.Objects.isNull(o)){
                return true;
            }
        }

        return false;
    }

    public static String object2Json(Object o) {
        String jsonString = null;

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            jsonString = objectMapper.writeValueAsString(o);

        } catch (JsonProcessingException e) {
            log.warn("Failed while converting object to json string");
        }

        return jsonString;
    }
}
