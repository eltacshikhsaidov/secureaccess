package io.shikhsaidov.secureaccess.response.model;

import lombok.Builder;
import lombok.Data;

import java.util.HashMap;

@Data
@Builder
public class MessageResponse {
    private String message;
    private HashMap<String, String> data;
}
