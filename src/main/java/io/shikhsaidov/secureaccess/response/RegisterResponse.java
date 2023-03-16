package io.shikhsaidov.secureaccess.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class RegisterResponse {
    private String token;
}
