package io.shikhsaidov.secureaccess.response.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ForgotPasswordResponse {
    private String message;
}
