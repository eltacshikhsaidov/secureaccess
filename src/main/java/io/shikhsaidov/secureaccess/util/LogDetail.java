package io.shikhsaidov.secureaccess.util;

import lombok.Builder;
import lombok.Data;

@Data
public class LogDetail {
    private String requestPath;
    private String ip;
}
