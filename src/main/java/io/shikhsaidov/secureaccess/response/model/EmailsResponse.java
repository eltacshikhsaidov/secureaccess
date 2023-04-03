package io.shikhsaidov.secureaccess.response.model;

import io.shikhsaidov.secureaccess.entity.EmailInfo;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class EmailsResponse {
    List<EmailInfo> emailInfos;
}
