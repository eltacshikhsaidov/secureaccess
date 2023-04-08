package io.shikhsaidov.secureaccess.util;

import io.shikhsaidov.secureaccess.entity.LoginLocation;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@PropertySource("classpath:config-${application.environment}.properties")
public class IpDataUtil {

    private final RestClient restClient;

    @Value("${ipapi.url}")
    public String ipApiUrl;

    @Value("${ipapi.key}")
    public String ipApiKey;

    public LoginLocation loginLocation(String ip) {
        String url = ipApiUrl.concat(ip).concat("/json/?key=").concat(ipApiKey);
        LoginLocation loginLocation;

        try {
            return restClient.doGet(url, LoginLocation.class);
        } catch (Exception e) {
            loginLocation = LoginLocation.builder()
                    .city("Unrecognized")
                    .region("Unrecognized")
                    .regionCode("Unrecognized")
                    .countryCode("Unrecognized")
                    .countryIso3("Unrecognized")
                    .countryName("Unrecognized")
                    .countryCapital("Unrecognized")
                    .countryTld("Unrecognized")
                    .inEu(false)
                    .postal("Unrecognized")
                    .latitude(0)
                    .longitude(0)
                    .timezone("Unrecognized")
                    .utcOffset("Unrecognized")
                    .countryCallingCode("Unrecognized")
                    .currency("Unrecognized")
                    .currencyName("Unrecognized")
                    .languages("Unrecognized")
                    .asn("Unrecognized")
                    .org("Unrecognized")
                    .build();

        }

        return loginLocation;
    }

}
