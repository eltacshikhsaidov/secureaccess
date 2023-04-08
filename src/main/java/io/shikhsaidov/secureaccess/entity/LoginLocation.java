package io.shikhsaidov.secureaccess.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Builder
@AllArgsConstructor
@Entity
public class LoginLocation {
    @Id
    @GeneratedValue
    private Long id;
    private String ip;
    private String network;
    private String version;
    private String city;
    private String region;
    @JsonProperty(value = "region_code")
    private String regionCode;
    private String country;
    @JsonProperty(value = "country_code")
    private String countryCode;
    @JsonProperty(value = "country_code_iso3")
    private String countryIso3;
    @JsonProperty(value = "country_name")
    private String countryName;
    @JsonProperty(value = "country_capital")
    private String countryCapital;
    @JsonProperty(value = "country_tld")
    private String countryTld;
    @JsonProperty(value = "continent_code")
    private String continentCode;
    @JsonProperty(value = "in_eu")
    private boolean inEu;
    private String postal;
    private double latitude;
    private double longitude;
    private String timezone;
    @JsonProperty(value = "utc_offset")
    private String utcOffset;
    @JsonProperty(value = "country_calling_code")
    private String countryCallingCode;
    private String currency;
    @JsonProperty(value = "currency_name")
    private String currencyName;
    private String languages;
    @JsonProperty(value = "country_area")
    private double countryArea;
    @JsonProperty(value = "country_population")
    private int countryPopulation;
    private String asn;
    private String org;
}
