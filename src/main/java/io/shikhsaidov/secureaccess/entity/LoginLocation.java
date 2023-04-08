package io.shikhsaidov.secureaccess.entity;

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
    private String city;
    private String region;
    private String regionCode;
    private String countryCode;
    private String countryIso3;
    private String countryName;
    private String countryCapital;
    private String countryTld;
    private String continentCode;
    private boolean inEu;
    private String postal;
    private double latitude;
    private double longitude;
    private String timezone;
    private String utcOffset;
    private String countryCallingCode;
    private String currency;
    private String currencyName;
    private String languages;
    private String asn;
    private String org;


}
