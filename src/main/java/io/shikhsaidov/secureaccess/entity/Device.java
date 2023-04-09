package io.shikhsaidov.secureaccess.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import io.shikhsaidov.secureaccess.enums.DeviceStatus;
import io.shikhsaidov.secureaccess.enums.Status;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Builder
@AllArgsConstructor
@Entity
public class Device {
    @Id
    @GeneratedValue
    private Long id;
    private String deviceName;
    private String ipAddress;
    private String token;
    @Enumerated(EnumType.STRING)
    private DeviceStatus deviceStatus;
    @Enumerated(EnumType.STRING)
    private Status status = Status.ACTIVE;
    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonBackReference
    public User user;
}
