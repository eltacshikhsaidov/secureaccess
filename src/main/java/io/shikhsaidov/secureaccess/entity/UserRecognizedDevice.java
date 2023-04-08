package io.shikhsaidov.secureaccess.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import io.shikhsaidov.secureaccess.enums.Status;
import jakarta.persistence.*;
import lombok.*;

// one user can recognize multiple devices

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Builder
@AllArgsConstructor
@Entity
public class UserRecognizedDevice {
    @Id
    @GeneratedValue
    private Long id;
    private String deviceName;
    private String ipAddress;
    @Enumerated(EnumType.STRING)
    private Status status = Status.ACTIVE;
    @ManyToOne
    @JoinColumn(name = "user_id")
    @JsonBackReference
    public User user;
}
