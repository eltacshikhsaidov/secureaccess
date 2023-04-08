package io.shikhsaidov.secureaccess.entity;

import io.shikhsaidov.secureaccess.enums.LoginStatus;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Builder
@AllArgsConstructor
@Entity
public class LoginHistory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String ipAddress;
    @CreationTimestamp
    private LocalDateTime loginTime;
    private String deviceName;
    @Enumerated(EnumType.STRING)
    private LoginStatus loginStatus;
    @ManyToOne
    @JoinColumn(name = "login_location_id")
    private LoginLocation loginLocation;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;
}
