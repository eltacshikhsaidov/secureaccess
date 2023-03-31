package io.shikhsaidov.secureaccess.entity;

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
public class ResetPasswordToken {
    @Id
    @GeneratedValue
    public Long id;
    public String token;
    @CreationTimestamp
    public LocalDateTime createdAt;
    public LocalDateTime expiresAt;
    @ManyToOne
    @JoinColumn(name = "user_id")
    public User user;
}
