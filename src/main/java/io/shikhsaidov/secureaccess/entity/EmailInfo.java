package io.shikhsaidov.secureaccess.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.shikhsaidov.secureaccess.enums.EmailStatus;
import io.shikhsaidov.secureaccess.enums.EmailType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@RequiredArgsConstructor
@Builder
//@NoArgsConstructor
@AllArgsConstructor
@Entity
public class EmailInfo {

    @Id
    @GeneratedValue
    public Long id;
    public String emailTo;
    public String subject;
    @Lob
    public byte[] content;
    @Enumerated(EnumType.STRING)
    public EmailStatus status;
    public int retryCount = 0;
    public LocalDateTime retriedAt;
    @Enumerated(EnumType.STRING)
    public EmailType type;
    @CreationTimestamp
    public LocalDateTime createdAt;

    @OneToOne
    @JoinColumn(name = "user_id")
    @JsonIgnore
    public User user;
}
