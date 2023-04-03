package io.shikhsaidov.secureaccess.entity;

import io.shikhsaidov.secureaccess.enums.Role;
import io.shikhsaidov.secureaccess.enums.Status;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.LazyCollection;
import org.hibernate.annotations.LazyCollectionOption;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Getter
@Setter
@ToString
@Entity
@Table(name = "_user")
@NoArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    private Boolean locked = false;
    private Boolean enabled = false;
    @CreationTimestamp
    private LocalDateTime registeredAt;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Enumerated(EnumType.STRING)
    private Status status = Status.ACTIVE;

    @OneToMany(mappedBy = "user")
    @ToString.Exclude
    @LazyCollection(LazyCollectionOption.FALSE)
    private List<Token> tokens;

    @OneToMany(mappedBy = "user")
    @ToString.Exclude
    @LazyCollection(LazyCollectionOption.FALSE)
    private List<ResetPasswordToken> resetPasswordTokens;

    @OneToMany(mappedBy = "user")
    @ToString.Exclude
    @LazyCollection(LazyCollectionOption.FALSE)
    private List<ConfirmationToken> confirmationTokens;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public User(String firstname, String lastname, String email, String password, Role role) {
        this.email = email;
        this.firstname = firstname;
        this.lastname = lastname;
        this.password = password;
        this.role = role;
    }
}