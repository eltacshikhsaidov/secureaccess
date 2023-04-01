package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.ResetPasswordToken;
import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface ResetPasswordTokenRepository extends JpaRepository<ResetPasswordToken, Long> {

    @Transactional
    @Modifying
    @Query("update ResetPasswordToken r set r.status=?1 where r.user=?2")
    void updateAllByStatusAndUser(Status status, User user);

    int countByStatusAndCreatedAtBetween(Status status, LocalDateTime startedAt, LocalDateTime endsAt);

    @Query("select r.user from ResetPasswordToken r where r.token=?1 and r.status='ACTIVE'")
    Optional<User> getUserByActiveToken(String token);

    Optional<ResetPasswordToken> findResetPasswordTokenByToken(String token);
}
