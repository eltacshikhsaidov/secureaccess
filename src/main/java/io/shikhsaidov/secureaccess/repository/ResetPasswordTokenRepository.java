package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.ResetPasswordToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ResetPasswordTokenRepository extends JpaRepository<ResetPasswordToken, Long> {
}
