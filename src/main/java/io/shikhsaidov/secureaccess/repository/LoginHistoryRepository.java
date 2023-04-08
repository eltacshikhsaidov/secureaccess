package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.LoginHistory;
import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.enums.LoginStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface LoginHistoryRepository extends JpaRepository<LoginHistory, Long> {
    int countLoginHistoriesByIpAddressAndLoginStatusAndLoginTimeBetween(
            String ipAddress,
            LoginStatus loginStatus,
            LocalDateTime startLoginTime,
            LocalDateTime endLoginTime
    );

    List<LoginHistory> findAllByLoginStatus(LoginStatus loginStatus);
}
