package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.UserBlockedDevice;
import io.shikhsaidov.secureaccess.enums.Status;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface UserBlockedDeviceRepository extends JpaRepository<UserBlockedDevice, Long> {
    UserBlockedDevice findByToken(String token);

    @Transactional
    @Modifying
    @Query("update UserBlockedDevice u set u.status=?2 where u.token=?1")
    void updateUserBlockedDeviceByToken(String token, Status status);
}
