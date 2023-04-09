package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.Device;
import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.enums.DeviceStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface DeviceRepository extends JpaRepository<Device, Long> {
    List<Device> findAllByUserAndDeviceStatus(User user, DeviceStatus deviceStatus);

    Optional<Device> findDeviceByToken(String token);

    @Transactional
    @Modifying
    @Query("UPDATE Device d set d.deviceStatus=?2 where d.id=?1")
    void updateDeviceStatusById(Long id, DeviceStatus deviceStatus);

    Optional<Device> findDeviceByIpAddressAndDeviceName(String ipAddress, String deviceName);

    @Transactional
    @Modifying
    @Query("UPDATE Device d set d.token=?2 where d.id=?1")
    void updateDeviceTokenById(Long id, String token);
}
