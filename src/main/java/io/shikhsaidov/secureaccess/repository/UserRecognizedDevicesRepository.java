package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.entity.UserRecognizedDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserRecognizedDevicesRepository extends JpaRepository<UserRecognizedDevice, Long> {
    List<UserRecognizedDevice> findAllByUser(User user);
}
