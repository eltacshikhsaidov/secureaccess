package io.shikhsaidov.secureaccess.repository;

import java.util.List;
import java.util.Optional;

import io.shikhsaidov.secureaccess.entity.User;
import io.shikhsaidov.secureaccess.enums.Status;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE User a SET a.enabled = TRUE WHERE a.email = ?1")
    void enableUser(String email);

    @Transactional
    @Modifying
    @Query("update User u set u.password=?2 where u.id=?1")
    void updatePasswordByUserId(Integer userId, String password);

    List<User> findUsersByStatusAndLockedAndEnabled(Status status, boolean locked, boolean enabled);

}
