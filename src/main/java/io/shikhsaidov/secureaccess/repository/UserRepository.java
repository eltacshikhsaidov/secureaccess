package io.shikhsaidov.secureaccess.repository;

import java.util.Optional;

import io.shikhsaidov.secureaccess.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);

}
