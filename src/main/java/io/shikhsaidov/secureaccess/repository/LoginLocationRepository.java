package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.LoginLocation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginLocationRepository extends JpaRepository<LoginLocation, Long> {}
