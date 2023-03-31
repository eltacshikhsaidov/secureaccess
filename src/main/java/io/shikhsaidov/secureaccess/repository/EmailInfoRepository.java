package io.shikhsaidov.secureaccess.repository;

import io.shikhsaidov.secureaccess.entity.EmailInfo;
import io.shikhsaidov.secureaccess.enums.EmailStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface EmailInfoRepository extends JpaRepository<EmailInfo, Long> {
    List<EmailInfo> getEmailInfoByStatus(EmailStatus status);

    @Transactional
    @Modifying
    @Query("update EmailInfo e set e.retriedAt=?2, e.retryCount=?3, e.status=?4 where e.id=?1")
    void updateEmailInfoById(Long id, LocalDateTime retriedAt, Integer retryCount, EmailStatus emailStatus);
}
