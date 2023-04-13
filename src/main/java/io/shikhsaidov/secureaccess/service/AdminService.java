package io.shikhsaidov.secureaccess.service;

import io.shikhsaidov.secureaccess.enums.EmailStatus;
import io.shikhsaidov.secureaccess.enums.Status;
import io.shikhsaidov.secureaccess.response.Response;

public interface AdminService {
    Response<?> getEnvironment();

    Response<?> getUsers(Status status, boolean locked, boolean enabled);

    Response<?> getEmails(EmailStatus emailStatus);

    Response<?> changeUserLockStatus(Integer id);
}
