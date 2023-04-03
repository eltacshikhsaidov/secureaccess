package io.shikhsaidov.secureaccess.response.model;

import io.shikhsaidov.secureaccess.entity.User;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UsersResponse {
    private List<User> users;
}
