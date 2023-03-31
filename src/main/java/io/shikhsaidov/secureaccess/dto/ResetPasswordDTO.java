package io.shikhsaidov.secureaccess.dto;

public record ResetPasswordDTO(String email, String newPassword, String confirmNewPassword, String token) {}
