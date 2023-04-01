package io.shikhsaidov.secureaccess.dto;

public record ResetPasswordDTO(String newPassword, String confirmNewPassword, String token) {}
