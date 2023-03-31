package io.shikhsaidov.secureaccess.response;

public class ResponseCodes {
    public static final Integer SUCCESS = 1;
    public static final Integer EMAIL_IS_TAKEN = 2;
    public static final Integer INVALID_REQUEST_DATA = 3;
    public static final Integer EMAIL_FORMAT_IS_INCORRECT = 4;
    public static final Integer USER_IS_NOT_REGISTERED = 5;
    public static final Integer TOKEN_IS_INVALID_OR_EXPIRED = 6;
    public static final Integer EMAIL_IS_ALREADY_CONFIRMED = 7;
    public static final Integer CONFIRMATION_TOKEN_EXPIRED = 8;
    public static final Integer CONFIRMATION_TOKEN_NOT_FOUND = 9;
    public static final Integer EMAIL_IS_NOT_CONFIRMED = 10;
    public static final Integer USER_IS_LOCKED_BY_ADMIN = 11;
    public static final Integer NO_ENVIRONMENT_IS_PRESENT = 12;
    public static final Integer EMAIL_SENT_WITH_PASSWORD_RESET = 13;
}
