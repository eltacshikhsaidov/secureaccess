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
    public static final Integer DAILY_EMAIL_LIMIT_EXCEEDED = 14;
    public static final Integer PASSWORDS_DID_NOT_MATCH = 15;
    public static final Integer RESET_PASSWORD_TOKEN_NOT_FOUND = 16;
    public static final Integer INVALID_RESET_PASSWORD_TOKEN = 17;
    public static final Integer RESET_PASSWORD_TOKEN_IS_DISABLED = 18;
    public static final Integer RESET_PASSWORD_TOKEN_EXPIRED = 19;
    public static final Integer EXCEPTION_OCCURRED = 20;
    public static final Integer EMAIL_LIST_IS_EMPTY = 21;
    public static final Integer USER_NOT_FOUND = 22;
    public static final Integer BAD_CREDENTIALS = 23;
    public static final Integer TRY_AGAIN_LATER = 24;
    public static final Integer VERIFY_NEW_DEVICE = 25;
    public static final Integer DEVICE_VERIFICATION_TOKEN_IS_NULL = 26;
    public static final Integer DEVICE_VERIFICATION_TOKEN_IS_NOT_VALID = 27;
    public static final Integer DEVICE_VERIFICATION_TOKEN_IS_ALREADY_CONFIRMED = 28;
}
