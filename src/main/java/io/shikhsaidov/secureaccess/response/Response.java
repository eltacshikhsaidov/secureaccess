package io.shikhsaidov.secureaccess.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Response<T> {

    private Integer code;
    private String message;
    private T data;

    public static <T> Response<T> success(String message, T data) {
        return new Response<>(
                SUCCESS,
                message,
                data
        );
    }

    public static Response<?> failed(Integer code, String msg) {
        return new Response<>(
                code,
                msg,
                null
        );
    }

    public static <T> Response<?> response(Integer code, String msg, T data) {
        return new Response<>(
                code,
                msg,
                data
        );
    }

}
