package io.shikhsaidov.secureaccess.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import static io.shikhsaidov.secureaccess.response.ResponseCodes.*;
import static io.shikhsaidov.secureaccess.util.Translator.translate;

@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Response<T> {

    private Integer code;
    private String message;
    private T data;

    public static <T> Response<T> success(T data) {
        return new Response<>(
                SUCCESS,
                translate(SUCCESS.toString()),
                data
        );
    }

    public static Response<?> failed(Integer code) {
        return new Response<>(
                code,
                translate(code.toString()),
                null
        );
    }

    public static <T> Response<?> response(Integer code, T data) {
        return new Response<>(
                code,
                translate(code.toString()),
                data
        );
    }

    public static Response<?> response(Integer code) {
        return new Response<>(
                code,
                translate(code.toString()),
                null
        );
    }

}
