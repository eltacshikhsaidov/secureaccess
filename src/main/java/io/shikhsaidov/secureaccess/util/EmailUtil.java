package io.shikhsaidov.secureaccess.util;

import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;


@Component
@PropertySource("classpath:email.properties")
public class EmailUtil {

}
