package com.example.SpringSecurity.security;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;


@Getter
public class JwtAuthenticationException  extends AuthenticationException {

    private HttpStatus httpStatus;
    }
    public JwtAuthenticationException(String msg) {
        super(msg);
        this.httpStatus = HttpStatus;
    }

    public JwtAuthenticationException(String s, HttpStatus unauthorized) {
        super();
    }
}
