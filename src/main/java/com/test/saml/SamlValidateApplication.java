package com.test.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableAutoConfiguration
//@EnableResourceServer
public class SamlValidateApplication {

    public static void main(String[] args) {
        SpringApplication.run(SamlValidateApplication.class, args);
    }
}
