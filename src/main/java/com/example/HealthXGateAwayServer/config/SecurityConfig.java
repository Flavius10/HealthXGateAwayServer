package com.example.HealthXGateAwayServer.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class SecurityConfig {

    @Value("${jwt.public.key}")
    private String publicKey;


    @Bean
    public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception{
        http
                .authorizeExchange(exchange ->
                        exchange.anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 ->
                    oauth2.jwt(c -> c.publicKey(publicKey())));

        return http.build();
    }

    @Bean
    public RSAPublicKey publicKey(){
        try{
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 =
                    new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey.getBytes()));
            return (RSAPublicKey) keyFactory.generatePublic(keySpecX509);

        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }


}
