package config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GateAwayConfig {

    @Value("${bussines.logic.server.url}")
    private String bussinesLogicServerUrl;

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder ){
        return builder.routes().
                route(p -> p
                        .path("/metric/**")
                        .uri(bussinesLogicServerUrl + "/metric"))
                .route(p -> p
                        .path("/profile")
                        .uri(bussinesLogicServerUrl + "/profile"))
                .route(p -> p
                        .path("/advice/**")
                        .uri(bussinesLogicServerUrl + "/advice"))
                .build();
    }

}
