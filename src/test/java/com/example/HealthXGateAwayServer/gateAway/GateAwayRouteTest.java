package com.example.HealthXGateAwayServer.gateAway;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class GateAwayRouteTest {

    @LocalServerPort
    private int port;

    @Value("${bussines.logic.server.url}")
    private String bussinesLogicServerUrl;

    @Test
    public void testMetricRoute(){
        WebTestClient client = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port).build();

        client.get()
                .uri("/metric/test") // ruta Gateway
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .consumeWith(response -> {
                    System.out.println("Response: " + response.getResponseBody());
                });
    }


    @Test
    void testProfileRoute() {
        WebTestClient client = WebTestClient.bindToServer()
                .baseUrl("http://localhost:" + port)
                .build();

        client.get()
                .uri("/profile") // ruta Gateway
                .exchange()
                .expectStatus().isOk();
    }

}
