package lissa.trading.auth_security_lib.feign;

import lissa.trading.auth_security_lib.dto.UserInfoDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;


@FeignClient(
        name = "auth-service",
        url = "${auth.service.url:http://localhost:8081}",
        configuration = FeignConfiguration.class
)
public interface AuthServiceClient {

    @PostMapping("/api/auth/user-info")
    UserInfoDto getUserInfo(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader);
}