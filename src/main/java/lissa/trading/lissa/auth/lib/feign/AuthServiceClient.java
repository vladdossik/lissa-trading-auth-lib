package lissa.trading.lissa.auth.lib.feign;

import lissa.trading.lissa.auth.lib.dto.UserInfoDto;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;


@FeignClient(
        name = "auth-service",
        url = "${integration.rest.auth-service-url}",
        configuration = FeignConfiguration.class
)
public interface AuthServiceClient {

    @PostMapping("/v1/auth/user-info")
    UserInfoDto getUserInfo(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader);
}