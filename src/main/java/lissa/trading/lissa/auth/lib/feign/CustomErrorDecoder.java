package lissa.trading.lissa.auth.lib.feign;

import feign.Response;
import feign.Util;
import feign.codec.ErrorDecoder;
import lissa.trading.lissa.auth.lib.exception.BadRequestException;
import lissa.trading.lissa.auth.lib.exception.ForbiddenException;
import lissa.trading.lissa.auth.lib.exception.NotFoundException;
import lissa.trading.lissa.auth.lib.exception.UnauthorizedException;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class CustomErrorDecoder implements ErrorDecoder {

    @Override
    public Exception decode(String methodKey, Response response) {
        String errorMessage = "Unknown error";

        try {
            if (response.body() != null) {
                String body = Util.toString(response.body().asReader(StandardCharsets.UTF_8));
                errorMessage = String.format("Error during the call to %s: Status %d, Body: %s",
                        methodKey, response.status(), body);
            } else {
                errorMessage = String.format("Error during the call to %s: Status %d",
                        methodKey, response.status());
            }
        } catch (IOException e) {
            log.error("Failed to read the response body", e);
        }

        return switch (response.status()) {
            case 400 -> new BadRequestException(errorMessage);
            case 401 -> new UnauthorizedException(errorMessage);
            case 403 -> new ForbiddenException(errorMessage);
            case 404 -> new NotFoundException(errorMessage);
            default -> new RuntimeException("General error: " + errorMessage);
        };
    }
}
