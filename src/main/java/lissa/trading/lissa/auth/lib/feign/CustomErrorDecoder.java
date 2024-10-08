package lissa.trading.lissa.auth.lib.feign;

import feign.Response;
import feign.codec.ErrorDecoder;
import lissa.trading.lissa.auth.lib.exception.BadRequestException;
import lissa.trading.lissa.auth.lib.exception.ForbiddenException;
import lissa.trading.lissa.auth.lib.exception.NotFoundException;
import lissa.trading.lissa.auth.lib.exception.UnauthorizedException;

public class CustomErrorDecoder implements ErrorDecoder {

    @Override
    public Exception decode(String methodKey, Response response) {
        return switch (response.status()) {
            case 400 -> new BadRequestException("Bad request");
            case 401 -> new UnauthorizedException("Unauthorized access");
            case 403 -> new ForbiddenException("Access is forbidden");
            case 404 -> new NotFoundException("Resource not found");
            default -> new Exception("Generic error");
        };
    }
}