package lissa.trading.auth_security_lib.feign;

import feign.Response;
import feign.codec.ErrorDecoder;
import lissa.trading.auth_security_lib.exception.BadRequestException;
import lissa.trading.auth_security_lib.exception.ForbiddenException;
import lissa.trading.auth_security_lib.exception.NotFoundException;
import lissa.trading.auth_security_lib.exception.UnauthorizedException;

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