# lissa-auth-security-lib

## Описание

`auth-security-lib` — библиотека для работы с JWT токенами, интеграцией Feign и шифрованием.

### Возможности:

1. Быстрый доступ к информации о пользователе из **контекста**.
2. Удобное создание классов для проверки JWT и других токенов.
3. Автоматическое шифрование токенов.

## Установка

Клонируйте репозиторий и установите библиотеку в локальный репозиторий Maven.

```shell
git clone https://github.com/vladdossik/lissa-trading-auth-lib.git
```
После клонирования перейдите в папку с проектом и выполните команду:
```shell
mvn clean install
```

Для использования библиотеки добавьте соответствующую зависимость в ваш проект Maven.

```xml
<dependency>
    <groupId>lissa.trading</groupId>
    <artifactId>auth-security-lib</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

В application.yaml укажите URL для интеграции с сервисами.

```yaml 
integration:
  rest:
    auth-service-url:http://localhost:8080
```

### Требования

- Java 17
- Spring Boot 3.3.3
- Spring Cloud 2023.0.3

## Конфигурация

1. **Feign-клиент для авторизации и получения данных пользователя из контекста (JWT):**

```java
@FeignClient(
        name = "auth-service",
        url = "${integration.rest.auth-service-url}",
        configuration = FeignConfiguration.class
)
public interface AuthServiceClient {
    @PostMapping("/v1/auth/user-info")
    UserInfoDto getUserInfo(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader);
}
```

2. **Конфигурация фильтра авторизации:**

```java
@Slf4j
public abstract class BaseAuthTokenFilter<T> extends OncePerRequestFilter {
    // Реализация логики фильтрации запросов с JWT токенами
    // Переопределение методов для работы с пользователями и ролями
}
```

3. **Конфигурация безопасности:**

```java
public abstract class BaseWebSecurityConfig {
    // Реализация настройки цепочки безопасности Spring,
    // добавление кастомных фильтров, сессионной политики и авторизации запросов
}
```

4. **Шифрование данных:**

```java
@Slf4j
public class EncryptionService {
    public static String encrypt(String plainText) {
        // Шифрование текста с использованием AES
    }

    public static String decrypt(String cipherText) {
        // Расшифровка текста
    }
}
```

## Инструкция по запуску

1. Добавьте библиотеку в зависимости Maven.
2. Убедитесь, что ваш `application.properties` или `application.yaml` содержит правильные URL для интеграции с
   сервисами.
3. Если необходимо, настройте Feign-клиент и используйте его для взаимодействия с вашим сервисом авторизации.
4. Реализуйте свои классы, унаследованные от `BaseAuthTokenFilter` и `BaseWebSecurityConfig`, для настройки фильтров
   безопасности.
5. В сервисе авторизации реализуйте метод для получения информации о пользователе по токену и добавления в SecurityContextHolder
6. Используйте `EncryptionService` для безопасного шифрования и расшифровки данных.

## Пример использования

BaseAuthTokenFilter

```java
public class AuthTokenFilter extends BaseAuthTokenFilter<UserInfoDto> {
    // обязательные методы для переопределения
    @Override
    protected List<String> parseRoles(UserInfoDto userInfo) {
        return userInfo.getRoles();
    }

    @Override
    protected UserInfoDto retrieveUserInfo(String token) {
        return authServiceClient.getUserInfo("Bearer " + token);
    }

    // Дополнительные методы, необязательные для переопределения
    @Override
    protected boolean shouldSkipFilterAddons(String requestURI) {
        return requestURI.equals("/v1/auth/signup");
    }
}
```

BaseWebSecurityConfig

```java

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig extends BaseWebSecurityConfig {
    // обязательный конструктор
    public WebSecurityConfig(BaseAuthTokenFilter<UserInfoDto> authTokenFilter) {
        super(authTokenFilter);
    }
    // Дополнительные методы, необязательные для переопределения. Можно ничего не переопределять
}
```

Использование контекста для создания пользователя

```java
@PostMapping("/register")
public ResponseEntity<String> registerUser(@AuthenticationPrincipal UserInfoDto userInfo) {
    tempUserCreationService.createTempUser(userInfo);
    return ResponseEntity.ok("User registration successful");
}
```

```java
@Override
@Transactional
public void createTempUser(UserInfoDto userInfoDto) {
    TempUserReg savedTempUser = tempUserRegRepository.save(userInfoDto);
}
```
