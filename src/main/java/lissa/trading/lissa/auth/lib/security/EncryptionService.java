package lissa.trading.auth_security_lib.security;

import lissa.trading.auth_security_lib.exception.EncryptionTokenException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

@Service
@Slf4j
public class EncryptionService {

    private EncryptionService() {
        throw new IllegalStateException("Utility class");
    }

    private static final SecretKey secretKey;
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    // Ваш ключ (должен быть Base64 закодирован и иметь размер 32 байта после декодирования)
    private static final String SECRET_KEY_STRING = "tDfV5xlY9Fv5eH7orlcQRQhaQDevNIKHKj8I+WFqor0=";

    static {
        byte[] keyBytes = null;
        try {
            keyBytes = Base64.getDecoder().decode(SECRET_KEY_STRING);
        } catch (Exception e) {
            throw new IllegalArgumentException("Ключ должен быть длиной 256 бит (32 байта) и корректно закодирован в Base64.", e);
        }
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("Ключ должен быть длиной 256 бит (32 байта).");
        }
        synchronized (EncryptionService.class) {
            secretKey = new SecretKeySpec(keyBytes, "AES");
        }
    }

    public static String encrypt(String plainText) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] cipherText = cipher.doFinal(plainText.getBytes());
            byte[] ivAndCipherText = ByteBuffer.allocate(iv.length + cipherText.length).put(iv).put(cipherText).array();
            return Base64.getEncoder().encodeToString(ivAndCipherText);
        } catch (Exception e) {
            log.error("Encryption error in class {}", EncryptionService.class);
            throw new EncryptionTokenException("Encryption error", e);
        }
    }

    public static String decrypt(String cipherText) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            byte[] ivAndCipherText = Base64.getDecoder().decode(cipherText);
            ByteBuffer byteBuffer = ByteBuffer.wrap(ivAndCipherText);
            byte[] iv = new byte[IV_LENGTH_BYTE];
            byteBuffer.get(iv);
            byte[] cipherTextBytes = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherTextBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            byte[] plainText = cipher.doFinal(cipherTextBytes);
            return new String(plainText);
        } catch (Exception e) {
            log.error("Decryption error in class {}", EncryptionService.class);
            throw new EncryptionTokenException("Decryption error", e);
        }
    }
}