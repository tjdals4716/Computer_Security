package Assigment2;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class Assignment_1 {

    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";

    // DES 키 생성 메서드
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(56);
        return keyGenerator.generateKey();
    }

    // IV 생성 메서드 (랜덤)
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // 파일 암호화 메서드 (CBC 모드)
    public static void encryptFile(SecretKey key, IvParameterSpec iv, String inputFilePath, String outputFilePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFilePath));
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // IV를 파일에 함께 저장하기 위해 IV + 암호문 형식으로 파일 작성
        byte[] ivAndEncrypted = new byte[iv.getIV().length + outputBytes.length];
        System.arraycopy(iv.getIV(), 0, ivAndEncrypted, 0, iv.getIV().length);
        System.arraycopy(outputBytes, 0, ivAndEncrypted, iv.getIV().length, outputBytes.length);

        Files.write(Paths.get(outputFilePath), Base64.getEncoder().encode(ivAndEncrypted));
        System.out.println("암호화 파일 확인 완료 : " + outputFilePath);
    }

    // 파일 복호화 메서드 (CBC 모드)
    public static void decryptFile(SecretKey key, String inputFilePath, String outputFilePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFilePath));
        byte[] decodedBytes = Base64.getDecoder().decode(inputBytes);

        // 저장된 IV를 분리하고 복호화 수행
        byte[] iv = new byte[8];
        byte[] encryptedData = new byte[decodedBytes.length - iv.length];

        System.arraycopy(decodedBytes, 0, iv, 0, iv.length);
        System.arraycopy(decodedBytes, iv.length, encryptedData, 0, encryptedData.length);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] outputBytes = cipher.doFinal(encryptedData);

        Files.write(Paths.get(outputFilePath), outputBytes);
        System.out.println("복호화 파일 확인 완료 : " + outputFilePath);
    }
}

