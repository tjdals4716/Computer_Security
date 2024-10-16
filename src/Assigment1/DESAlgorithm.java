package Assigment1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Scanner;

public class DESAlgorithm {

    private static final String ALGORITHM = "DES";  // DES 알고리즘 명시
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";  // ECB 모드와 PKCS5 패딩 방식 지정

    // DES 키 생성 메서드
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(56);  // DES는 56-bit 키 사용
        return keyGenerator.generateKey();
    }

    // 문자열 암호화 메서드
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);  // 암호화 알고리즘 설정
        cipher.init(Cipher.ENCRYPT_MODE, key);  // 암호화 모드 설정

        // 평문을 바이트 배열로 변환 후 암호화
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        // 암호화된 바이트 배열을 Base64로 인코딩하여 문자열로 반환
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // 문자열 복호화 메서드
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);  // 복호화 알고리즘 설정
        cipher.init(Cipher.DECRYPT_MODE, key);  // 복호화 모드 설정

        // 암호문을 Base64로 디코딩 후 복호화
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        // 복호화된 바이트 배열을 문자열로 변환하여 반환
        return new String(decryptedBytes);
    }

    // 메인 메서드
    public static void main(String[] args) {
        try {
            // 1. DES 키 생성
            SecretKey key = generateKey();

            // 2. 사용자로부터 평문 입력 받기
            Scanner scanner = new Scanner(System.in);
            System.out.print("암호화할 평문을 입력하세요 : ");
            String plainText = scanner.nextLine();

            // 3. 암호화
            String encryptedText = encrypt(plainText, key);
            System.out.println("암호문 : " + encryptedText);

            // 4. 복호화
            String decryptedText = decrypt(encryptedText, key);
            System.out.println("복호문 : " + decryptedText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
