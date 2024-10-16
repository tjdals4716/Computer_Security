package Assigment1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.Scanner;

public class DESEncryption {

    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    // DES 키 생성
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(56);
        return keyGenerator.generateKey();
    }

    // 암호화 메서드
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // SecretKey 파일로 저장
    public static void saveKey(SecretKey key, String fileName) throws Exception {
        try (ObjectOutputStream keyOut = new ObjectOutputStream(new FileOutputStream(fileName))) {
            keyOut.writeObject(key);  // SecretKey를 파일로 저장
        }
    }

    // 메인 메서드
    public static void main(String[] args) {
        try {
            // DES 키 생성
            SecretKey key = generateKey();

            // 평문 설정
            Scanner scanner = new Scanner(System.in);
            System.out.print("암호화할 평문을 입력하세요 : ");
            String plainText = scanner.nextLine();
            System.out.println("평문: " + plainText);

            // 암호화
            String encryptedText = encrypt(plainText, key);
            System.out.println("암호문: " + encryptedText);

            // SecretKey 파일로 저장
            saveKey(key, "secretKey.ser");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
