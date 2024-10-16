package Assigment1;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.Scanner;

public class DESDecryption {

    private static final String ALGORITHM = "DES";
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    // SecretKey 파일로부터 읽어오기
    public static SecretKey loadKey(String fileName) throws Exception {
        try (ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream(fileName))) {
            return (SecretKey) keyIn.readObject();
        }
    }

    // 복호화 메서드
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    // 메인 메서드
    public static void main(String[] args) {
        try {
            // SecretKey 파일로부터 불러오기
            SecretKey key = loadKey("secretKey.ser");

            Scanner scanner = new Scanner(System.in);
            String encryptedText = null;
            boolean decryptionSuccess = false; // 복호화 성공 여부를 판단하는 플래그

            while (!decryptionSuccess) {
                try {
                    // 사용자로부터 암호문 입력 받기
                    System.out.print("복호화할 암호문(Base64로 인코딩된 문자열)을 입력하세요 : ");
                    encryptedText = scanner.nextLine();

                    // 복호화 시도
                    String decryptedText = decrypt(encryptedText, key);
                    System.out.println("복호문 : " + decryptedText);
                    decryptionSuccess = true;  // 복호화 성공 시 루프 종료

                } catch (javax.crypto.BadPaddingException | IllegalArgumentException e) {
                    // 암호문이 잘못되었을 경우 예외 처리
                    System.out.println("잘못된 암호문이 입력되었습니다. 다시 시도하세요.");
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
