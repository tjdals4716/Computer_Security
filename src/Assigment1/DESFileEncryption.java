package Assigment1;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class DESFileEncryption {

    private static final String ALGORITHM = "DES";  // DES 알고리즘 지정
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";  // ECB 모드와 패딩 방식 지정

    // DES 키 생성 메서드
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(56);  // DES는 56-bit 키 사용
        return keyGenerator.generateKey();
    }

    // 파일 암호화 메서드
    public static void encryptFile(SecretKey key, String inputFilePath, String outputFilePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key);  // 암호화 모드로 설정

        // 평문 파일 읽기
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFilePath));

        // 암호화 수행
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // 암호문 파일로 저장
        Files.write(Paths.get(outputFilePath), Base64.getEncoder().encode(outputBytes));
        System.out.println("암호화 파일 확인 완료 : " + outputFilePath);
    }

    // 파일 복호화 메서드
    public static void decryptFile(SecretKey key, String inputFilePath, String outputFilePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key);  // 복호화 모드로 설정

        // 암호문 파일 읽기
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFilePath));

        // Base64 디코딩 후 복호화 수행
        byte[] decodedBytes = Base64.getDecoder().decode(inputBytes);
        byte[] outputBytes = cipher.doFinal(decodedBytes);

        // 복호화된 파일로 저장
        Files.write(Paths.get(outputFilePath), outputBytes);
        System.out.println("복호화 파일 확인 완료 : " + outputFilePath);
    }

    // 두 파일이 동일 여부 확인 메서드
    public static boolean compareFiles(String filePath1, String filePath2) throws IOException {
        byte[] file1Bytes = Files.readAllBytes(Paths.get(filePath1));
        byte[] file2Bytes = Files.readAllBytes(Paths.get(filePath2));

        // 파일 내용을 비교하여 동일하면 true, 다르면 false 반환
        return java.util.Arrays.equals(file1Bytes, file2Bytes);
    }

    // 메인 메서드
    public static void main(String[] args) {
        try {
            // 1. DES 암호화 키 생성
            SecretKey key = generateKey();

            // 2. 파일 경로 설정
            String inputFile = "/Users/thdtjdals__/Desktop/문서/컴퓨터보안과제.rtf";  // 평문 파일
            String encryptedFile = "/Users/thdtjdals__/Desktop/문서/컴퓨터보안과제.rtf";  // 암호문 파일
            String decryptedFile = "/Users/thdtjdals__/Desktop/문서/컴퓨터보안과제.rtf";  // 복호화된 파일

            // 3. 파일 암호화
            encryptFile(key, inputFile, encryptedFile);

            // 4. 파일 복호화
            decryptFile(key, encryptedFile, decryptedFile);

            // 5. 복호화된 파일과 원본 파일 비교
            boolean isSame = compareFiles(inputFile, decryptedFile);
            if (isSame) {
                System.out.println("복호화 성공 : 원본 파일과 일치합니다.");
            } else {
                System.out.println("복호화 실패 : 원본 파일과 일치하지 않습니다.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

