package Assigment2;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

public class Assignment_1_2 {

    // DES 알고리즘 지정
    private static final String ALGORITHM = "DES";
    // CBC 모드와 패딩 방식 지정
    private static final String TRANSFORMATION = "DES/CBC/PKCS5Padding";

    // DES 키 생성 메서드
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        // DES는 56-bit 키 사용
        keyGenerator.init(56);
        return keyGenerator.generateKey();
    }

    // IV 생성 메서드
    public static IvParameterSpec generateIV() {
        // DES 블록 크기는 8바이트
        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // 파일 암호화 메서드
    public static void encryptFile(SecretKey key, IvParameterSpec iv, String inputFilePath, String outputFilePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        // 암호화 모드와 IV 설정
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        // 평문 파일 읽기
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFilePath));

        // 암호화 수행
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // IV와 암호문을 함께 저장 (IV + 암호문)
        byte[] ivWithCipherText = new byte[iv.getIV().length + outputBytes.length];
        System.arraycopy(iv.getIV(), 0, ivWithCipherText, 0, iv.getIV().length);
        System.arraycopy(outputBytes, 0, ivWithCipherText, iv.getIV().length, outputBytes.length);

        Files.write(Paths.get(outputFilePath), Base64.getEncoder().encode(ivWithCipherText));
        System.out.println("암호화 파일 확인 완료 : " + outputFilePath);
    }

    // 파일 복호화 메서드
    public static void decryptFile(SecretKey key, String inputFilePath, String outputFilePath) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);

        // 암호문 파일 읽기
        byte[] inputBytes = Files.readAllBytes(Paths.get(inputFilePath));
        byte[] decodedBytes = Base64.getDecoder().decode(inputBytes);

        // IV와 암호문 분리
        byte[] iv = new byte[8];
        byte[] cipherText = new byte[decodedBytes.length - 8];
        System.arraycopy(decodedBytes, 0, iv, 0, iv.length);
        System.arraycopy(decodedBytes, iv.length, cipherText, 0, cipherText.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        // 복호화 모드와 IV 설정
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        // 복호화 수행
        byte[] outputBytes = cipher.doFinal(cipherText);

        // 복호화된 파일로 저장
        Files.write(Paths.get(outputFilePath), outputBytes);
        System.out.println("복호화 파일 확인 완료 : " + outputFilePath);
    }

    // 두 파일 동일 여부 확인 메서드
    public static boolean compareFiles(String filePath1, String filePath2) throws IOException {
        byte[] file1Bytes = Files.readAllBytes(Paths.get(filePath1));
        byte[] file2Bytes = Files.readAllBytes(Paths.get(filePath2));

        // 파일 내용을 비교하여 동일하면 true, 다르면 false 반환
        return java.util.Arrays.equals(file1Bytes, file2Bytes);
    }

    // 파일 내용 출력 메서드
    public static void printFileContent(String filePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(filePath)));
        System.out.println("파일 내용 (" + filePath + ") : \n" + content);
    }

    // 메인 메서드
    public static void main(String[] args) {
        try {
            // 1. DES 암호화 키 및 IV 생성
            SecretKey key = generateKey();
            IvParameterSpec iv = generateIV();

            // 2. 파일 경로 설정
            String inputFile = "/Users/thdtjdals__/Desktop/문서/컴퓨터보안과제.txt";  // 평문 파일
            String encryptedFile = "/Users/thdtjdals__/Desktop/문서/encrypted_컴퓨터보안과제.txt";  // 암호문 파일
            String decryptedFile = "/Users/thdtjdals__/Desktop/문서/decrypted_컴퓨터보안과제.txt";  // 복호화된 파일

            // 3. 파일 암호화
            encryptFile(key, iv, inputFile, encryptedFile);

            // 4. 파일 복호화
            decryptFile(key, encryptedFile, decryptedFile);

            // 5. 복호화된 파일과 원본 파일 비교
            boolean isSame = compareFiles(inputFile, decryptedFile);
            if (isSame) {
                System.out.println("복호화 성공 : 원본 파일과 일치합니다.");
            } else {
                System.out.println("복호화 실패 : 원본 파일과 일치하지 않습니다.");
            }

            // 6. 파일 내용 출력
            printFileContent(inputFile);
            printFileContent(encryptedFile);
            printFileContent(decryptedFile);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

