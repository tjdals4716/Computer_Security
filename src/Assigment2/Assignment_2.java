package Assigment2;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Assignment_2 {

    // 두 파일 동일 여부 확인 메서드
    public static boolean compareFiles(String filePath1, String filePath2) throws IOException {
        byte[] file1Bytes = Files.readAllBytes(Paths.get(filePath1));
        byte[] file2Bytes = Files.readAllBytes(Paths.get(filePath2));

        return java.util.Arrays.equals(file1Bytes, file2Bytes);
    }

    // 파일 내용 출력 메서드
    public static void printFileContent(String filePath) throws IOException {
        String content = new String(Files.readAllBytes(Paths.get(filePath)));
        System.out.println("파일 내용 (" + filePath + ") : \n" + content);
    }

    public static void main(String[] args) {
        try {
            // 1. DES 암호화 키와 IV 생성
            SecretKey key = Assignment_1.generateKey();
            IvParameterSpec iv = Assignment_1.generateIv();

            // 2. 파일 경로 설정
            String inputFile = "/Users/thdtjdals__/Desktop/문서/컴퓨터보안과제.txt";
            String encryptedFile = "/Users/thdtjdals__/Desktop/문서/encrypted_컴퓨터보안과제.txt";
            String decryptedFile = "/Users/thdtjdals__/Desktop/문서/decrypted_컴퓨터보안과제.txt";

            // 3. 파일 암호화
            Assignment_1.encryptFile(key, iv, inputFile, encryptedFile);

            // 4. 파일 복호화
            Assignment_1.decryptFile(key, encryptedFile, decryptedFile);

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

