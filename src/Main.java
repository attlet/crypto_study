import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {


    public static void main(String[] args) throws Exception {

        String beforeMessage = "hello world";   //암호화하려고 하려는 메시지
        AesClass aesClass = new AesClass("forSecretkey!@#$");  //AES 알고리즘

        String CBCencryptedMessage = aesClass.encrypt(beforeMessage, "AES/CBC/PKCS5Padding");
        String CBCdecryptedMessage = aesClass.decrypt(CBCencryptedMessage, "AES/CBC/PKCS5Padding");
        String EBCencryptedMessage = aesClass.encrypt(beforeMessage, "AES/ECB/PKCS5Padding");
        String EBCdecryptedMessage = aesClass.decrypt(EBCencryptedMessage, "AES/ECB/PKCS5Padding");

        System.out.println("AES start"); //AES 알고리즘
        System.out.println("before message : " + beforeMessage);
        System.out.println("CBC encrypted message : " + CBCencryptedMessage);
        System.out.println("CBC decrypted message : " + CBCdecryptedMessage);
        System.out.println("EBC encrypted message : " + EBCencryptedMessage);
        System.out.println("EBC decrypted message : " + EBCdecryptedMessage);

        System.out.println("--------------------------------------------------------");
        RSAClass rsaClass = new RSAClass();   //RSA알고리즘

        String encrypted = rsaClass.encrypt(beforeMessage);
        String decrypted = rsaClass.decrypt(encrypted);

        System.out.println("RSA start");
        System.out.println("before message : " + beforeMessage);
        System.out.println("encrypted message : " + encrypted);  //실행할 때 마다 다름, 소수 생성되는 게 랜덤이기 때문.
        System.out.println("decrypted message : " + decrypted);

        System.out.println("--------------------------------------------------------");

        MdcClass mdcClass = new MdcClass();   //MDC는 단방향 암호화 -> 복호화 과정 불가
        byte[] encryptedMdc = mdcClass.encrypt(beforeMessage);

        System.out.println("MDC start");
        System.out.println("before message : " + beforeMessage);
        System.out.println("encrypted message : " + new String(encryptedMdc));

        System.out.println("--------------------------------------------------------");
        HmacClass hmacMD5 = new HmacClass("forSecretkey!", "HmacMD5");  // hmac에서 사용하는 해시 함수들 적용
        HmacClass hmacSHA256 = new HmacClass("forSecretkey!", "HmacSHA256");
        HmacClass hmacSHA512 = new HmacClass("forSecretkey!", "HmacSHA512");

        String encryptedHmacMD5 = hmacMD5.encrypt(beforeMessage);
        String encryptedSHA256 = hmacSHA256.encrypt(beforeMessage);
        String encryptedSHA512 = hmacSHA512.encrypt(beforeMessage);

        System.out.println("HMAC start");
        System.out.println("before message : " + beforeMessage);
        System.out.println("encrypted message using md5 : " + encryptedHmacMD5);
        System.out.println("encrypted message using sha256: " + encryptedSHA256);
        System.out.println("encrypted message using sha512: " + encryptedSHA512);

        System.out.println("--------------------------------------------------------");
        SignatureClass signatureClass = new SignatureClass();
        System.out.println("Signature start");
        System.out.println("before message : " + beforeMessage);
        System.out.println("signature result : " + signatureClass.verify(beforeMessage));


    }
}