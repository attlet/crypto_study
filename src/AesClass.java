import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesClass {
    private final SecretKeySpec secretKeySpec;
    private String iv = "qwertasdfgzxcvbq";
    //생성자를 통해 객체 생성 시 원하는 키값을 입력
    public AesClass(String secretKey) throws Exception{
        this.secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "AES");  //AES를 위한 비밀 키 생성
    }

    //매개변수로 받은 평문을 암호화
    public String encrypt(String plainText, String algorithm) throws Exception{
        Cipher encryptCipher = Cipher.getInstance(algorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());
        if(algorithm.equals("AES/CBC/PKCS5Padding"))
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        else
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        //암호화할 수 있도록 초기화
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());  //암호화 진행
        return Base64.getEncoder().encodeToString(cipherText);
    }

    //매개변수로 받은 암호문을 복호화
    public String decrypt(String cipherText, String algorithm) throws Exception{
        Cipher decryptCipher = Cipher.getInstance(algorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes());

        if(algorithm.equals("AES/CBC/PKCS5Padding"))
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        else
            decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        //복호화할 수 있도록 초기화
        byte[] decryptedText = decryptCipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decryptedText);         //복호화 진행
    }
}
