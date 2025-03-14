
import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAClass {

    private KeyPairGenerator keyPairGenerator;
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAClass() throws Exception{
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");  //RSA를 위한 키 페어 생성
        this.keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public String encrypt(String plainText) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);       //공개키로 암호화
        return Base64.getEncoder().encodeToString(encryptCipher.doFinal(plainText.getBytes()));
    }

    public String decrypt(String cipherText) throws Exception {
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);    //비밀키로 복호화
        return new String(decryptCipher.doFinal(Base64.getDecoder().decode(cipherText)));
    }

}
