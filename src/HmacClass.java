import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HmacClass {
    private SecretKeySpec secretKeySpec;
    private String algorithm;
    public HmacClass(String key, String algorithm) throws Exception {
        this.algorithm = algorithm;
        this.secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
    }

    public String encrypt(String plainText) throws Exception {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        return Base64.getEncoder().encodeToString(mac.doFinal(plainText.getBytes()));  //hmac 암호화
    }
}
