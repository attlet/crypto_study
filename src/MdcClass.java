import java.security.MessageDigest;

public class MdcClass {
    public byte[] encrypt(String plainText) throws Exception{
        MessageDigest messageDigest = MessageDigest.getInstance("SHA256");  //단방향 해시 알고리즘 기능을 제공하는 클래스
        byte[] encryptedMessage = messageDigest.digest(plainText.getBytes());
        return encryptedMessage;
    }
}
