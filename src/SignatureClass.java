import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class SignatureClass {
    public String verify(String plainText) throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        //서명 객체 생성 및 초기화
        //RSA 와 sha256으로 지정
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());

        //서명이 필요한 평문을 입력
        signature.update(plainText.getBytes());

        //서명 진행
        byte[] signatureBytes = signature.sign();

        //signature을 검증하는 객체로 변경
        signature.initVerify(keyPair.getPublic());

        //서명 검증을 진행
        signature.update(plainText.getBytes());

        //검증 결과
        boolean verify = signature.verify(signatureBytes);

        return verify ? "verify success" : "verify failed";

    }
}
