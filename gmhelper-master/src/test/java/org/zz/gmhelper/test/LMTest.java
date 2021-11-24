package org.zz.gmhelper.test;
import com.longmai.mtoken.GM3000Jna;
import com.longmai.mtoken.GM3000Lib;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.zz.gmhelper.*;
import org.zz.gmhelper.cert.CommonUtil;
import org.zz.gmhelper.cert.SM2PublicKey;
import org.zz.gmhelper.cert.SM2X509CertMaker;
import org.zz.gmhelper.cert.test.SM2PfxMakerTest;
import org.zz.gmhelper.cert.test.SM2X509CertMakerTest;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.OperationNotSupportedException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LMTest extends GMBaseTest
{

    //private static GM3000Lib skf = GM3000Jna.getInstance();
    private  static  String xHex = "";
    private static String yHex = "";
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, SignatureException, OperationNotSupportedException, OperatorCreationException {
        // dn主题
//        String dn2 = "CN=zdfg, OU=ert, O=er, L=fgj, ST=vfgh, C=CN";
//        String subject = "1.2.156.10197.1.301";
        // String p10 =   P10List.genCSR(dn2,"sm2",subject);
        //  System.err.println("P10 ="+p10);
       // byte[] pub =    LMUSBKey.exportKeyPublic(1); //导出公钥

        //公钥
        byte[] pub = Hex.decode("9803F6EF06F6FF8C11970926207CE2D48D75D00C5369A37169D06FD15795F17275C00E3160427B51695D0255AA1C292555E007E4CB2044C2A5C08B85DF79AE29");
        System.err.println("PUB= "+Hex.toHexString(pub));
        byte[] envData = Hex.decode(ENVELOPEDKEYBLOB(pub)); //生成加密秘钥密文。
        System.err.println("envData = "+Hex.toHexString(envData));

//                  int con = LMUSBKey.getCon();
//                    System.err.println("con = "+con);
//                    int ret = skf.SKF_ImportECCKeyPair(con,envData);
//                    System.err.println("ret = "+ret);
//
//         SM4Encrypt(xHex,yHex); //SM4 加密
//        byte[] cipherText = Hex.decode("DEA3A778746464D0A44437F800ADFB21782720BB3D266AB75193841F210DFA75");
//        byte[] key = Hex.decode("C32F3B4AC8789F83144F963B884BBC86");
//        byte[] prikey = SM4Dencrypt(key,cipherText);
//        byte[] data = Hex.decode("00000000000000000000000000000000000000000000000000000000000000009eaa7d3da0d2358ea4f733c1617f76b71dd63c7cf43ff4c7a629a5a68e9e6dba3132333435363738313233343536373800000000000000000000000000000000000000000000000000000000000000003452c4cb77fc9db07d2df9b9cc38e7b40bd36b6cd1abf305cfd72400093c2ccd");
//        byte[] outData = SM3Util.hash(data);
//        System.err.println(Hex.toHexString(outData));
//        System.err.println("prikey = "+Hex.toHexString(prikey));
    }

    public  static byte[]  SM4Dencrypt(byte[]  key,byte[] cipherText) throws BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException {

        byte[] prikey =  SM4Util.decrypt_Ecb_NoPadding(key,cipherText);
        return prikey;
    }





    //sm4加密会话密钥
    public static void SM4Encrypt(String xHex,String yHex)
    {

        byte[] sessionKey = "1122334455667788".getBytes();

        ECPublicKeyParameters srcpubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);
        try {
            byte[] CipherBlob = SM2Util.encrypt(srcpubKey,sessionKey);
            SM2Cipher cip =  SM2Util.parseSM2Cipher(CipherBlob);
            byte[] c1 = cip.getC1();
            byte[] c2 = cip.getC2();
            byte[] c3 = cip.getC3();
            ByteBuffer buff = ByteBuffer.allocate(180);
            buff.put(new byte[32]);
            buff.put(Arrays.copyOfRange(c1,1,33));
            buff.put(new byte[32]);
            buff.put(Arrays.copyOfRange(c1, 33, 65));
            buff.put(SM2Util.fixToCurveLengthBytes(c3));
            buff.put(Hex.decode("20000000"));
            buff.put(c2);

        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }



    //生成加密密钥的密文
    public static String ENVELOPEDKEYBLOB(byte[] inPubkey)
    {
        ByteBuffer buff = ByteBuffer.allocate(388);
        try {


            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubkey = (ECPublicKeyParameters) keyPair.getPublic();
            byte[] xHex = new byte[32];
            byte[] yHex = new byte[32];
            System.arraycopy(inPubkey,0,xHex,0,32);
            System.arraycopy(inPubkey,32,yHex,0,32);
            ECPublicKeyParameters srcpubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey  = (ECPublicKeyParameters) keyPair.getPublic();//
            byte[] sessionKey = "1234567812345678".getBytes();
            //srcpukey

            byte[] CipherBlob = SM2Util.encrypt(srcpubKey, sessionKey); //公钥加密会话秘钥
            SM2Cipher cip =  SM2Util.parseSM2Cipher(CipherBlob);
            byte[] c1 = cip.getC1();
            byte[] c2 = cip.getC2();
            byte[] c3 = cip.getC3();
            System.err.println("CipherBlob = "+Hex.toHexString(CipherBlob));
            byte[] cbEncryptedPriKey = SM4Util.encrypt_Ecb_NoPadding(sessionKey, SM2Util.fixToCurveLengthBytes(priKey.getD().toByteArray())); //SM4加密 加密秘钥对

            buff.put(Hex.decode("010000000104000000010000"));
            buff.put(new byte[32]);
            buff.put(cbEncryptedPriKey);
            buff.put(Hex.decode("00010000"));
            buff.put(new byte[32]);
            buff.put(SM2Util.fixToCurveLengthBytes(pubkey.getQ().getXCoord().getEncoded()));
            buff.put(new byte[32]);
            buff.put(SM2Util.fixToCurveLengthBytes(pubkey.getQ().getYCoord().getEncoded()));
            buff.put(new byte[32]);
            buff.put(Arrays.copyOfRange(c1, 1, 33));
            buff.put(new byte[32]);
            buff.put(Arrays.copyOfRange(c1, 33, 65));
            buff.put(SM2Util.fixToCurveLengthBytes(c3));
            buff.put(Hex.decode("10000000"));
            buff.put(c2);


            ByteBuffer ciperBuff = ByteBuffer.allocate(180);
            ciperBuff.put(Arrays.copyOfRange(buff.array(),208,388));

            System.err.println("PENVELOPEDKEYBLOB : "+Hex.toHexString(buff.array()));
            System.err.println("ECCCIPHERBLOB : "+Hex.toHexString(ciperBuff.array()));
            System.out.println("X = "+Hex.toHexString(pubKey.getQ().getXCoord().getEncoded()));
            System.out.println("Y = "+Hex.toHexString(pubKey.getQ().getYCoord().getEncoded()));

        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
        return Hex.toHexString(buff.array());
    }
    private static byte[] intToByte(int val) {
        byte[] b = new byte[4];
        b[0] = (byte) (val & 0xff);
        b[1] = (byte) ((val >> 8) & 0xff);
        b[2] = (byte) ((val >> 16) & 0xff);
        b[3] = (byte) ((val >> 24) & 0xff);

        return b;
    }
}
