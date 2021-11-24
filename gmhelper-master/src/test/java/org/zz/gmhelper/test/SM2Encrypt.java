package org.zz.gmhelper.test;

import com.longmai.util.encoders.Base64;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Cipher;
import org.zz.gmhelper.SM2Util;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class SM2Encrypt {
    public static void main(String[] args) throws InvalidCipherTextException {
        byte[] xHex = Hex.decode("810F5E7EA1881F3F1F6472B4A8850966A46A8264C9FF88C8A7ABA36F5E786AC3");
        byte[] yHex = Hex.decode("B7753BA061AC72A34F31E219820F6DBD8BE2B0AB16A5984AFC57B118AD3C8387");
        byte[] sessionKey = "12345678123456781234567812345678".getBytes();
        byte[] buffer = sm2Encrypt(xHex,yHex,sessionKey);
        System.out.println(" Base64 buffer = "+ Base64.toBase64String(buffer));
        System.out.println("Hex buffer = "+Hex.toHexString(buffer));


    }

    public static   byte[] sm2Encrypt(byte[] xHex ,byte[] yHex, byte[] sessionKey) throws InvalidCipherTextException {
        ECPublicKeyParameters srcpubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);
        byte[] CipherBlob = SM2Util.encrypt(srcpubKey, sessionKey); //公钥加密会话秘钥
        ByteBuffer buff = ByteBuffer.allocate(164+sessionKey.length);
        System.out.println("cipdata  = "+Hex.toHexString(CipherBlob));
        byte[] xTemp = new byte[32];
        byte[] yTemp = new byte[32];
        byte[] hashData = new byte[32];
        System.arraycopy(CipherBlob,1,xTemp,0,32);
        System.arraycopy(CipherBlob,33,yTemp,0,32);
        SM2Cipher cip =  SM2Util.parseSM2Cipher(CipherBlob);
        byte[] c1 = cip.getC1();
        byte[] c2 = cip.getC2();
        byte[] c3 = cip.getC3();
        buff.put(new byte[32]);
        buff.put(Arrays.copyOfRange(c1, 1, 33));
        buff.put(new byte[32]);
        buff.put(Arrays.copyOfRange(c1, 33, 65));
        buff.put(SM2Util.fixToCurveLengthBytes(c3));
        buff.put(Hex.decode("20000000"));   //密文长度 ，数据长度不同 传入的数据不同。
        buff.put(c2);
        return buff.array();

    }





//    // ECC密文数据结构
//    typedef struct Struct_ECCCIPHERBLOB{
//        BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];64
//        BYTE	YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];64
//        BYTE	HASH[32];32
//        UINT32	CipherLen;32
//        BYTE	Cipher[1];
//    } ECCCIPHERBLOB, *PECCCIPHERBLOB;


}
