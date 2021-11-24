package org.zz.gmhelper.test;

import com.longmai.util.encoders.Base64;
import com.longmai.util.encoders.Hex;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;

import java.math.BigInteger;

public class SM2Verify {
    public static void main(String[] args) {

        testSM2KeyRecovery();

    }
    @Test
    public static void testSM2KeyRecovery() {
        try {
            //String priHex = "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D";
            String xHex = "747e80f75600a2e5475781ccf5f9e558e6c8cecd80d7e95bd8ae7a1eed07f204";
            String yHex = "4619b3a5908cd8fdaddaedd18919e7a65534f0275e7ecb65c64712a0ce033225";
            //String signHex = "3046022100AF5096DFC919B328FC51828F7A0219D941EA263692F5D93DFA9331104519EB47022100FE01EA76C8F46949818FE50F72B73E34D0853D01BE3E103DFEBB563FF29DC6BD";
//            String r  = "7942BE665D8D0AA44BC2788505192442454AAC218854AF66B8EC61FD88C2FCAE";
//            String s =  "A442461B816595E872E0E7AAF7A6A491B642506C278119AFC46CD6E0D4BD3C18";
           // byte[] rsData =  ByteUtils.fromHexString(r+s);
            byte[] signHexToDer = Base64.decode("MEQCIHgBqzI6836teLVDtJD8dAicsBcfc9li8vBtaiKGO3aMAiBFDqvBrqf+V0duv8mggBd2UxQdv4yoNXhPPW4R1CoY1Q==");
            // byte[] signHexToDer =  SM2Util.encodeSM2SignToDER(rsData);
           // System.err.println(Hex.toHexString(signHexToDer));
            byte[] src = "ac0c47fbb5942e5e39bbafb0iJa1JRm3GQRMq753695qMu3M0109212000142".getBytes();
            byte[] withId ="1234567812345678".getBytes();
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            if (!SM2Util.verify(pubKey,withId, src, signHexToDer)) {
                Assert.fail("verify failed");
            }
            else{
                System.err.println("verify success");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

}
