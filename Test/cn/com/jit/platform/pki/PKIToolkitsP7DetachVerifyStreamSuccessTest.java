package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CER_2048;
import static cn.com.jit.platform.pki.SignHelper.SM2_PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.SM2_SIGN_CER;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7DetachVerifyStreamSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { 
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_SHA1, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_SHA256, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_MD5, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SignHelper.SM2_FLAG_DETTACH, PLAIN,handleResult}
		};
		return Arrays.asList(objects);
	}
	
	private byte[] privateKey;
	private byte[] publicKeyCert;
	private byte[] originalData;
	private String digestArithmeticType;
	private HandleResult out;
	private int flag;

	public PKIToolkitsP7DetachVerifyStreamSuccessTest(byte[] privateKey,byte[] publicKeyCert,String digestArithmeticType,int flag,byte[] originalData,HandleResult out) {
		super();
		this.digestArithmeticType = digestArithmeticType;
		this.originalData = originalData;
		this.out=out;
		this.publicKeyCert = publicKeyCert;
		this.privateKey = privateKey;
		this.flag = flag;
	}

	@Test
	public void p7DetachVerifyStreamTest() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult sign=su.p7SignStream(originalData,flag,privateKey,publicKeyCert, digestArithmeticType);
		
		byte[] signData = sign.resultData;
		pkiTool.p7detachVerifyInit(signData, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > originalData.length){
				endIndex=originalData.length;
				blocks = new byte[originalData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(originalData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7detachVerifyUpdate(out.handle, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=originalData.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7detachVerifyFinal(out.handle, resultTmp);
		resultTmp.setResultData(StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData()));
		Assert.assertEquals(digestArithmeticType, new String(resultTmp.hashAlg));
	}
	 
}
