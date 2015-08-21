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
public class PKIToolkitsP7DetachSignStreamSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { 
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256,  SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5,  SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_SHA1,  SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_SHA256,  SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_MD5,  SignHelper.FLAG_DETTACH, PLAIN,handleResult},
				{SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SignHelper.SM2_FLAG_DETTACH, PLAIN,handleResult}
		};
		return Arrays.asList(objects);
	}

	private byte[] privateKey;
	private byte[] publicKeyCert;
	private String digestArithmeticType;
	private int flag;
	private byte[] originalData;
	private HandleResult out;

	public PKIToolkitsP7DetachSignStreamSuccessTest(byte[] privateKey,byte[] publicKeyCert,String digestArithmeticType, int flag, byte[] originalData,HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.publicKeyCert = publicKeyCert;
		this.digestArithmeticType = digestArithmeticType;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}

	@Test
	public void p7SignStreamTest() {
		pkiTool.p7SignInit(privateKey, publicKeyCert, digestArithmeticType, originalData.length, flag, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int end = index + step;
			if(end > originalData.length){
				end = originalData.length;
				blocks = new byte[originalData.length-index];
			}
			blocks = Arrays.copyOfRange(originalData, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7SignUpdate(out.handle, publicKeyCert, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=originalData.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(out.handle, publicKeyCert,null,	resultTmp);
		resultTmp.setResultData(StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData()));
		HandleResult verifyData = new HandleResult();
		
		StreamTestUtil verify = new StreamTestUtil();
		verifyData=verify.p7DetachVerifyStream(resultTmp.resultData,originalData,flag,privateKey,publicKeyCert,digestArithmeticType);
		Assert.assertEquals(digestArithmeticType, new String(verifyData.hashAlg));
	}
	 
	
}
