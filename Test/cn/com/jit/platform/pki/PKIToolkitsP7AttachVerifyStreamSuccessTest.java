package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.SM2_SIGN_CER;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import cn.com.jit.assp.css.client.util.Base64;


@RunWith(Parameterized.class)
public class PKIToolkitsP7AttachVerifyStreamSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { 
				{SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.FLAG_ATTACH, PLAIN,handleResult},
				{SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA256, SignHelper.FLAG_ATTACH, PLAIN,handleResult},
				{SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_MD5, SignHelper.FLAG_ATTACH, PLAIN,handleResult},
				{SignHelper.PRVKEY_2048, SignHelper.SIGN_CER_2048, PKIToolkits.DIGEST_SHA1, SignHelper.FLAG_ATTACH, PLAIN,handleResult},
				{SignHelper.PRVKEY_2048, SignHelper.SIGN_CER_2048, PKIToolkits.DIGEST_SHA256, SignHelper.FLAG_ATTACH, PLAIN,handleResult},
				{SignHelper.PRVKEY_2048, SignHelper.SIGN_CER_2048, PKIToolkits.DIGEST_MD5, SignHelper.FLAG_ATTACH, PLAIN,handleResult},
				{SignHelper.SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SignHelper.SM2_FLAG_ATTACH, PLAIN,handleResult},
		};
		return Arrays.asList(objects);
	}
	
	private byte[] privateCert;
	private byte[] cert;
	private byte[] originalData;
	private String digestArithmeticType;
	private int flag;
	
	public PKIToolkitsP7AttachVerifyStreamSuccessTest(byte[] privateKey,byte[] publicKeyCert,String digestArithmeticType,int flag,byte[] originalData,HandleResult out) {
		super();
		this.privateCert = privateKey;
		this.cert = publicKeyCert;
		this.digestArithmeticType = digestArithmeticType;
		this.originalData = originalData;
		this.flag=flag;
	}

	/*@Test
	public void p7AttachVerifySignStreamHandlerTest() {
		pkiTool.p7Sign(privateCert, cert, digestArithmeticType, 0, originalData, out);
		byte[] signData = out.resultData;
		out = new HandleResult();
		boolean isGM = false;
		if(!isGM){
			cert = null;
		}
		Pkcs7Stream pkcs7 = new Pkcs7Stream();
		pkcs7.attachVerifyInit(false, false);
		int index = 0;
		int step = 500;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			resultTmp = pkcs7.attachVerifyUpdate(blocks);
			resultBytes = mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=signData.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7attachVerifyFinal(out.handle, resultTmp);
		resultTmp.setResultData(mergeBytes(resultBytes, resultTmp.getResultData()));
	System.out.println("verify length is "+resultTmp.resultData.length);
//		Assert.assertNotNull(out.resultData);
		Assert.assertArrayEquals(originalData, resultTmp.resultData);
	}*/
	
	
	//attach非国密
	@Test
	public void p7AttachVerifySignStreamTest() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(originalData,flag,privateCert,cert,digestArithmeticType);
		byte[] signData = out.resultData;
		out = new HandleResult();
		cert = Base64.decode(cert);
		pkiTool.p7attachVerifyInit(cert, flag, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(out.handle, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=signData.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7attachVerifyFinal(out.handle, resultTmp);
		resultTmp.setResultData(StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData()));
		Assert.assertArrayEquals(originalData, resultTmp.resultData);
	}
	
}
