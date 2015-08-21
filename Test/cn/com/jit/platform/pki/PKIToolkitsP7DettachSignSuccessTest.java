package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.*;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import cn.com.jit.assp.css.client.util.Base64;

@RunWith(Parameterized.class)
public class PKIToolkitsP7DettachSignSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { 
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256, FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5, FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_SHA256, FLAG_DETTACH, PLAIN,handleResult},
				{PRVKEY_2048, SIGN_CER_2048, PKIToolkits.DIGEST_MD5, FLAG_DETTACH, PLAIN,handleResult},
				{SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_DETTACH, PLAIN,handleResult},
		};
		return Arrays.asList(objects);
	}

	private byte[] privateKey;
	private byte[] publicKeyCert;
	private String digestArithmeticType;
	private int flag;
	private byte[] originalData;
	private HandleResult out;

	public PKIToolkitsP7DettachSignSuccessTest(byte[] privateKey,byte[] publicKeyCert,String digestArithmeticType, int flag, byte[] originalData,HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.publicKeyCert = publicKeyCert;
		this.digestArithmeticType = digestArithmeticType;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}

	@Test
	public void testPkip7Sign() {
		pkiTool.p7Sign(privateKey,publicKeyCert,digestArithmeticType,flag,originalData,out);
		assertSuccessP7DettachSign(out,Base64.encode(out.resultData));
	}
}
