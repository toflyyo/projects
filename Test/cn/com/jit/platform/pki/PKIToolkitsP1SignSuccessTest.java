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
public class PKIToolkitsP1SignSuccessTest extends BasePKIToolKitsTest {
	static HandleResult	handleResult	= new HandleResult();

	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = {

		{ PRVKEY, PKIToolkits.DIGEST_SHA1, 0, PLAIN, APP_ID, handleResult },
				{ PRVKEY, PKIToolkits.DIGEST_SHA256, 0, PLAIN, APP_ID, handleResult },
				{ PRVKEY, PKIToolkits.DIGEST_MD5, 0, PLAIN, APP_ID, handleResult },
				{ PRVKEY_2048, PKIToolkits.DIGEST_SHA1, 0, PLAIN, APP_ID_2048, handleResult },
				{ PRVKEY_2048, PKIToolkits.DIGEST_SHA256, 0, PLAIN, APP_ID_2048, handleResult },
				{ PRVKEY_2048, PKIToolkits.DIGEST_MD5, 0, PLAIN, APP_ID_2048, handleResult },
				{ SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 4, PLAIN, APP_ID_SM2, handleResult } };
		return Arrays.asList(objects);
	}

	private byte[]			privateKey;
	private String			digestArithmeticType;
	private int				flag;
	private byte[]			originalData;
	private String			appId;
	private HandleResult	out;

	public PKIToolkitsP1SignSuccessTest(byte[] privateKey, String digestArithmeticType, int flag, byte[] originalData,
			String appId, HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.digestArithmeticType = digestArithmeticType;
		this.flag = flag;
		this.originalData = originalData;
		this.appId = appId;
		this.out = out;
	}

	@Test
	public void testPkiP1() {
		pkiTool.p1Sign(privateKey, digestArithmeticType, flag, originalData, out);
		assertSuccessP1(appId, out, digestArithmeticType, Base64.encode(out.resultData));
	}
}
