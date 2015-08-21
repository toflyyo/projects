package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.APP_ID;
import static cn.com.jit.platform.pki.SignHelper.APP_ID_2048;
import static cn.com.jit.platform.pki.SignHelper.APP_ID_SM2;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY_2048;
import static cn.com.jit.platform.pki.SignHelper.SM2_PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP1;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import cn.com.jit.cloud.common.Base64Utils;

@RunWith(Parameterized.class)
public class PKIToolKitsP1SignStreamSuccessTest extends BasePKIToolKitsTest {
	static HandleResult	handleResult	= new HandleResult();

	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { PRVKEY, PKIToolkits.DIGEST_SHA1, 0, SignHelper.PLAIN, APP_ID, handleResult },
				{ PRVKEY, PKIToolkits.DIGEST_SHA256, 0, SignHelper.PLAIN, APP_ID, handleResult },
				{ PRVKEY, PKIToolkits.DIGEST_MD5, 0, SignHelper.PLAIN, APP_ID, handleResult },
				{ PRVKEY_2048, PKIToolkits.DIGEST_SHA1, 0, SignHelper.PLAIN, APP_ID_2048, handleResult },
				{ PRVKEY_2048, PKIToolkits.DIGEST_SHA256, 0, SignHelper.PLAIN, APP_ID_2048, handleResult },
				{ PRVKEY_2048, PKIToolkits.DIGEST_MD5, 0, SignHelper.PLAIN, APP_ID_2048, handleResult },
				{ SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 4, SignHelper.PLAIN, APP_ID_SM2, handleResult }, };
		return Arrays.asList(objects);
	}

	private byte[]			privateKey;
	private String			digestArithmeticType;
	private byte[]			originalData;
	private String			appId;
	private HandleResult	out;
	private int				flag;

	public PKIToolKitsP1SignStreamSuccessTest(byte[] privateKey, String digestArithmeticType, int flag,
			byte[] originalData, String appId, HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.digestArithmeticType = digestArithmeticType;
		this.originalData = originalData;
		this.appId = appId;
		this.out = out;
		this.flag = flag;
	}

	@Test
	public void testPkiP1() {
		pkiTool.p1SignInit(privateKey, digestArithmeticType, flag, out);
		long handle = out.handle;
		pkiTool.p1SignUpdate(handle, originalData, out);
		pkiTool.p1SignFinal(handle, out);
		out.setResultData(Base64Utils.encode(out.getResultData()));
		assertSuccessP1(appId, out, digestArithmeticType, out.resultData);
	}

}
