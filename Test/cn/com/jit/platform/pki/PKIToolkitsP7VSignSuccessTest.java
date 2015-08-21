package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT_BASE_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_BASE_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SM2_ATTACH_BASE64_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_ATTACH_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_DETTACH_BASE64_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_DETTACH_SIGN_RESULT;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7VSignSuccessTest extends BasePKIToolKitsTest {
	static HandleResult	handleResult	= new HandleResult();

	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { SIGN_RESULT, FLAG_DETTACH, PLAIN, handleResult },
				{ SIGN_RESULT_RSA_2048, FLAG_DETTACH, PLAIN, handleResult },
				{ SM2_DETTACH_SIGN_RESULT, FLAG_DETTACH, PLAIN, handleResult },
				{ SIGN_ATTACH_RESULT, FLAG_ATTACH, PLAIN, handleResult },
				{ SIGN_ATTACH_RESULT_RSA_2048, FLAG_ATTACH, PLAIN, handleResult },
				{ SM2_ATTACH_SIGN_RESULT, FLAG_ATTACH, PLAIN, handleResult },
				{ SIGN_RESULT_BASE, FLAG_DETTACH_BASE64, PLAINBASE, handleResult },
				{ SIGN_RESULT_BASE_RSA_2048, FLAG_DETTACH_BASE64, PLAINBASE, handleResult },
				{ SM2_DETTACH_BASE64_SIGN_RESULT, FLAG_DETTACH_BASE64, PLAINBASE, handleResult },
				{ SIGN_ATTACH_RESULT_BASE, FLAG_ATTACH_BASE64, PLAINBASE, handleResult },
				{ SIGN_ATTACH_RESULT_BASE_RSA_2048, FLAG_ATTACH_BASE64, PLAINBASE, handleResult },
				{ SM2_ATTACH_BASE64_SIGN_RESULT, FLAG_ATTACH_BASE64, PLAINBASE, handleResult }, };
		return Arrays.asList(objects);
	}

	private byte[]			signedData;
	private int				flag;
	private byte[]			originalData;
	private HandleResult	out;

	public PKIToolkitsP7VSignSuccessTest(byte[] signedData, int flag, byte[] originalData, HandleResult out) {
		super();
		this.signedData = signedData;
		this.flag = flag;
		this.originalData = originalData;
		this.out = out;
	}

	/*
	 * @Test public void testPkip7VSign() { long actual =
	 * pkiTool.p7Verify(signedData,flag,originalData); assertEquals(0L, actual);
	 * }
	 */
	@Test
	public void testPkip7VSign() {
		pkiTool.p7Verify(signedData, flag, originalData, out);
		assertTrue(handleResult.errorCode == 0L);
	}
}
