package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CER_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_MD5;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_MD5_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA256;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA256_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_SM2_P1;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_SM2_P1_BASE;
import static cn.com.jit.platform.pki.SignHelper.SM2_SIGN_CER;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import cn.com.jit.cloud.common.Base64Utils;

@RunWith(Parameterized.class)
public class PKIToolkitsP1VerifyStreamSuccessTest extends BasePKIToolKitsTest {
	static HandleResult	handleResult	= new HandleResult();

	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = {
				{ SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, PLAIN, handleResult },
				{ SIGN_RESULT_P1_SHA256, PKIToolkits.DIGEST_SHA256, SIGN_CERT, PLAIN, handleResult },
				{ SIGN_RESULT_P1_MD5, PKIToolkits.DIGEST_MD5, SIGN_CERT, PLAIN, handleResult },
				{ SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, PLAIN, handleResult },
				{ SIGN_RESULT_P1_SHA1_RSA_2048, PKIToolkits.DIGEST_SHA1, SIGN_CER_2048, PLAIN, handleResult },
				{ SIGN_RESULT_P1_SHA256_RSA_2048, PKIToolkits.DIGEST_SHA256, SIGN_CER_2048, PLAIN, handleResult },
				{ SIGN_RESULT_P1_MD5_RSA_2048, PKIToolkits.DIGEST_MD5, SIGN_CER_2048, PLAIN, handleResult },
				{ Base64Utils.decode(SIGN_RESULT_SM2_P1_BASE), PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, PLAIN,
						handleResult } };
		return Arrays.asList(objects);
	}

	private byte[]			signedData;
	private String			digestArithmeticType;
	private byte[]			publicKeyCert;
	private byte[]			originalData;
	private HandleResult	out;

	public PKIToolkitsP1VerifyStreamSuccessTest(byte[] signedData, String digestArithmeticType, byte[] publicKeyCert,
			byte[] originalData, HandleResult out) {
		super();
		this.signedData = signedData;
		this.digestArithmeticType = digestArithmeticType;
		this.publicKeyCert = publicKeyCert;
		this.originalData = originalData;
		this.out = out;
	}

	@Test
	public void testPkiP1() {
		pkiTool.p1VerifyInit(signedData, digestArithmeticType, publicKeyCert, out);
		long handle = out.handle;
		pkiTool.p1VerifyUpdate(handle, originalData, out);
		pkiTool.p1VerifyFinal(handle, out);
		assertEquals(0L, out.errorCode);
	}
}
