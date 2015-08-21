package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CER_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_MD5;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_MD5_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_MD5_BASE_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_MD5_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1_BASE_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA256;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA256_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA256_BASE_RSA_2048;
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

@RunWith(Parameterized.class)
public class PKIToolkitsP1VSignSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN,handleResult },
				{ SIGN_RESULT_P1_SHA256, PKIToolkits.DIGEST_SHA256, SIGN_CERT, 0, PLAIN,handleResult },
				{ SIGN_RESULT_P1_MD5, PKIToolkits.DIGEST_MD5, SIGN_CERT, 0, PLAIN ,handleResult},
				{ SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, PLAIN ,handleResult},
				{ SIGN_RESULT_P1_SHA1_RSA_2048, PKIToolkits.DIGEST_SHA1, SIGN_CER_2048, 0, PLAIN,handleResult },
				{ SIGN_RESULT_P1_SHA256_RSA_2048, PKIToolkits.DIGEST_SHA256, SIGN_CER_2048, 0, PLAIN ,handleResult},
				{ SIGN_RESULT_P1_MD5_RSA_2048, PKIToolkits.DIGEST_MD5, SIGN_CER_2048, 0, PLAIN,handleResult },
				{ SIGN_RESULT_P1_SHA1_BASE, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 2, PLAINBASE ,handleResult},
				{ SIGN_RESULT_P1_SHA256_BASE, PKIToolkits.DIGEST_SHA256, SIGN_CERT, 2, PLAINBASE ,handleResult},
				{ SIGN_RESULT_P1_MD5_BASE, PKIToolkits.DIGEST_MD5, SIGN_CERT, 2, PLAINBASE ,handleResult},
				{ SIGN_RESULT_P1_SHA1_BASE_RSA_2048, PKIToolkits.DIGEST_SHA1, SIGN_CER_2048, 2, PLAINBASE,handleResult },
				{ SIGN_RESULT_P1_SHA256_BASE_RSA_2048, PKIToolkits.DIGEST_SHA256, SIGN_CER_2048, 2, PLAINBASE ,handleResult},
				{ SIGN_RESULT_P1_MD5_BASE_RSA_2048, PKIToolkits.DIGEST_MD5, SIGN_CER_2048, 2, PLAINBASE ,handleResult},
				{ SIGN_RESULT_SM2_P1_BASE, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 6, PLAINBASE,handleResult } };
		return Arrays.asList(objects);
	}

	private byte[]	signedData;
	private String	digestArithmeticType;
	private byte[]	publicKeyCert;
	private int		flag;
	private byte[]	originalData;
	private HandleResult out;

	public PKIToolkitsP1VSignSuccessTest(byte[] signedData, String digestArithmeticType, byte[] publicKeyCert,
			int flag, byte[] originalData,HandleResult out) {
		super();
		this.signedData = signedData;
		this.digestArithmeticType = digestArithmeticType;
		this.publicKeyCert = publicKeyCert;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}

	@Test
	public void testPkiP1() {
		 pkiTool.p1Verify(signedData, digestArithmeticType, publicKeyCert, flag, originalData,out);
		assertEquals(0L, out.errorCode);
	}
}
