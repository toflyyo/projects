package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailP7Sign;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7SignFailedTest extends BasePKIToolKitsTest {
	static HandleResult	handleResult	= new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { ZERO, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH, PLAIN,handleResult },
				{ PRVKEY, null, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH, PLAIN,handleResult }, { PRVKEY, SIGN_CERT, "0", FLAG_ATTACH, PLAIN,handleResult },
				{ new byte[0], SIGN_CERT, PKIToolkits.DIGEST_MD5, FLAG_ATTACH, PLAIN,handleResult },
				{ PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256, FLAG_ATTACH, new byte[0] ,handleResult},
				{ PRVKEY, new byte[0], PKIToolkits.DIGEST_MD5, FLAG_DETTACH, PLAIN ,handleResult},
				{ PRVKEY, "".getBytes(), PKIToolkits.DIGEST_SHA256, FLAG_DETTACH, PLAIN,handleResult },
				{ PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5, 9, PLAINBASE ,handleResult}, { PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, -1, PLAINBASE,handleResult },
				{ PRVKEY, SIGN_CERT, "*[]", FLAG_DETTACH, PLAIN,handleResult }, };
		return Arrays.asList(objects);
	}

	private byte[]	privateKey;
	private byte[]	publicKeyCert;
	private String	digestArithmeticType;
	private int		flag;
	private byte[]	originalData;
	private HandleResult out;

	public PKIToolkitsP7SignFailedTest(byte[] privateKey, byte[] publicKeyCert, String digestArithmeticType, int flag,
			byte[] originalData,HandleResult out) {
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
		 pkiTool.p7Sign(privateKey, publicKeyCert, digestArithmeticType, flag, originalData,out);
		assertFailP7Sign(out);
	}
}
