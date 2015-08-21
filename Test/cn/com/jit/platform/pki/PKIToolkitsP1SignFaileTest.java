package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailed;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP1SignFaileTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = {

		{ ZERO, "0", 0, ZERO,handleResult }, { null, PKIToolkits.DIGEST_MD5, 1, PLAIN,handleResult }, { "".getBytes(), PKIToolkits.DIGEST_MD5, 1, PLAIN,handleResult },
				{ PRVKEY, null, 0, PLAIN,handleResult }, { PRVKEY, "", 1, PLAIN,handleResult }, { PRVKEY, PKIToolkits.DIGEST_MD5, 1, PLAIN ,handleResult},
				{ PRVKEY, PKIToolkits.DIGEST_MD5, 1, PLAINBASE,handleResult }, { PRVKEY, PKIToolkits.DIGEST_MD5, 1, "".getBytes(),handleResult },
				{ PRVKEY, PKIToolkits.DIGEST_MD5, 1, null,handleResult }, { PRVKEY, PKIToolkits.DIGEST_MD5, 7, PLAIN,handleResult }, { PRVKEY, PKIToolkits.DIGEST_MD5, -1, PLAIN ,handleResult},
				{ PRVKEY, "*[]", 1, PLAIN,handleResult }, { PRVKEY, PKIToolkits.DIGEST_MD5, 2, PLAIN ,handleResult}, };
		return Arrays.asList(objects);
	}

	private byte[]	privateKey;
	private String	digestArithmeticType;
	private int		flag;
	private byte[]	originalData;
	private HandleResult out;

	public PKIToolkitsP1SignFaileTest(byte[] privateKey, String digestArithmeticType, int flag, byte[] originalData,HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.digestArithmeticType = digestArithmeticType;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}

	@Test
	public void testPkiP1() {
		pkiTool.p1Sign(privateKey, digestArithmeticType, flag, originalData,out);
		assertFailed(out);
	}

}
