package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP1VSignFaileTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData(){
		Object [][] objects = {
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, "MIICdjCCAd+gAwIBNAQEFBQAwLDE".getBytes(), 0, PLAIN,handleResult},
				{null, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 2, PLAINBASE,handleResult},
				{"".getBytes(), PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, null, SIGN_CERT, 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, "", SIGN_CERT, 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, null, 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, "".getBytes(), 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, null,handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, "".getBytes(),handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, -1, PLAIN,handleResult},
				{"\\".getBytes(), PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, "/*&%", SIGN_CERT, 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, "*#@".getBytes(), 0, PLAIN,handleResult},
				{SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, "$%^".getBytes(),handleResult},
		};
		return Arrays.asList(objects);
	}
	
	private byte[] signedData;
	private String digestArithmeticType;
	private byte[] publicKeyCert;
	private int flag;
	private byte[] originalData;
	private HandleResult out;
	
	public PKIToolkitsP1VSignFaileTest(byte[] signedData, String digestArithmeticType, byte[] publicKeyCert, int flag,byte[] originalData,HandleResult out) {
		super();
		this.signedData = signedData;
		this.digestArithmeticType = digestArithmeticType;
		this.publicKeyCert = publicKeyCert;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}

	
	
	@Test
	public void testPkiP1(){
		pkiTool.p1Verify(signedData, digestArithmeticType, publicKeyCert, flag, originalData,out);
		assertTrue(out.errorCode != 0L);
	}
}
