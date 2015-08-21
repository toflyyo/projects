package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_BASE;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7VSignFailedTest extends BasePKIToolKitsTest {
static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { new byte[0], FLAG_ATTACH, PLAIN,handleResult }, { null, FLAG_ATTACH, PLAIN,handleResult },
				{ "".getBytes(), FLAG_ATTACH, PLAIN,handleResult }, { SIGN_RESULT, FLAG_ATTACH, new byte[0],handleResult},
				{ SIGN_RESULT, FLAG_ATTACH, null,handleResult }, { SIGN_RESULT, FLAG_ATTACH, "".getBytes(),handleResult },
				{ SIGN_ATTACH_RESULT_BASE, FLAG_ATTACH, PLAIN,handleResult }, { SIGN_ATTACH_RESULT, FLAG_ATTACH_BASE64, PLAINBASE,handleResult },
				{ SIGN_ATTACH_RESULT, FLAG_DETTACH, PLAIN,handleResult }, { SIGN_RESULT, FLAG_ATTACH, PLAIN ,handleResult},
				{ "*".getBytes(), FLAG_DETTACH, PLAIN ,handleResult}, { SIGN_RESULT_BASE, FLAG_DETTACH_BASE64, "*".getBytes() ,handleResult},
				{ SIGN_ATTACH_RESULT_BASE, -1, PLAINBASE,handleResult } };
		return Arrays.asList(objects);
	}

	private byte[]	signedData;
	private int		flag;
	private byte[]	originalData;
	private HandleResult out;

	public PKIToolkitsP7VSignFailedTest(byte[] signedData, int flag, byte[] originalData,HandleResult out) {
		super();
		this.signedData = signedData;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}
	/*
	@Test
	public void testPkip7VSign() {
		long actual = pkiTool.p7Verify(signedData, flag, originalData);
		assertTrue(actual != 0L);
	}*/
	@Test
	public void testPkip7VSign(){
		  pkiTool.p7Verify(signedData, flag, originalData,out);
		 assertTrue(out.errorCode != 0L);
	}
	
}
