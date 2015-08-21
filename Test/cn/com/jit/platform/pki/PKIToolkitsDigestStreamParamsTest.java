package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.assertFailDigest;

import java.util.Arrays;

import org.junit.Test;

public class PKIToolkitsDigestStreamParamsTest extends BasePKIToolKitsTest {
	private HandleResult	out	= new HandleResult();

	@Test
	public void should_return_fail_when_digestInit_with_empty_digestAlg() {
		pkiTool.digestInit("", out);
		assertFailDigest(out);
	}

	@Test
	public void should_return_fail_when_digestInit_with_null_privateKey() {
		pkiTool.digestInit(null, out);
		assertFailDigest(out);
	}

	@Test
	public void should_return_fail_when_digestUpdate_with_invalid_handle() {
		pkiTool.digestInit(PKIToolkits.DIGEST_SHA1, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		while (true) {
			int end = index + step;
			if(end > SignHelper.PLAIN.length){
				end = SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-index];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.digestUpdate(-1, blocks, resultTmp);
			assertFailDigest(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_digestUpdate_with_null_plainData() {
		pkiTool.digestInit(PKIToolkits.DIGEST_SHA1, out);
		while (true) {
			HandleResult resultTmp = new HandleResult();
			pkiTool.digestUpdate(out.handle, null, resultTmp);
			assertFailDigest(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_digestFinal_with_invalid_handle() {
		pkiTool.digestInit(PKIToolkits.DIGEST_SHA1, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		while (true) {
			int end = index + step;
			if(end > SignHelper.PLAIN.length){
				end = SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-index];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.digestUpdate(-1, blocks, resultTmp);
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult re = new HandleResult();
		pkiTool.digestFinal(-1, re);
		assertFailDigest(re);
	}
}
