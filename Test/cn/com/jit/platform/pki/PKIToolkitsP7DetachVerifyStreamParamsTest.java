package cn.com.jit.platform.pki;

import java.util.Arrays;

import org.junit.Test;

public class PKIToolkitsP7DetachVerifyStreamParamsTest extends BasePKIToolKitsTest {
	private HandleResult	out	= new HandleResult();

	@Test
	public void should_return_fail_when_verifyInit_with_empty_signData() {
		pkiTool.p7detachVerifyInit("".getBytes(), out);
		SignHelper.assertFailP7Verify(out);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_null_signData() {
		pkiTool.p7detachVerifyInit(null, out);
		SignHelper.assertFailP7Verify(out);
	}

	@Test
	public void should_return_fail_when_verifyUpdate_with_error_handle() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult sign=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		
		byte[] signData = sign.resultData;
		pkiTool.p7detachVerifyInit(signData, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		while (true) {
			int endIndex = index + step;
			if(endIndex > SignHelper.PLAIN.length){
				endIndex=SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7detachVerifyUpdate(1234, blocks, resultTmp);
			SignHelper.assertFailP7Verify(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_verifyUpdate_with_null_plainData() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult sign=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		
		byte[] signData = sign.resultData;
		pkiTool.p7detachVerifyInit(signData, out);
		while (true) {
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7detachVerifyUpdate(out.handle, null, resultTmp);
			SignHelper.assertFailP7Verify(resultTmp);
			return;
		}
	}

	@Test
	public void should_return_fail_when_verifyFinal_with_error_handle() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult sign=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		
		byte[] signData = sign.resultData;
		pkiTool.p7detachVerifyInit(signData, out);
		int index = 0;
		int step = 204800;
		byte[] resultBytes = new byte[0];
		byte[] blocks = new byte[step];
		while (true) {
			int endIndex = index + step;
			if(endIndex > SignHelper.PLAIN.length){
				endIndex=SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7detachVerifyUpdate(out.handle, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7detachVerifyFinal(1234, resultTmp);
		SignHelper.assertFailP7Verify(resultTmp);
	}
	@Test
	public void should_return_fail_when_verifyFinal_with_invalid_handle() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult sign=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		
		byte[] signData = sign.resultData;
		pkiTool.p7detachVerifyInit(signData, out);
		int index = 0;
		int step = 204800;
		byte[] resultBytes = new byte[0];
		byte[] blocks = new byte[step];
		while (true) {
			int endIndex = index + step;
			if(endIndex > SignHelper.PLAIN.length){
				endIndex=SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7detachVerifyUpdate(out.handle, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length)
				break;
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7detachVerifyFinal(-1, resultTmp);
		SignHelper.assertFailP7Verify(resultTmp);
	}
}
