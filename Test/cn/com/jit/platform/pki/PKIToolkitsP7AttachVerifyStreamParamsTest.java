package cn.com.jit.platform.pki;

import java.util.Arrays;

import org.junit.Test;

public class PKIToolkitsP7AttachVerifyStreamParamsTest extends BasePKIToolKitsTest {
	private HandleResult	out	= new HandleResult();

	@Test
	public void should_return_fail_when_verifyInit_with_empty_publicCert() {
		pkiTool.p7attachVerifyInit(new byte[0], SignHelper.SM2_FLAG_ATTACH, out);
		SignHelper.assertFailP7Verify(out);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_null_publicCert() {
		pkiTool.p7attachVerifyInit(null, SignHelper.SM2_FLAG_ATTACH, out);
		SignHelper.assertFailP7Verify(out);
	}


	@Test
	public void should_return_fail_when_verifyInit_with_invalid_flag() {
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, -1, out);
		SignHelper.assertFailP7Verify(out);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_null_flag() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, null, SignHelper.SIGN_CERT, out);
		SignHelper.assertFailP7Verify(out);
	}

	@Test
	public void should_return_fail_when_verifyUpdate_with_error_handle() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		byte[] signData = out.resultData;
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(1234, blocks, resultTmp);
			SignHelper.assertFailP7Verify(resultTmp);
			return;
		}
	}

	@Test
	public void should_return_fail_when_verifyUpdate_with_invalid_handler() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		byte[] signData = out.resultData;
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(-1, blocks, resultTmp);
			SignHelper.assertFailP7Verify(resultTmp);
			return;
		}
	}
	
	
	@Test
	public void should_return_fail_when_verifyUpdate_with_null_signData() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		while (true) {
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(out.handle, null, resultTmp);
			SignHelper.assertFailP7Verify(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_verifyUpdate_with_invalid_signData() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		while (true) {
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(out.handle, "abc".getBytes(), resultTmp);
			SignHelper.assertFailP7Verify(resultTmp);
			return;
		}
	}


	@Test
	public void should_return_fail_when_verifyFinal_with_invalid_handle() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		byte[] signData = out.resultData;
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(1234, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(-1, SignHelper.SIGN_CERT,null,	resultTmp);
		SignHelper.assertFailP1Verify(resultTmp);
	}
	@Test
	public void should_return_fail_when_verifyFinal_with_error_handle() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		byte[] signData = out.resultData;
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(1234, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(123, SignHelper.SIGN_CERT,null,	resultTmp);
		SignHelper.assertFailP1Verify(resultTmp);
	}
	@Test
	public void should_return_fail_when_verifyFinal_with_error_publickey() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		byte[] signData = out.resultData;
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(1234, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(123, SignHelper.SIGN_CER_2048,null,	resultTmp);
		SignHelper.assertFailP1Verify(resultTmp);
	}
	@Test
	public void should_return_fail_when_verifyFinal_with_invalid_publickey() {
		StreamTestUtil su = new StreamTestUtil();
		HandleResult out=su.p7SignStream(SignHelper.PLAIN,SignHelper.FLAG_ATTACH,SignHelper.PRVKEY,SignHelper.SIGN_CERT,PKIToolkits.DIGEST_SHA1);
		byte[] signData = out.resultData;
		out = new HandleResult();
		pkiTool.p7attachVerifyInit(SignHelper.SIGN_CERT, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int endIndex = index + step;
			if(endIndex > signData.length){
				endIndex=signData.length;
				blocks = new byte[signData.length-(endIndex-step)];
			}
			blocks = Arrays.copyOfRange(signData, index, endIndex);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7attachVerifyUpdate(1234, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(123,null,null,	resultTmp);
		SignHelper.assertFailP1Verify(resultTmp);
	}

}
