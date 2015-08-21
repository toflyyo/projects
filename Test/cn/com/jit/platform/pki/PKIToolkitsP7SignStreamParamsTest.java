package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.assertFailP7Sign;

import java.util.Arrays;

import org.junit.Test;

public class PKIToolkitsP7SignStreamParamsTest extends BasePKIToolKitsTest {
	private HandleResult	out	= new HandleResult();

	@Test
	public void should_return_fail_when_signInit_with_empty_privateKey() {
		pkiTool.p7SignInit(new byte[0], SignHelper.SIGN_CERT,  PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}

	@Test
	public void should_return_fail_when_signInit_with_null_privateKey() {
		pkiTool.p7SignInit(null, SignHelper.SIGN_CERT,  PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}
	@Test
	public void should_return_fail_when_signInit_with_empty_publicKey() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, new byte[0],  PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}
	
	@Test
	public void should_return_fail_when_signInit_with_null_publicKey() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, null,  PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}

	@Test
	public void should_return_fail_when_signInit_with_empty_digestArithmetic() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT,  "", SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}

	@Test
	public void should_return_fail_when_signInit_with_null_digestArithmetic() {
		pkiTool.p7SignInit(SignHelper.PRVKEY,  SignHelper.SIGN_CERT,  null, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}
	@Test
	public void should_return_fail_when_signInit_with_invalid_digestArithmetic() {
		pkiTool.p7SignInit(SignHelper.PRVKEY,  SignHelper.SIGN_CERT,  PKIToolkits.DIGEST_SM3, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}

	@Test
	public void should_return_fail_when_signInit_with_invalid_plaindata_length() {
		pkiTool.p7SignInit(SignHelper.PRVKEY,  SignHelper.SIGN_CERT,   PKIToolkits.DIGEST_SHA1, -1, SignHelper.FLAG_ATTACH, out);
		assertFailP7Sign(out);
	}

	@Test
	public void should_return_fail_when_signInit_with_invalid_flag() {
		pkiTool.p7SignInit(SignHelper.PRVKEY,  SignHelper.SIGN_CERT,   PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, -1, out);
		assertFailP7Sign(out);
	}

	@Test
	public void should_return_fail_when_signUpdate_with_invalid_handle() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
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
			pkiTool.p7SignUpdate(-1,  SignHelper.SIGN_CERT, blocks, resultTmp);
			assertFailP7Sign(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_signUpdate_with_error_handle() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
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
			pkiTool.p7SignUpdate(321,  SignHelper.SIGN_CERT, blocks, resultTmp);
			assertFailP7Sign(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_signUpdate_with_null_publickey() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
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
			pkiTool.p7SignUpdate(out.handle, null, blocks, resultTmp);
			assertFailP7Sign(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_signUpdate_with_invalid_publickey() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
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
			pkiTool.p7SignUpdate(out.handle, new byte[0], blocks, resultTmp);
			assertFailP7Sign(resultTmp);
			return;
		}
	}
	@Test
	public void should_return_fail_when_signUpdate_with_null_plaindata() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		while (true) {
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7SignUpdate(out.handle, SignHelper.SIGN_CERT, null, resultTmp);
			assertFailP7Sign(resultTmp);
			return;
		}
	}


	@Test
	public void should_return_fail_when_signFinal_with_invalid_handle() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int end = index + step;
			if(end > SignHelper.PLAIN.length){
				end = SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-index];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7SignUpdate(out.handle,SignHelper.SIGN_CERT, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(-1, SignHelper.SIGN_CERT,null,	resultTmp);
		assertFailP7Sign(resultTmp);
	}
	@Test
	public void should_return_fail_when_signFinal_with_error_handle() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int end = index + step;
			if(end > SignHelper.PLAIN.length){
				end = SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-index];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7SignUpdate(out.handle, SignHelper.SIGN_CERT, blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(123, SignHelper.SIGN_CERT,null,	resultTmp);
		assertFailP7Sign(resultTmp);
	}
	@Test
	public void should_return_fail_when_signFinal_with_error_publickey() {
		pkiTool.p7SignInit(SignHelper.PRVKEY, SignHelper.SIGN_CERT, PKIToolkits.DIGEST_SHA1, SignHelper.PLAIN.length, SignHelper.FLAG_ATTACH, out);
		int index = 0;
		int step = 204800;
		byte[] blocks = new byte[step];
		byte[] resultBytes = new byte[0];
		while (true) {
			int end = index + step;
			if(end > SignHelper.PLAIN.length){
				end = SignHelper.PLAIN.length;
				blocks = new byte[SignHelper.PLAIN.length-index];
			}
			blocks = Arrays.copyOfRange(SignHelper.PLAIN, index, end);
			index += step;
			HandleResult resultTmp = new HandleResult();
			pkiTool.p7SignUpdate(out.handle, new byte[0], blocks, resultTmp);
			resultBytes = StreamTestUtil.mergeBytes(resultBytes, resultTmp.getResultData());
			if(index>=SignHelper.PLAIN.length){
				break;
			}
		}
		HandleResult resultTmp = new HandleResult();
		pkiTool.p7SignFinal(out.handle, SignHelper.SM2_SIGN_CER,null,	resultTmp);
		assertFailP7Sign(resultTmp);
	}

}
