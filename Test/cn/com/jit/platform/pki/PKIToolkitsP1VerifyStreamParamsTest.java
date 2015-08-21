package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.assertFailP1Verify;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PKIToolkitsP1VerifyStreamParamsTest extends BasePKIToolKitsTest {
	private HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_fail_when_verifyInit_with_empty_signData() {
		pkiTool.p1VerifyInit(new byte[0], PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_null_signData() {
		pkiTool.p1VerifyInit(null, PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_invalid_signData() {
		pkiTool.p1VerifyInit("0".getBytes(), PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_empty_digestArithmetic() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, "", SignHelper.SIGN_CERT, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_null_digestArithmetic() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, null, SignHelper.SIGN_CERT, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_invalid_digestArithmetic() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, "*][", SignHelper.SIGN_CERT, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_empty_publicKey() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, new byte[0], handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_null_publicKey() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, null, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyInit_with_invalid_publicKey() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SignHelper.ZERO, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_success_when_verifyInit() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT,
				handleResult);
		assertTrue(handleResult.errorCode == 0L);
		assertTrue(handleResult.handle > 0L);
	}

	@Test
	public void should_return_fail_when_verifyUpdate_with_invalid_handle() {
		pkiTool.p1VerifyUpdate(-1l, PLAIN, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyUpdate_with_empty_plainData() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT,
				handleResult);
		pkiTool.p1VerifyUpdate(handleResult.handle, "".getBytes(), handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_fail_when_verifyUpdate_with_null_plainData() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT,
				handleResult);
		pkiTool.p1VerifyUpdate(handleResult.handle, null, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_success_when_verifyUpdate() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT,
				handleResult);
		pkiTool.p1VerifyUpdate(handleResult.handle, PLAIN, handleResult);
		assertTrue(handleResult.errorCode == 0L);
	}

	@Test
	public void should_return_fail_when_verifyFinal_with_invalid_handle() {
		pkiTool.p1VerifyFinal(-1l, handleResult);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_success_when_verifyFinal() {
		pkiTool.p1VerifyInit(SignHelper.SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SignHelper.SIGN_CERT,
				handleResult);
		long handle = handleResult.handle;
		pkiTool.p1VerifyUpdate(handle, PLAIN, handleResult);
		pkiTool.p1VerifyFinal(handle, handleResult);
		assertTrue(handleResult.errorCode == 0L);
	}
}
