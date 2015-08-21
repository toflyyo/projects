package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_SM2_P1;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_SM2_P1_BASE;
import static cn.com.jit.platform.pki.SignHelper.SM2_PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.SM2_SIGN_CER;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailP1Verify;
import static cn.com.jit.platform.pki.SignHelper.assertFailed;
import static cn.com.jit.platform.pki.SignHelper.assertSuccess;
import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class PKIToolkitsSM2P1Test extends BasePKIToolKitsTest {
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_sm2_signedData_with_base64() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 6, PLAINBASE, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_sm2_signedData_without_base64() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 4, PLAIN, handleResult);
		// 测试结果
		assertSuccess(handleResult);
	}

	@Test
	public void should_return_all_args_is_zero() {
		// 测试执行
		pkiTool.p1Sign(ZERO, "0", 0, ZERO, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_pfx_is_null() {
		// 测试执行
		pkiTool.p1Sign(null, PKIToolkits.DIGEST_SM3, 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_pfx_is_empty() {
		// 测试执行
		pkiTool.p1Sign("".getBytes(), PKIToolkits.DIGEST_SM3, 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);

	}

	@Test
	public void should_return_error_code_when_digest_is_null() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, null, 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_digest_is_empty() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, "", 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_plain_is_null() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 0, null, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_plain_is_empty() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 0, "".getBytes(), handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_digest_illegal_parameter_is_sprit() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, "\\", 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_error_code_when_digest_illegal_parameter_is_agains_sprit() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, "/", 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_flag_is_7() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, PKIToolkits.DIGEST_SM3, 7, PLAINBASE, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_flag_is_negtive() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, PKIToolkits.DIGEST_SM3, -1, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_digest_is_illegal_without_base64() {
		// 测试执行
		pkiTool.p1Sign(SM2_PRVKEY, "*[]", 0, PLAIN, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	/** 国密P1验签名 **/

	@Test
	public void should_return_success_when_p1Verify__with_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1_BASE, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 6, PLAINBASE, handleResult);
		// 测试结果
		assertEquals(0L, handleResult.errorCode);

	}

	@Test
	public void should_return_success_when_p1Verify__without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertEquals(0L, handleResult.errorCode);

	}

	@Test
	public void should_return_error_code_when_public_cert_is_wrong_without_base64() {
		// 测试准备
		byte[] wrongPublicCert = "MIICdjCCAd+gAwIBAgIIRTUCMF6AR3kwDQYJKoZIhvcNAQEFBQAwLDE".getBytes();
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, wrongPublicCert, 4, PLAIN, handleResult);
		// 测试结果
		// assertTrue(handleResult != 0L);
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_signedData_is_null() {
		// 测试执行
		pkiTool.p1Verify(null, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_signedData_is_empty() {
		// 测试执行
		pkiTool.p1Verify("".getBytes(), PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_digest_is_null() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, null, SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_digest_is_empty() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, "", SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_publicKey_cert_is_null() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, null, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_publicKey_cert_is_empty() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, "".getBytes(), 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_plain_is_null() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, null, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_plain_is_empty() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, "".getBytes(), handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_flag_is_negtive() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, -1, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_verify_signdata_is_special_character() {
		// 测试执行
		pkiTool.p1Verify("\\".getBytes(), PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_digest_is_special_character() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, "/*&%", SM2_SIGN_CER, 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_public_cert_is_special_character() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, "*#@".getBytes(), 4, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_error_code_when_plain_is_special_character() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_SM2_P1, PKIToolkits.DIGEST_SM3, SM2_SIGN_CER, 4, "$%^".getBytes(), handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}
}
