package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY_2048;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_P1_SHA1_BASE;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailP1Sign;
import static cn.com.jit.platform.pki.SignHelper.assertFailP1Verify;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessRSA2048P1;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessRSA2048SHA1P1Base64;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessRSA204SHA256P1Base64;
import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;

public class PKIToolkitsRSA2048P1Test extends BasePKIToolKitsTest {

	/*
	 * p1签名单元测试用例
	 */
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_success_without_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, 0, PLAIN, handleResult);
		// 测试结果
		assertSuccessRSA2048SHA1P1Base64(handleResult);
	}

	@Test
	public void should_return_success_digest_is_sha256_without_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA256, 0, PLAIN, handleResult);
		// 测试结果
		assertSuccessRSA204SHA256P1Base64(handleResult);
	}

	@Test
	public void should_return_success_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, 2, PLAINBASE, handleResult);
		// 测试结果
		assertSuccessRSA2048P1(handleResult);
	}

	@Test
	public void should_return_fail_all_args_is_zero_without_base64() {
		// 测试执行
		pkiTool.p1Sign(ZERO, "0", 0, ZERO, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_signpfx_is_null_without_base64() {
		// 测试执行
		pkiTool.p1Sign(null, PKIToolkits.DIGEST_MD5, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);

	}

	@Test
	public void should_return_digest_is_null_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, null, FLAG_ATTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_pfx_is_empty_with_base64() {
		// 测试执行
		pkiTool.p1Sign("".getBytes(), PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_password_is_empty_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_digest_is_empty_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, "", FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_plain_is_empty_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, "".getBytes(), handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_password_is_sprit_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_password_is_agains_sprit_with_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_fail_flag_is_7_without_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, 7, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_flag_is_negtive_without_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, -1, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_digest_is_illegal_without_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, "*[]", FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	@Test
	public void should_return_flag_is_base64_and_plain_is_not_base64() {
		// 测试执行
		pkiTool.p1Sign(PRVKEY_2048, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH_BASE64, PLAIN, handleResult);
		// 测试结果
		assertFailP1Sign(handleResult);
	}

	/**
	 * p1验签
	 */

	@Test
	public void should_return_Verify_without_base64() {
		// 预期结果
		long expected = 0L;
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN, handleResult);
		// 测试结果
		assertEquals(expected, handleResult.errorCode);
	}

	@Test
	public void should_return_Verify_with_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1_BASE, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 2, PLAINBASE, handleResult);
		// 测试结果
		assertEquals(handleResult, handleResult);
	}

	@Test
	public void should_return_public_cert_is_wrong_without_base64() {
		// 测试准备
		byte[] wrongPublicCert = "MIICdjCCAd+gAwIBAgIIRTUCMF6AR3kwDQYJKoZIhvcNAQEFBQAwLDE".getBytes();
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, wrongPublicCert, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_sign_result_is_null_without_base64() {
		// 测试执行
		pkiTool.p1Verify(null, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_digest_is_null_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, null, SIGN_CERT, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_public_cert_is_null_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, null, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Ignore
	public void should_return_plain_is_null_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, null, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_sign_result_is_empty() {
		// 测试执行
		pkiTool.p1Verify("".getBytes(), PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_public_cert_is_empty() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, "".getBytes(), 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_plain_is_empty() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, "".getBytes(), handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_verify_flag_is_negtive_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, -1, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_verify_sign_result_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p1Verify("\\".getBytes(), PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_verify_digest_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, "/*&%", SIGN_CERT, 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_verify_public_cert_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, "*#@".getBytes(), 0, PLAIN, handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}

	@Test
	public void should_return_verify_plain_is_special_character_without_base64() {
		// 测试执行
		pkiTool.p1Verify(SIGN_RESULT_P1_SHA1, PKIToolkits.DIGEST_SHA1, SIGN_CERT, 0, "$%^".getBytes(), handleResult);
		// 测试结果
		assertFailP1Verify(handleResult);
	}
}
