package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.SM2_ATTACH_BASE64_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_ATTACH_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_DETTACH_BASE64_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_DETTACH_SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SM2_FLAG_ATTACH;
import static cn.com.jit.platform.pki.SignHelper.SM2_FLAG_ATTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.SM2_FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.SM2_FLAG_DETTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.SM2_PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.SM2_SIGN_CER;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailP7Sign;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7AttachSign;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7AttachSignNotBase;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7Sign;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class PKIToolkitsSM2P7Test extends BasePKIToolKitsTest {

	/** 国密P7签名 **/
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_success_when_sm2_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7Sign(handleResult);
	}

	@Test
	public void should_return_success_when_sm2_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7AttachSign(handleResult);
	}

	@Test
	public void should_return_success_when_sm2_dettach_with_base64() {

		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_DETTACH_BASE64, PLAINBASE,
				handleResult);
		// 测试结果
		assertEquals(0L, handleResult.errorCode);
	}

	@Test
	public void should_return_success_when_sm2_attach_with_base64() {

		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH_BASE64, PLAINBASE,
				handleResult);
		// 测试结果
		assertSuccessP7AttachSignNotBase(handleResult);
	}

	@Test
	public void should_return_error_code_when_signPfx_is_zero() {

		// 测试执行
		pkiTool.p7Sign(ZERO, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_pfxpassword_is_zero() {

		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, "0".getBytes(), PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_digest_is_zero() {

		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, "0", SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_plain_is_zero() {

		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH, ZERO, handleResult);
		// 测试结果
		assertSuccessP7AttachSign(handleResult);
	}

	@Test
	public void should_return_error_code_when_signpfx_is_null() {

		// 测试执行
		pkiTool.p7Sign(null, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_plain_is_null() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, SM2_FLAG_ATTACH, null, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_pfxpassword_is_failed() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, "123".getBytes(), PKIToolkits.DIGEST_SM3, SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_pfxpassword_is_backslashbase64() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, "\\".getBytes(), PKIToolkits.DIGEST_SM3, SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_pfxpassword_is_question_mark() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, "?".getBytes(), PKIToolkits.DIGEST_SM3, SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_success_when_flag_is_bigdata_dettach() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, 32767, PLAINBASE, handleResult);
		// 测试结果
		assertTrue(handleResult.errorCode != 0L);
	}

	@Test
	public void should_return_error_code_when_flag_is_negative() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, PKIToolkits.DIGEST_SM3, -1, PLAINBASE, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_digest_is_backslash() {
		// 测试执行
		pkiTool.p7Sign(SM2_PRVKEY, SM2_SIGN_CER, "*[]", SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	/** 国密P7 验签 **/

	@Test
	public void should_verify_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Verify(SM2_DETTACH_SIGN_RESULT, FLAG_DETTACH, PLAIN, handleResult);

		// 测试结果
		// assertEquals(expected, handleResult);
		assertEquals(0L, handleResult.errorCode);
	}

	@Test
	public void should_verify_attach_without_base64() {
		// 预期结果
		long expected = 0L;
		// 测试执行
		pkiTool.p7Verify(SM2_ATTACH_SIGN_RESULT, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertEquals(expected, handleResult);
		assertEquals(expected, handleResult.errorCode);
	}

	@Test
	public void should_verify_dettach_with_base64() {
		// 预期结果
		long expected = 0L;
		// 测试执行
		pkiTool.p7Verify(SM2_DETTACH_BASE64_SIGN_RESULT, FLAG_DETTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		// assertEquals(expected, handleResult);
		assertEquals(expected, handleResult.errorCode);
	}

	@Test
	public void should_verify_attach_with_base64() {
		// 预期结果
		long expected = 0L;
		// 测试执行
		// Long handleResult = pkiTool.p7Verify(SM2_ATTACH_BASE64_SIGN_RESULT,
		// FLAG_ATTACH_BASE64, PLAINBASE);
		pkiTool.p7Verify(SM2_ATTACH_BASE64_SIGN_RESULT, FLAG_ATTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		// assertEquals(expected, handleResult);
		assertEquals(expected, handleResult.errorCode);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_is_null() {
		// 测试执行
		pkiTool.p7Verify(null, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_plain_is_null() {
		// 测试执行
		pkiTool.p7Verify(SM2_ATTACH_BASE64_SIGN_RESULT, SM2_FLAG_ATTACH, null, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_is_base64_but_flag_without_base64() {
		// 测试执行
		pkiTool.p7Verify(SM2_ATTACH_BASE64_SIGN_RESULT, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_is_special_character() {
		// 测试执行
		pkiTool.p7Verify("\\".getBytes(), SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_without_base64_but_flag_with_base64() {
		// 测试执行
		pkiTool.p7Verify(SM2_ATTACH_SIGN_RESULT, SM2_FLAG_ATTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_is_attach_and_flag_is_dettach() {
		// 测试执行
		pkiTool.p7Verify(SM2_ATTACH_SIGN_RESULT, SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_is_dettach_and_flag_is_attach() {
		// 测试执行
		pkiTool.p7Verify(SM2_DETTACH_SIGN_RESULT, SM2_FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_signdata_is_forbidden() {
		// 测试执行
		pkiTool.p7Verify("*".getBytes(), SM2_FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_plain_is_forbidden() {
		// 测试执行
		pkiTool.p7Verify(SM2_DETTACH_BASE64_SIGN_RESULT, SM2_FLAG_DETTACH_BASE64, "*".getBytes(), handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_code_when_p7Verify_flag_is_negative() {
		// 测试执行
		pkiTool.p7Verify(SM2_DETTACH_BASE64_SIGN_RESULT, -1, PLAINBASE, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_success_when_p7Verify_flag_is_bigdata() {
		// 测试执行
		pkiTool.p7Verify(SM2_ATTACH_BASE64_SIGN_RESULT, 32766, PLAINBASE, handleResult);
		// 测试结果
		// assertTrue(handleResult != 0L);
		assertFailP7Sign(handleResult);
	}

}
