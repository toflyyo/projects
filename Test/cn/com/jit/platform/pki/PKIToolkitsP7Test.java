package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_ATTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH;
import static cn.com.jit.platform.pki.SignHelper.FLAG_DETTACH_BASE64;
import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_ATTACH_RESULT_BASE;
import static cn.com.jit.platform.pki.SignHelper.SIGN_CERT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT;
import static cn.com.jit.platform.pki.SignHelper.SIGN_RESULT_BASE;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailP7Sign;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7AttachSign;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7AttachSignNotBase;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7Sign;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7SignNotBase;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessP7Verify;

import java.io.UnsupportedEncodingException;

import org.junit.Test;

public class PKIToolkitsP7Test extends BasePKIToolKitsTest {

	/*
	 * p7签名单元测试用例
	 */
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7Sign(handleResult);
	}
	
	@Test
	public void test() {
		// 测试执行
		pkiTool.p7SignInit(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, 100,FLAG_DETTACH,  handleResult);
	}

	@Test
	public void should_return_digest_is_sha256_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7Sign(handleResult);
	}

	@Test
	public void should_return_digest_is_md5_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7Sign(handleResult);
		;
	}

	@Test
	public void should_return_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7AttachSign(handleResult);
	}

	@Test
	public void should_return_digest_is_sha256_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7AttachSign(handleResult);
	}

	@Test
	public void should_return_digest_is_md5_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7AttachSign(handleResult);
	}

	@Test
	public void should_return_dettach_with_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_DETTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		assertSuccessP7SignNotBase(handleResult);
	}

	@Test
	public void should_return_attach_with_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		assertSuccessP7AttachSignNotBase(handleResult);
	}

	@Test
	public void should_return_signPfx_is_zero_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(ZERO, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_signcert_is_null_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, null, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_DIGEST_is_zero_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, "0", FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_plain_is_zero_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, FLAG_ATTACH, ZERO, handleResult);
		// 测试结果
		assertSuccessP7AttachSign(handleResult);
	}

	@Test
	public void should_return_signpfx_is_null_attach_without_base64() {

		// 测试执行
		pkiTool.p7Sign(new byte[0], SIGN_CERT, PKIToolkits.DIGEST_MD5, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_when_plain_is_null_attach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA256, FLAG_ATTACH, new byte[0], handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_signcert_is_empty_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, new byte[0], PKIToolkits.DIGEST_MD5, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_error_when_signcert_is_invalid_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, "".getBytes(), PKIToolkits.DIGEST_SHA256, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_flag_is_bigdata_dettach_with_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_MD5, 32767, PLAINBASE, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_flag_is_negative_dettach_with_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, PKIToolkits.DIGEST_SHA1, -1, PLAINBASE, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_return_digest_is_backslash_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Sign(PRVKEY, SIGN_CERT, "*[]", FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	/*
	 * p7验签单元测试用例
	 */

	@Test
	public void should_verify_dettach_without_base64() {
		// 预期结果
		// long expected = 0L;

		// 测试执行
		pkiTool.p7Verify(SIGN_RESULT, FLAG_DETTACH, PLAIN, handleResult);

		// 测试结果
		// assertEquals(expected, handleResult);
		assertSuccessP7Verify(handleResult);
	}

	@Test
	public void should_verify_attach_without_base64() {
		// 预期结果
		// long expected = 0L;
		// 测试执行
		pkiTool.p7Verify(SIGN_ATTACH_RESULT, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		assertSuccessP7Verify(handleResult);
	}

	@Test
	public void should_verify_dettach_with_base64() {
		// 预期结果
		// long expected = 0L;
		// 测试执行
		pkiTool.p7Verify(SIGN_RESULT_BASE, FLAG_DETTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		assertSuccessP7Verify(handleResult);
	}

	@Test
	public void should_verify_attach_with_base64() {
		// 测试执行
		pkiTool.p7Verify(SIGN_ATTACH_RESULT_BASE, FLAG_ATTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		assertSuccessP7Verify(handleResult);
	}

	@Test
	public void should_verify_sign_result_is_null_attach_without_base64() {
		// 测试执行
		pkiTool.p7Verify(new byte[0], FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_plain_is_null_attach_without_base64() {
		// 测试执行
		pkiTool.p7Verify(SIGN_RESULT, FLAG_ATTACH, new byte[0], handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_sign_result_is_base64_attach_without_base64() {
		// 测试执行
		pkiTool.p7Verify(SIGN_ATTACH_RESULT_BASE, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_sign_result_without_base64_attach_with_base64() {
		// 测试执行
		pkiTool.p7Verify(SIGN_ATTACH_RESULT, FLAG_ATTACH_BASE64, PLAINBASE, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_sign_result_is_attach_and_flag_is_dettach() {
		// 测试执行
		pkiTool.p7Verify(SIGN_ATTACH_RESULT, FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_sign_result_is_dettach_and_flag_is_attach() {
		// 测试执行
		pkiTool.p7Verify(SIGN_RESULT, FLAG_ATTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_sign_is_forbidden_dettach_without_base64() {
		// 测试执行
		pkiTool.p7Verify("*".getBytes(), FLAG_DETTACH, PLAIN, handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_plain_is_forbidden() {
		// 测试执行
		pkiTool.p7Verify(SIGN_RESULT_BASE, FLAG_DETTACH_BASE64, "*".getBytes(), handleResult);
		// 测试结果
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

	@Test
	public void should_verify_flag_is_negative_attach_with_base64() throws UnsupportedEncodingException {
		// 测试执行
		pkiTool.p7Verify(SIGN_ATTACH_RESULT_BASE, -1, PLAINBASE, handleResult);
		// 测试结果
		System.out.print(new String(handleResult.errorDescription, "UTF-8"));
		// assertFailP7Verify(expected);
		assertFailP7Sign(handleResult);
	}

}
