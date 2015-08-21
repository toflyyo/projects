package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.ZERO;
import static cn.com.jit.platform.pki.SignHelper.assertFailDigest;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessDigest;

import org.junit.Test;

public class PKIToolkitsDigestTest extends BasePKIToolKitsTest {

	/**
	 * 摘要单元测试用例
	 */
	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_right_digest() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SHA1, PLAIN, handleResult);
		// 测试结果
		assertSuccessDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_empty() {
		// 测试执行
		pkiTool.digest("", PLAIN, handleResult);
		// 测试结果
		assertFailDigest(handleResult);

	}

	@Test
	public void should_return_palin_is_empty() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SHA1, "".getBytes(), handleResult);
		// 测试结果
		assertFailDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_null() {
		// 测试执行
		pkiTool.digest(null, PLAIN, handleResult);
		// 测试结果
		assertFailDigest(handleResult);
	}

	@Test
	public void should_return_plain_is_null() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SHA1, null, handleResult);
		// 测试结果
		assertFailDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_sha256() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SHA256, PLAIN, handleResult);
		// 测试结果
		assertSuccessDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_md5() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_MD5, PLAIN, handleResult);
		// 测试结果
		assertSuccessDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_zero() {
		// 测试执行
		pkiTool.digest("0", PLAIN, handleResult);
		// 测试结果
		assertFailDigest(handleResult);
	}

	@Test
	public void should_return_plain_is_zero() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SHA1, ZERO, handleResult);
		// 测试结果
		assertSuccessDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_special_character() {
		// 测试执行
		pkiTool.digest("\\", PLAIN, handleResult);
		// 测试结果
		assertFailDigest(handleResult);
	}

	@Test
	public void should_return_plain_is_special_character() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SHA1, "*&^".getBytes(), handleResult);
		// 测试结果
		assertSuccessDigest(handleResult);
	}

	@Test
	public void should_return_digest_is_sm3() {
		// 测试执行
		pkiTool.digest(PKIToolkits.DIGEST_SM3, PLAIN, handleResult);
		// 测试结果
		assertSuccessDigest(handleResult);
	}
}
