package cn.com.jit.signhp.pkcs;

import static org.junit.Assert.*;
import static cn.com.jit.signhp.policy.RuntimePolicyTestHelper.*;

import org.junit.Test;

import cn.com.jit.ida.util.pki.encoders.Base64;
import cn.com.jit.platform.pki.BasePKIToolKitsTest;
import cn.com.jit.platform.pki.HandleResult;
import cn.com.jit.signhp.policy.RuntimePolicy;

public class Pkcs1Test extends BasePKIToolKitsTest {

	private static final byte[]	PLAIN_TEXT	= "data1".getBytes();

	private Pkcs1				pkcs1		= new Pkcs1();

	@Override
	public void setUp() throws Exception {
		RuntimePolicy policy = new RuntimePolicy();
		policy.setCertConfigList(getCertConfigList());
		pkcs1 = policy.getPkcs1("certid", RuntimePolicy.USAGE_SIGN);
	}

	@Test
	public void should_do_pkcs1_sign_success() {
		// 测试执行
		HandleResult result = pkcs1.sign(PLAIN_TEXT, "SHA1", false);
		byte[] actual = result.getResultData();

		// 校验结果
		assertTrue(pkcs1.verify(actual, PLAIN_TEXT, "SHA1", false).isSuccess());
	}

	@Test
	public void should_do_pkcs1_sign_success_with_default_algorithm_when_digestAlgorithm_is_empty() {
		// 测试执行
		HandleResult result = pkcs1.sign(PLAIN_TEXT, "", false);
		byte[] actual = result.getResultData();

		// 校验结果
		assertTrue(pkcs1.verify(actual, PLAIN_TEXT, "SHA1", false).isSuccess());
	}

	@Test
	public void should_do_pkcs1_sign_success_with_plainBase64_when_plainBase64_is_true() {
		// 测试执行
		HandleResult result = pkcs1.sign(Base64.encode(PLAIN_TEXT), "SHA1", true);
		byte[] actual = result.getResultData();

		// 校验结果
		assertTrue(pkcs1.verify(actual, Base64.encode(PLAIN_TEXT), "SHA1", true).isSuccess());
	}

	@Test
	public void should_do_pkcs1_sign_success_with_default_algorithm_when_digestAlgorithm_is_null() {
		// 测试执行
		HandleResult result = pkcs1.sign(PLAIN_TEXT, null, false);
		byte[] actual = result.getResultData();

		// 校验结果
		assertTrue(pkcs1.verify(actual, PLAIN_TEXT, "SHA1", false).isSuccess());
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_exception_when_plain_is_null() {
		// 测试执行
		pkcs1.sign(null, "SHA1", false);
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_exception_when_plain_is_empty() {
		// 测试执行
		pkcs1.sign("".getBytes(), "SHA1", false);
	}

}
