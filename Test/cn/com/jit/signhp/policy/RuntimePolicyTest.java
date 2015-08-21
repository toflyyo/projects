package cn.com.jit.signhp.policy;

import static org.junit.Assert.*;
import static cn.com.jit.signhp.policy.RuntimePolicyTestHelper.*;

import org.junit.Test;

import cn.com.jit.signhp.pkcs.Pkcs1;

public class RuntimePolicyTest {

	@Test
	public void should_get_pkcs1_success_with_id_and_usage() {
		// 测试准备
		CertConfigList certConfigList = getCertConfigList();
		Pkcs1 expected = new Pkcs1();
		expected.setCertConfig(certConfigList.getCertConfigList().get(0));
		RuntimePolicy policy = new RuntimePolicy();
		policy.setCertConfigList(certConfigList);

		// 测试执行
		Pkcs1 actual = policy.getPkcs1("certid", RuntimePolicy.USAGE_SIGN);

		// 校验结果
		assertEquals(expected, actual);
	}
}
