package cn.com.jit.signhp.pkcs;

import static org.junit.Assert.*;
import static cn.com.jit.signhp.policy.RuntimePolicyTestHelper.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import junit.framework.Assert;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.ida.util.pki.encoders.Base64;
import cn.com.jit.platform.pki.HandleResult;
import cn.com.jit.platform.pki.PKIToolkits;
import cn.com.jit.signhp.policy.RuntimePolicy;
import cn.com.jit.signhp.policy.SymmEncConfigList;
import cn.com.jit.signhp.policy.SymmEncryptConfig;

public class SymmetricKeyTest {

	private SymmetricKey	key;
	static {
		new PKIToolkits().loadLibrary();
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {}

	@Before
	public void setUp() throws Exception {
		SymmEncryptConfig config = getSymmEncryptConfig();
		List<SymmEncryptConfig> symmEncConfigList = new ArrayList<>();
		symmEncConfigList.add(config);
		SymmEncConfigList symmEncPolicy = new SymmEncConfigList();
		symmEncPolicy.setSymmEncConfigList(symmEncConfigList);
		RuntimePolicy policy = new RuntimePolicy();
		policy.setSymmEncConfigList(symmEncPolicy);
		this.key = policy.getSymmetricKey("key.00000");
	}

	@After
	public void tearDown() throws Exception {}

	@Test
	public void should_encrypt_success_with_base64() {
		// 测试准备
		byte[] expected = Base64.encode("test plain".getBytes());

		// 测试执行
		HandleResult result = this.key.encrypt(expected, true);

		// 测试验证
		assertTrue(Arrays.equals(expected, key.decrypt(result.getResultData(), true).getResultData()));
	}

	@Test
	public void should_encrypt_success_without_base64() {
		// 测试准备
		byte[] expected = "test plain".getBytes();

		// 测试执行
		HandleResult result = this.key.encrypt(expected, false);

		// 测试验证
		assertTrue(Arrays.equals(expected, key.decrypt(result.resultData, false).getResultData()));
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_encrypt_throw_exception_when_plain_is_null() {
		// 测试执行
		key.encrypt(null, true);
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_encrypt_throw_exception_when_plain_is_empty() {
		// 测试执行
		key.encrypt(new byte[0], true);
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_decrypt_throw_exception_when_plain_is_null() {
		// 测试执行
		key.decrypt(null, true);
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_decrypt_throw_exception_when_plain_is_empty() {
		// 测试执行
		key.decrypt(new byte[0], true);
	}
	@Test
	public void should_encrypt_resultData_match_symmetricKey_decrypt(){
		String plaindata = "test";
		HandleResult encryptResult = key.encrypt(plaindata.getBytes(), false);
		HandleResult decryptResult = key.decrypt(encryptResult.getResultData(), false);
		Assert.assertEquals(plaindata, new String(decryptResult.resultData));
	}
	@Test(expected = PKCSException.class)
	public void should_decrypt_fail_for_error_isBase64Flag(){
		String plaindata = "test";
		byte[] encryptResult = key.encrypt(plaindata.getBytes(), true).getResultData();
		key.decrypt(encryptResult, false);
	}
	@Test
	public void should_return_success_xml_for_symmetricKey_encrypt(){
		
	}
	
}
