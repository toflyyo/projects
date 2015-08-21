package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.PLAIN;
import static cn.com.jit.platform.pki.SignHelper.PLAINBASE;
import static cn.com.jit.platform.pki.SignHelper.assertFailBase64Dncode;
import static cn.com.jit.platform.pki.SignHelper.assertFailBase64Encode;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessBase64Dncode;
import static cn.com.jit.platform.pki.SignHelper.assertSuccessBase64Encode;

import org.junit.Assert;
import org.junit.Test;

public class PKIToolkitsBase64Test extends BasePKIToolKitsTest {
	/**
	 * Base64编码
	 */
	HandleResult handleResult=new HandleResult();
	@Test
	public void should_return_right_base64_encode() {
		// 测试执行
		pkiTool.base64Encode(PLAIN,handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_null() {
		// 测试执行
		 pkiTool.base64Encode(null,handleResult);
		// 测试结果
		assertFailBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_letter_and_number() {
		// 测试执行
		 pkiTool.base64Encode("agbcas131312asdad8765".getBytes(),handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_letter_and_character() {
		// 测试执行
		 pkiTool.base64Encode("asdhasdha*&^%$#@asda".getBytes(),handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_number_and_character() {
		// 测试执行
		 pkiTool.base64Encode("1345677768:;/*\\*76".getBytes(),handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_chinese() {
		// 测试执行
		 pkiTool.base64Encode("测试".getBytes(),handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_zero() {
		// 测试执行
		 pkiTool.base64Encode("0".getBytes(),handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_negative() {
		// 测试执行
		 pkiTool.base64Encode("-1".getBytes(),handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_base64() {
		// 测试执行
		 pkiTool.base64Encode(PLAINBASE,handleResult);
		// 测试结果
		assertSuccessBase64Encode(handleResult);
	}

	@Test
	public void should_return_plain_is_empty() {
		// 测试执行
		 pkiTool.base64Encode("".getBytes(),handleResult);
		// 测试结果
		assertFailBase64Encode(handleResult);
	}

	/**
	 * base64解码
	 */
	@Test
	public void should_return_right_base64_decode() {
		// 测试执行
		 pkiTool.base64Decode(PLAINBASE,handleResult);
		// 测试结果
		assertSuccessBase64Dncode(handleResult);
	}

	@Test
	public void should_return_encode_result_is_null() {
		// 测试执行
		 pkiTool.base64Decode(null,handleResult);
		// 测试结果
		assertFailBase64Encode(handleResult);
	}

	@Test
	public void should_return_base_result_is_letter_and_number() {
		// 测试执行
		 pkiTool.base64Decode("asdhasdjkas1q2312313".getBytes(),handleResult);
		// 测试执行
		assertSuccessBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_result_is_letter_and_character() {
		// 测试执行
		 pkiTool.base64Decode("asddasdas^&%$#".getBytes(),handleResult);
		// 测试结果
		assertFailBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_result_is_number_and_character() {
		// 测试执行
		 pkiTool.base64Decode("a123123213)&^%*(".getBytes(),handleResult);
		// 测试结果
		assertFailBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_result_is_chinese() {
		// 测试执行
		 pkiTool.base64Decode("测试".getBytes(),handleResult);
		// 测试结果
		assertFailBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_result_is_negtive() {
		// 测试执行
		 pkiTool.base64Decode("-1".getBytes(),handleResult);
		// 测试结果
		assertFailBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_result_is_zero() {
		// 测试执行
		 pkiTool.base64Decode("0".getBytes(),handleResult);
		// 测试结果
		assertFailBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_result_is_encode() {
		// 测试执行
		 pkiTool.base64Decode(PLAINBASE,handleResult);
		// 测试结果
		assertSuccessBase64Dncode(handleResult);
	}

	@Test
	public void should_return_base_code_each_another_eg1() {
		// 测试执行
		 pkiTool.base64Encode(PLAIN,handleResult);
		// 测试结果
		Assert.assertArrayEquals(PLAINBASE, handleResult.resultData);

	}

	@Test
	public void should_return_base_code_each_anpother_eg2() {
		// 测试执行
		 pkiTool.base64Decode(PLAINBASE,handleResult);
		// 测试结果
		Assert.assertArrayEquals(PLAIN, handleResult.resultData);
	}

}
