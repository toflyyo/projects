package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.*;
import org.junit.Assert;
import org.junit.Test;

public class PKIToolkitsRandomNumberTest extends BasePKIToolKitsTest {

	HandleResult	handleResult	= new HandleResult();

	@Test
	public void should_return_random_number_when_normal_parameter() {
		// 测试执行
		pkiTool.randomNumber(1, handleResult);
		// 测试结果
		Assert.assertEquals(0L, handleResult.errorCode);
	}

	@Test
	public void should_return_random_number_failed_when_parameter_is_zero() {
		// 测试执行
		pkiTool.randomNumber(0, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

	@Test
	public void should_return_random_number_failed_when_parameter_is_negative() {
		// 测试执行
		pkiTool.randomNumber(-1, handleResult);
		// 测试结果
		assertFailed(handleResult);
	}

}
