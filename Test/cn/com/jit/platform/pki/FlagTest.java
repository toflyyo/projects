package cn.com.jit.platform.pki;

import static org.junit.Assert.*;

import org.junit.Test;

public class FlagTest {

	private Flag	flag	= new Flag();

	@Test
	public void should_return_0_with_attach() {
		// 测试准备
		int expected = 0;
		flag.setDetach(false);

		// 测试执行
		int actual = flag.toFlag();

		// 校验结果
		assertEquals(expected, actual);
	}

	@Test
	public void should_return_1_with_detach() {
		// 测试准备
		int expected = 1;
		flag.setDetach(true);

		// 测试执行
		int actual = flag.toFlag();

		// 校验结果
		assertEquals(expected, actual);
	}

	@Test
	public void should_return_1_with_Base64() {
		// 测试准备
		int expected = 2;
		this.flag.setBase64(true);

		// 测试执行
		int actual = this.flag.toFlag();

		// 校验结果
		assertEquals(expected, actual);
	}

	@Test
	public void should_return_1_with_GM() {
		// 测试准备
		int expected = 4;
		this.flag.setSM2(true);

		// 测试执行
		int actual = this.flag.toFlag();

		// 校验结果
		assertEquals(expected, actual);
	}
	
	@Test
	public void should_return_7_with_detach_base64_GM() {
		// 测试准备
		int expected = 7;
		this.flag.setDetach(true);
		this.flag.setBase64(true);
		this.flag.setSM2(true);
		
		// 测试执行
		int actual = this.flag.toFlag();
		
		// 校验结果
		assertEquals(expected, actual);
	}

}
