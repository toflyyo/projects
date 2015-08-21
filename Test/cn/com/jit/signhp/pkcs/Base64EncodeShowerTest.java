package cn.com.jit.signhp.pkcs;

import org.junit.Assert;
import org.junit.Test;

public class Base64EncodeShowerTest {

	@Test
	public void should_formBase64EncodeArr_output_Str_when_input_array(){
		byte[] originalDate = null;
		String string = Base64EncodeShower.formBase64EncodeArr(originalDate, true);
		Assert.assertEquals("", string);
	}
}
