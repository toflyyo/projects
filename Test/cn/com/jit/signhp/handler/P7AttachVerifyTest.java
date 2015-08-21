package cn.com.jit.signhp.handler;

import junit.framework.Assert;

import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.platform.pki.PKIToolkits;
import cn.com.jit.platform.pki.SignHelper;
import cn.com.jit.signhp.core.Request;
import cn.com.jit.signhp.core.Response;
import cn.com.jit.signhp.policy.UpdatePolicy;

public class P7AttachVerifyTest {
	private static Request	request;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		request = new Request();
		request.putParameter("DSignData", SignHelper.SIGN_ATTACH_RESULT);
		request.putParameter("PlainBase64", false);
		request.putParameter("DSignContext.Version", "1.0");
		request.setBusinessType("P7Verify");

		UpdatePolicy businessPolicy = new UpdatePolicy();
		businessPolicy.setBusinessConfig();

		PKIToolkits pki = new PKIToolkits();
		pki.loadLibrary();
	}

	@Test
	public void should_success_when_attach_verify() {
		P7VerifyHandler p7Verify = new P7VerifyHandler();
		Response actualResponse = p7Verify.doBusiness(request);
		Assert.assertTrue(actualResponse.getStatus().equals("0"));
	}

}
