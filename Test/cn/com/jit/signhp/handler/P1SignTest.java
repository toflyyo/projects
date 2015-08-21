package cn.com.jit.signhp.handler;

import java.util.Arrays;
import java.util.List;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.cloud.common.dao.MongoConfigDao;
import cn.com.jit.cloud.common.dao.MongoManager;
import cn.com.jit.platform.pki.PKIToolkits;
import cn.com.jit.platform.pki.SignHelper;
import cn.com.jit.signhp.core.Request;
import cn.com.jit.signhp.core.Response;
import cn.com.jit.signhp.policy.CertConfig;
import cn.com.jit.signhp.policy.UpdatePolicy;

public class P1SignTest {
	private static Request			request;
	private static Response			response;
	private static MongoConfigDao	configDao	= new MongoConfigDao();
	private static List<CertConfig>	oldCerts	= null;
	private static MongoManager		mongo		= new MongoManager();

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		request = new Request();
		request.putParameter("ApplyID", "rsa");
		request.putParameter("PlainData", SignHelper.PLAIN);
		request.putParameter("DSDigestALG", "SHA1");
		request.putParameter("PlainBase64", false);
		request.putParameter("DSignContext.Version", "1.0");
		request.setBusinessType("P1Sign");

		response = new Response();
		response.setStatus("0");
		response.putParameter("DSignContext.Version", "1.0");
		response.putParameter("doDSignResult.status", "true");
		response.putParameter("DSignData", SignHelper.SIGN_RESULT_P1_SHA1);
		response.putParameter("DSignData.stream", "true");

		oldCerts = configDao.findAll(CertConfig.class);
		mongo.dropCollection(configDao.getDbName(), CertConfig.class);
		generateCert();

		UpdatePolicy businessPolicy = new UpdatePolicy();
		businessPolicy.setBusinessConfig();

		PKIToolkits pki = new PKIToolkits();
		pki.loadLibrary();
	}

	@AfterClass
	public static void after() throws Exception {
		mongo.dropCollection(configDao.getDbName(), CertConfig.class);
		if (oldCerts != null) {
			for (CertConfig o : oldCerts) {
				configDao.saveOrUpdate(o);
			}
		}
	}

	private static void generateCert() {
		CertConfig config = new CertConfig();
		config.setCertID("rsa");
		config.setAliases("rsa1|rsa2|rsa3");
		config.setCert(SignHelper.SIGN_CERT);
		config.setPrvKey(SignHelper.PRVKEY);
		config.setDigestAlgorithm("SHA1");
		config.setSymmetricAlgorithm("DES3");
		config.getCertUseSet().setSignature(true);
		config.getCertUseSet().setVerify(true);
		config.setCanEncrypt(true);
		config.setSm2(false);
		configDao.saveOrUpdate(config);
	}

	@Test
	public void should_success_when_do_p1_sign() {
		P1SignHandler p1Sign = new P1SignHandler();
		Response actualResponse = p1Sign.doBusiness(request);
		Assert.assertTrue(isEqual(response, actualResponse));
	}

	private boolean isEqual(Response response, Response actualResponse) {
		boolean result = true;
		for (String key : response.getDatas().keySet()) {
			if (key != null && key.equals("DSignData")) {
				result = Arrays.equals((byte[]) response.getParameter(key), (byte[]) actualResponse.getParameter(key));
			} else {
				result = response.getParameter(key).equals(actualResponse.getParameter(key));
			}
			if (result == false) {
				return false;
			}
		}
		return true;
	}
}
