package cn.com.jit.signhp.handler;

import java.util.List;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.cloud.common.dao.MongoConfigDao;
import cn.com.jit.cloud.common.dao.MongoManager;
import cn.com.jit.platform.pki.HandleResult;
import cn.com.jit.platform.pki.PKIToolkits;
import cn.com.jit.platform.pki.SignHelper;
import cn.com.jit.signhp.core.Request;
import cn.com.jit.signhp.core.Response;
import cn.com.jit.signhp.policy.CertConfig;
import cn.com.jit.signhp.policy.UpdatePolicy;

public class P7AttachSignTest {
	private static Request			request;
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
		request.putParameter("DSignMode", "0");
		request.putParameter("DSignContext.Version", "1.0");
		request.setBusinessType("P7Sign");

		oldCerts = configDao.findAll(CertConfig.class);
		mongo.dropCollection(configDao.getDbName(), CertConfig.class);
		generateCert();

		UpdatePolicy businessPolicy = new UpdatePolicy();
		businessPolicy.setBusinessConfig();

		PKIToolkits pki = new PKIToolkits();
		pki.loadLibrary();
	}

	@Test
	public void should_success_when_attach_sign() {
		P7SignHandler p7Sign = new P7SignHandler();
		Response actualResponse = p7Sign.doBusiness(request);
		PKIToolkits pkiTool = new PKIToolkits();
		HandleResult result = new HandleResult();
		pkiTool.p7Verify((byte[]) actualResponse.getParameter("DSignData"), 0, null, result);
		Assert.assertTrue(result.errorCode == 0);
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
}
