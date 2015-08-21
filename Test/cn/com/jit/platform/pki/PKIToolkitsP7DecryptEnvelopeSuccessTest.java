package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATA;
import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATE_BASE64;
import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATE_BASE64_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATE_RSA_2048;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY_2048;
import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7DecryptEnvelopeSuccessTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { PRVKEY, 0, ENVELOPEDATA,handleResult }, { PRVKEY, 2, ENVELOPEDATE_BASE64,handleResult},
				{ PRVKEY_2048, 0, ENVELOPEDATE_RSA_2048,handleResult }, { PRVKEY_2048, 2, ENVELOPEDATE_BASE64_RSA_2048 ,handleResult}, };
		return Arrays.asList(objects);
	}

	private byte[]	privateKey;
	private int		flag;
	private byte[]	EnvelopeDate;
	private  HandleResult out;

	public PKIToolkitsP7DecryptEnvelopeSuccessTest(byte[] privateKey, int flag, byte[] EnvelopeDate,HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.flag = flag;
		this.EnvelopeDate = EnvelopeDate;
		this.out=out;
	}

	@Test
	public void testPkiDecryptEnvelope() {
		pkiTool.p7DecryptEnvelope(privateKey, flag, EnvelopeDate,out);
		assertEquals(0L, out.errorCode);
	}
}
