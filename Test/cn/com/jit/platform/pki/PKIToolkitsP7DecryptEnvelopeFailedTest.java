package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.ENVELOPEDATA;
import static cn.com.jit.platform.pki.SignHelper.PRVKEY;
import static cn.com.jit.platform.pki.SignHelper.assertFailed;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7DecryptEnvelopeFailedTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { null, 0, ENVELOPEDATA,handleResult }, { "".getBytes(), 0, ENVELOPEDATA,handleResult }, { PRVKEY, 0, null,handleResult },
				{ PRVKEY, 0, "".getBytes(),handleResult }, { PRVKEY, -1, ENVELOPEDATA,handleResult }, { "<>".getBytes(), 0, ENVELOPEDATA,handleResult },
				{ PRVKEY, 0, "%^&*@!".getBytes(),handleResult }, };
		return Arrays.asList(objects);
	}

	private byte[]	privateKey;
	private int		flag;
	private byte[]	EnvelopeDate;
	private HandleResult out;

	public PKIToolkitsP7DecryptEnvelopeFailedTest(byte[] privateKey, int flag, byte[] EnvelopeDate,HandleResult out) {
		super();
		this.privateKey = privateKey;
		this.flag = flag;
		this.EnvelopeDate = EnvelopeDate;
		this.out=out;
	}

	@Test
	public void testPkiDecryptEnvelope() {
		 pkiTool.p7DecryptEnvelope(privateKey, flag, EnvelopeDate,out);
		assertFailed(out);
	}
}
