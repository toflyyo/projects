package cn.com.jit.platform.pki;

import static cn.com.jit.platform.pki.SignHelper.*;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PKIToolkitsP7EnvelopeFailedTest extends BasePKIToolKitsTest {
	static HandleResult handleResult=new HandleResult();
	@SuppressWarnings("rawtypes")
	@Parameters
	public static Collection perpareData() {
		Object[][] objects = { { SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, null,handleResult },
				{ SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, "".getBytes(),handleResult  },
				{ null, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 2, PLAINBASE,handleResult  },
				{ "".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, PLAIN ,handleResult },
				{ SIGN_CERT, null, 0, PLAIN,handleResult  }, { SIGN_CERT, "", 0, PLAIN,handleResult  },
				{ SIGN_CERT, PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, -1, PLAIN,handleResult  },
				{ "&^%$8".getBytes(), PKIToolkits.SYMMETRICARITHMETICTYPE_DES_EDE3_CBC, 0, PLAIN,handleResult  },
				{ SIGN_CERT, "\\/;:", 0, PLAIN,handleResult  }, };
		return Arrays.asList(objects);
	}

	private byte[]	publicKeyCertificate;
	private String	symmetricArithmeticType;
	private int		flag;
	private byte[]	originalData;
	private HandleResult out;

	public PKIToolkitsP7EnvelopeFailedTest(byte[] publicKeyCertificate, String symmetricArithmeticType, int flag,
			byte[] originalData,HandleResult out) {
		super();
		this.publicKeyCertificate = publicKeyCertificate;
		this.symmetricArithmeticType = symmetricArithmeticType;
		this.flag = flag;
		this.originalData = originalData;
		this.out=out;
	}

	@Test
	public void testPkiEnvelope() {
		 pkiTool.p7Envelope(publicKeyCertificate, symmetricArithmeticType, flag, originalData,out);
		assertFailed(out);
	}
}
