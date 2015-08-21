package cn.com.jit.platform.pki;

import java.util.LinkedHashSet;
import java.util.Set;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import cn.com.jit.signhp.core.BusinessConstants;

public class MainSingleBusiness {
	private static Set<String>	businessSet	= new LinkedHashSet<>();
	private static String		bigData		= "b";
	private static String		smallData	= "s";
	static {
		businessSet.add(BusinessConstants.P1_SIGN);
		businessSet.add(BusinessConstants.P1_VERIFY);
		businessSet.add(BusinessConstants.ATTACH_SIGN);
		businessSet.add(BusinessConstants.ATTACH_VERIFY_SIGN);
		businessSet.add(BusinessConstants.DETACH_SIGN);
		businessSet.add(BusinessConstants.DETACH_VERIFY_SIGN);
		businessSet.add(BusinessConstants.SYMM_ENCRYPT);
		businessSet.add(BusinessConstants.SYMM_DECRYPT);
		businessSet.add(BusinessConstants.ENVELOP);
		businessSet.add(BusinessConstants.DECRYPT_ENVELOP);
		businessSet.add(BusinessConstants.DIGEST);
	}

	public static void main(String[] args) {
		helpInfo(args);
		if (args.length == 0) {
			for (String key : businessSet) {
				single(new String[] { key, bigData });
				single(new String[] { key, smallData });
			}
		} else {
			single(args);
		}
	}

	private static void single(String[] args) {
		String businessType = args[0];
		boolean isBigStr = args[1].equals(bigData) ? true : false;

		Result result = null;
		switch (businessType) {
		case BusinessConstants.P1_SIGN:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolKitsP1SignStreamSuccessTest.class,
						PKIToolkitsP1SignStreamParamsTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsP1SignFaileTest.class, PKIToolkitsP1SignSuccessTest.class,
						PKIToolkitsP1Test.class, PKIToolkitsBase64P1SignSuccessTest.class,
						PKIToolkitsRSA2048P1Test.class, PKIToolkitsSM2P1Test.class);
			}
			break;
		case BusinessConstants.P1_VERIFY:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsP1VerifyStreamParamsTest.class,
						PKIToolkitsP1VerifyStreamSuccessTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsP1VSignFaileTest.class, PKIToolkitsP1VSignSuccessTest.class,
						PKIToolkitsRSA2048P1Test.class, PKIToolkitsSM2P1Test.class);
			}
			break;
		case BusinessConstants.ATTACH_SIGN:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsP7AttachSignStreamSuccessTest.class,
						PKIToolkitsP7SignStreamParamsTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsP7AttachhSignSuccessTest.class,
						PKIToolkitsBase64P7AttachhSignSuccessTest.class, PKIToolkitsP7SignFailedTest.class,
						PKIToolkitsP7Test.class, PKIToolkitsSM2P1Test.class);
			}
			break;
		case BusinessConstants.ATTACH_VERIFY_SIGN:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsP7AttachVerifyStreamSuccessTest.class,
						PKIToolkitsP7AttachVerifyStreamParamsTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsP7Test.class, PKIToolkitsP7VSignFailedTest.class,
						PKIToolkitsP7VSignSuccessTest.class, PKIToolkitsSM2P1Test.class);
			}
			break;

		case BusinessConstants.DETACH_SIGN:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsP7DetachSignStreamSuccessTest.class,
						PKIToolkitsP7SignStreamParamsTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsBase64P7DettachSignSuccessTest.class,
						PKIToolkitsP7DettachSignSuccessTest.class, PKIToolkitsP7SignFailedTest.class,
						PKIToolkitsP7Test.class, PKIToolkitsSM2P1Test.class);
			}
			break;
		case BusinessConstants.DETACH_VERIFY_SIGN:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsP7DetachVerifyStreamSuccessTest.class,
						PKIToolkitsP7DetachVerifyStreamParamsTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsP7Test.class, PKIToolkitsP7VSignFailedTest.class,
						PKIToolkitsP7VSignSuccessTest.class, PKIToolkitsSM2P1Test.class);
			}
			break;
		case BusinessConstants.ENVELOP:
			if (isBigStr) {
				result = JUnitCore.runClasses();
			} else {
				result = JUnitCore.runClasses(PKIToolkitsBase64P7EnvelopeSuccessTest.class,
						PKIToolkitsP7EnvelopeFailedTest.class, PKIToolkitsP7EnvelopeSuccessTest.class,
						PKIToolkitsP7EnvelopeTest.class, PKIToolkitsSM2EnvelopeTest.class);
			}
			break;
		case BusinessConstants.DECRYPT_ENVELOP:
			if (isBigStr) {
				result = JUnitCore.runClasses();
			} else {
				result = JUnitCore.runClasses(PKIToolkitsP7DecryptEnvelopeFailedTest.class,
						PKIToolkitsP7DecryptEnvelopeSuccessTest.class);
			}
			break;
		case BusinessConstants.SYMM_ENCRYPT:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsSymmetricEncryptStreamParamsTest.class,
						PKIToolkitsSymmetricEncryptStreamSuccessTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsSymmetricKeyTest.class);
			}
			break;
		case BusinessConstants.SYMM_DECRYPT:
			if (isBigStr) {
				result = JUnitCore.runClasses(PKIToolkitsSymmetricDecryptStreamParamsTest.class,
						PKIToolkitsSymmetricDecryptStreamSuccessTest.class);
			} else {
				result = JUnitCore.runClasses(PKIToolkitsSymmetricKeyTest.class);
			}
			break;
		default:
			if (isBigStr) {
				result = JUnitCore.runClasses();
			} else {
				result = JUnitCore.runClasses(PKIToolkitsDigestTest.class);
			}
		}

		if (result != null) {
			for (Failure failure : result.getFailures()) {
				System.out.println(failure.toString());
			}
			System.out.println(result.wasSuccessful());
		}
	}

	private static void helpInfo(String[] args) {
		if (args == null || args.length <= 1) {
			System.out.println("--------------------help info--------------");
			System.out.println("no params : run all unit tests.");
			System.out.println("two params[business b/s] : run specific business.");
			System.out.println("--------------------help info end--------------");
			System.out.println();
		} else if (!businessSet.contains(args[0])) {
			System.out.println("params error, should input two params.");
			System.out.println("----first is a business type from " + businessSet);
			System.out.println("----second is s(small data) or b(big data) .");
			System.out.println("for example : java -jar main.jar " + BusinessConstants.P1_SIGN + " b");
			System.exit(0);
		}

	}
}
