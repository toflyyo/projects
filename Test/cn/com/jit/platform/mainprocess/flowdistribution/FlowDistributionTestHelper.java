package cn.com.jit.platform.mainprocess.flowdistribution;

import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import cn.com.jit.platform.common.command.CommandExecutor;
import cn.com.jit.platform.mainprocess.bean.ChildProcessInfo;
import cn.com.jit.platform.mainprocess.bean.ChildProcessInfos;
import cn.com.jit.platform.mainprocess.flowdistribution.FlowDistribution.OptType;

public class FlowDistributionTestHelper {

	public static FlowDistribution getInitFlowDistribution() {
		FlowDistribution flowDistribution = new FlowDistribution();

		CommandExecutor commandUtilsMok = createMock(CommandExecutor.class);
		expect(commandUtilsMok.execCommand(FlowDistribution.COMMAND_DELETE_ALL_RULE)).andReturn(true).times(1);
		expect(commandUtilsMok.execCommand(getCommandByChildProcessInfo(getChildProcessInfo()))).andReturn(true).times(
				1);
		replay(commandUtilsMok);

		flowDistribution.setCommandExecutor(commandUtilsMok);
		return flowDistribution;
	}

	public static FlowDistribution getFlowDistribution(int expectTimes) {
		FlowDistribution flowDistribution = new FlowDistribution();

		CommandExecutor commandUtilsMok = createMock(CommandExecutor.class);
		expect(commandUtilsMok.execCommand(anyString())).andReturn(true).times(expectTimes);

		replay(commandUtilsMok);
		flowDistribution.setCommandExecutor(commandUtilsMok);
		return flowDistribution;
	}

	public static FlowDistribution getFlowDistribution(ChildProcessInfo childProcessInfo) {
		FlowDistribution flowDistribution = new FlowDistribution();

		CommandExecutor commandUtilsMok = createMock(CommandExecutor.class);
		expect(commandUtilsMok.execCommand(getCommandByChildProcessInfo(childProcessInfo))).andReturn(true).times(1);
		replay(commandUtilsMok);
		flowDistribution.setCommandExecutor(commandUtilsMok);

		return flowDistribution;
	}

	public static ChildProcessInfo getChildProcessInfo() {
		ChildProcessInfo childProcessInfo = new ChildProcessInfo();
		childProcessInfo.setPort(9000);
		childProcessInfo.setSerialNum(1);
		return childProcessInfo;
	}

	public static ChildProcessInfo[] getChildProcessInfos(int num) {
		ChildProcessInfo[] childProcessInfos = new ChildProcessInfo[num];
		for (int i = 0; i < num; i++) {
			childProcessInfos[i] = new ChildProcessInfo();
		}
		return childProcessInfos;
	}

	public static String getCommandByChildProcessInfo(ChildProcessInfo childProcessInfo) {
		int localServerPort = FlowDistribution.defaultServerPort;
		;
		String localChildProcessIp = FlowDistribution.defaultChildProcessIp;
		;
		return String.format(FlowDistribution.COMMAND_CREATE_RULE, OptType.CREATE.getOptTypeStr(), localServerPort,
				localChildProcessIp, childProcessInfo.getPort(), ChildProcessInfos.getChildProcessNum(),
				childProcessInfo.getSerialNum());
	}
}
