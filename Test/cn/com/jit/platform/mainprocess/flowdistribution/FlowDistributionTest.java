package cn.com.jit.platform.mainprocess.flowdistribution;

import static cn.com.jit.platform.mainprocess.flowdistribution.FlowDistributionTestHelper.getChildProcessInfo;
import static cn.com.jit.platform.mainprocess.flowdistribution.FlowDistributionTestHelper.getChildProcessInfos;
import static cn.com.jit.platform.mainprocess.flowdistribution.FlowDistributionTestHelper.getFlowDistribution;
import static cn.com.jit.platform.mainprocess.flowdistribution.FlowDistributionTestHelper.getInitFlowDistribution;
import static org.easymock.EasyMock.verify;

import org.junit.Test;

import cn.com.jit.platform.mainprocess.bean.ChildProcessInfo;

public class FlowDistributionTest {

	@Test
	public void should_success_when_init_with_default_config() {
		// 测试准备
		FlowDistribution flowDistribution = getInitFlowDistribution();

		// 测试执行
		flowDistribution.init(getChildProcessInfo());

		// 校验结果
		verify(flowDistribution.getCommandExecutor());
	}

	@Test
	public void should_success_when_init_with_custom_config() {
		// 测试准备
		FlowDistribution flowDistribution = getInitFlowDistribution();

		// 测试执行
		flowDistribution.init(getChildProcessInfo());

		// 校验结果
		verify(flowDistribution.getCommandExecutor());
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_illegal_argument_exception_when_join_with_empty_childProcessInfos() {
		FlowDistribution flowDistribution = new FlowDistribution();
		flowDistribution.join();
	}

	@Test
	public void should_success_when_join_with_right_childProcessInfo() {
		ChildProcessInfo childProcessInfo = getChildProcessInfo();

		// 测试准备
		FlowDistribution flowDistribution = getFlowDistribution(childProcessInfo);

		// 测试执行
		flowDistribution.join(childProcessInfo);

		// 校验结果
		verify(flowDistribution.getCommandExecutor());
	}

	@Test
	public void should_success_when_join_with_right_childProcessInfos() {
		// 期待方法执行的次数
		int expectTimes = 10;

		// 测试准备
		FlowDistribution flowDistribution = getFlowDistribution(expectTimes);

		// 测试执行
		flowDistribution.join(getChildProcessInfos(expectTimes));

		// 校验结果
		verify(flowDistribution.getCommandExecutor());
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_illegal_argument_exception_when_exit_with_empty_childProcessInfos() {
		FlowDistribution flowDistribution = new FlowDistribution();
		flowDistribution.exit();
	}

	@Test
	public void should_success_when_exit_with_right_childProcessInfos() {
		// 期待方法执行的次数
		int expectTimes = 10;

		// 测试准备
		FlowDistribution flowDistribution = getFlowDistribution(expectTimes);

		// 测试执行
		flowDistribution.exit(getChildProcessInfos(expectTimes));

		// 校验结果
		verify(flowDistribution.getCommandExecutor());
	}

}
