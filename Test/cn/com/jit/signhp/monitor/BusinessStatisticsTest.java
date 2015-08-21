package cn.com.jit.signhp.monitor;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import junit.framework.Assert;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import cn.com.jit.cloud.common.dao.MongoConfigDao;
import cn.com.jit.cloud.common.dao.MongoManager;
import cn.com.jit.cloud.common.monitor.entity.BusinessStatisticsBean;

public class BusinessStatisticsTest {
	private String								P1Sign					= "P1Sign";
	private int									countTimeOfEveryThread	= 100;
	private int									threadNum				= 20;
	private AtomicInteger						threadEndMark			= new AtomicInteger(threadNum);
	private static List<BusinessStatisticsBean>	oldDatas;
	private static MongoConfigDao				configDao				= new MongoConfigDao();
	private static MongoManager					mongo					= new MongoManager();

	@BeforeClass
	public static void before() {
		oldDatas = configDao.findAll(BusinessStatisticsBean.class);
		mongo.dropCollection(configDao.getDbName(), BusinessStatisticsBean.class);
	}

	@AfterClass
	public static void after() {
		mongo.dropCollection(configDao.getDbName(), BusinessStatisticsBean.class);
		if (oldDatas != null && oldDatas.size() > 0) {
			for (BusinessStatisticsBean o : oldDatas) {
				configDao.saveOrUpdate(o);
			}
		}
	}

	@Test
	public void should_return_correct_result_when_count() {
		BusinessStatistics.init();
		BusinessStatistics.setTurnOn(true);
		int successNum = 50;
		int failedNum = 5;
		singleThreadCount(successNum, failedNum);

		BusinessStatisticsBean count = BusinessStatistics.getCount(P1Sign);
		Assert.assertEquals(successNum, count.getSuccessNum());
		Assert.assertEquals(failedNum, count.getFailedNum());
	}

	private void singleThreadCount(int successNum, int failedNum) {
		for (int i = 0; i < successNum; i++) {
			BusinessStatistics.count(P1Sign, true);
		}

		for (int i = 0; i < failedNum; i++) {
			BusinessStatistics.count(P1Sign, false);
		}
	}

	@Test
	public void should_return_correct_result_when_multiple_thread_count() {
		BusinessStatistics.init();
		BusinessStatistics.setTurnOn(true);
		for (int i = 0; i < threadNum; i++) {
			new Thread(new TestThread()).start();
		}

		// 等待线程结束
		while (threadEndMark.get() > 0) {
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {}
		}

		BusinessStatisticsBean count = BusinessStatistics.getCount(P1Sign);
		Assert.assertEquals(countTimeOfEveryThread * threadNum, count.getSuccessNum());
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_illegal_argument_exception_when_count_with_null_business_type() {
		BusinessStatistics.setTurnOn(true);
		BusinessStatistics.count(null, true);
	}

	@Test(expected = IllegalArgumentException.class)
	public void should_throw_illegal_argument_exception_when_count_with_empty_business_type() {
		BusinessStatistics.setTurnOn(true);
		BusinessStatistics.count("", true);
	}

	@Test
	public void should_return_0_when_turn_off_count() {
		BusinessStatistics.init();
		BusinessStatistics.setTurnOn(false);

		int successNum = 50;
		int failedNum = 5;
		singleThreadCount(successNum, failedNum);

		BusinessStatisticsBean count = BusinessStatistics.getCount(P1Sign);
		Assert.assertEquals(0, count.getSuccessNum());
		Assert.assertEquals(0, count.getFailedNum());
	}

	@Test
	public void should_send_success() {
		mongo.dropCollection(configDao.getDbName(), BusinessStatisticsBean.class);
		BusinessStatistics.init();
		BusinessStatistics.setTurnOn(true);
		int successNum = 50;
		int failedNum = 5;
		int times = 2;
		for (int i = 0; i < times; i++) {
			singleThreadCount(successNum, failedNum);
			BusinessStatistics.send();
		}

		List<BusinessStatisticsBean> currentStatistics = configDao.findAll(BusinessStatisticsBean.class);
		Assert.assertEquals(BusinessStatistics.getBusinessCount(), currentStatistics.size());
		BusinessStatisticsBean current = configDao.createQuery(BusinessStatisticsBean.class)
				.filter("businessType", P1Sign).get();
		Assert.assertEquals(expect(successNum, failedNum), current);
		Assert.assertTrue(50 * times == current.getTotalSuccess());
		Assert.assertTrue(5 * times == current.getTotalFailed());
	}

	private BusinessStatisticsBean expect(int successNum, int failedNum) {
		BusinessStatisticsBean expect = new BusinessStatisticsBean(P1Sign, 0);
		expect.setFailedNum(failedNum);
		expect.setSuccessNum(successNum);
		return expect;
	}

	@Test
	public void should_not_send_when_turn_off() {
		mongo.dropCollection(configDao.getDbName(), BusinessStatisticsBean.class);
		BusinessStatistics.setTurnOn(false);
		BusinessStatistics.send();

		List<BusinessStatisticsBean> currentStatistics = configDao.findAll(BusinessStatisticsBean.class);
		Assert.assertEquals(0, currentStatistics.size());
	}

	private class TestThread implements Runnable {
		@Override
		public void run() {
			for (int i = 0; i < countTimeOfEveryThread; i++) {
				BusinessStatistics.count(P1Sign, true);
			}
			threadEndMark.getAndDecrement();
		}
	}
}
