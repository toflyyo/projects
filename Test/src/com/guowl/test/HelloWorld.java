package com.guowl.test;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


public class HelloWorld {
	public static void main(String[] args) {
		// testRandom();
		int i = Calendar.getInstance().get(Calendar.DAY_OF_WEEK);
		System.out.println(i);
		// testRandom(1);

		SimpleDateFormat df = new SimpleDateFormat("HH:mm");

		int hour = Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
		int min = Calendar.getInstance().get(Calendar.MINUTE);
		System.out.println(df.format(new Date()));
	}

	private static void testRandom(Serializable id) {

		while (true) {
			test();
			try {
				Thread.sleep(1000 * 1);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private static void test() {
		int max = 5;
		int min = 1;
		Random random = new Random();
		Map<Integer, Integer> count = new HashMap<Integer, Integer>();
		count.put(1, 0);
		count.put(2, 0);
		count.put(3, 0);
		count.put(4, 0);
		count.put(5, 0);
		for (int i = 0; i < 10000; i++) {
			try {
				Thread.sleep(500 * 1);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			int s = random.nextInt(max) % (max - min + 1) + min;
			Integer integer = count.get(s);
			count.put(s, ++integer);
			System.out.println(count);
		}
		System.out.println(count);
	}

}
