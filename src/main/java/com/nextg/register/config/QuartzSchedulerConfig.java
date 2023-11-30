package com.nextg.register.config;

import com.nextg.register.service.CardPaymentAutoService;
import org.quartz.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.quartz.JobDetailFactoryBean;
import org.springframework.scheduling.quartz.SchedulerFactoryBean;

@Configuration
public class QuartzSchedulerConfig {

//    @Bean
//    public JobDetailFactoryBean paymentJobDetail() {
//        JobDetailFactoryBean jobDetailFactoryBean = new JobDetailFactoryBean();
//        jobDetailFactoryBean.setJobClass(CardPaymentAutoService.class);
//        jobDetailFactoryBean.setDurability(true);
//
//        JobDataMap jobDataMap=  new JobDataMap();
//        jobDataMap.put("subscription", new CardPaymentAutoService());
//        return null;
//    }
//
//    @Bean
//    public Trigger paymentJobTrigger(JobDetail paymentJobDetail) {
//        return TriggerBuilder.newTrigger()
//                .forJob(paymentJobDetail)
//                .withIdentity("paymentJobTrigger")
//                .withSchedule(CronScheduleBuilder.cronSchedule("0 0 2 * * ?")) // Chạy mỗi ngày vào lúc 2 giờ sáng
//                .build();
//    }
//    @Bean
//    public SchedulerFactoryBean schedulerFactoryBean(JobDetail paymentJobDetail, Trigger paymentJobTrigger) {
//        SchedulerFactoryBean schedulerFactoryBean = new SchedulerFactoryBean();
//        schedulerFactoryBean.setJobDetails(paymentJobDetail);
//        schedulerFactoryBean.setTriggers(paymentJobTrigger);
//        return schedulerFactoryBean;
//    }
}
