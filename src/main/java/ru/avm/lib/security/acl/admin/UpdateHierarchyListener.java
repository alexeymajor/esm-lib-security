package ru.avm.lib.security.acl.admin;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.ExchangeTypes;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;
import ru.avm.lib.common.dto.CompanyDto;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RequiredArgsConstructor

@Slf4j
@Component
public class UpdateHierarchyListener {

    private final AdminService adminService;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    @RabbitListener(
            bindings = @QueueBinding(
                    value = @Queue(name = "#{'companies-hierarchy-update_' + '${spring.application.name}'}"),
                    exchange = @Exchange(name = "amq.topic", type = ExchangeTypes.TOPIC, declare = Exchange.FALSE),
                    key = {"companies.create", "companies.*.update"}),
            errorHandler = "rabbitErrorHandler"
    )
    public void updateCmpHierarchyListener(@SuppressWarnings("unused") CompanyDto dto) {

        executor.submit(() -> {
            try {
                adminService.updateHierarchy();
            } catch (Exception e) {
                log.error("error update cmp hierarchy", e);
                throw e;
            }
        });

    }


}
