package ru.avm.security.acl.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.amqp.core.ExchangeTypes;
import org.springframework.amqp.rabbit.annotation.Exchange;
import org.springframework.amqp.rabbit.annotation.Queue;
import org.springframework.amqp.rabbit.annotation.QueueBinding;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;
import ru.avm.common.dto.CompanyDto;

@RequiredArgsConstructor

@Component
public class UpdateHierarchyListener {

    private final AdminService adminService;

    @RabbitListener(
            bindings = @QueueBinding(
                    value = @Queue(name = "companies-hierarchy-update_store-service"),
                    exchange = @Exchange(name = "amq.topic", type = ExchangeTypes.TOPIC, declare = Exchange.FALSE),
                    key = {"companies.create", "companies.*.update"}),
            errorHandler = "rabbitErrorHandler"
    )
    public void updateCmpHierarchyListener(@SuppressWarnings("unused") CompanyDto dto) {
        adminService.updateHierarchy();
    }


}
