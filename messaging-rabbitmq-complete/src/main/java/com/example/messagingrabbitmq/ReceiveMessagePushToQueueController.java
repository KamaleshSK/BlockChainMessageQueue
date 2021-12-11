package com.example.messagingrabbitmq;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

@RestController
@RequestMapping("/queue")
public class ReceiveMessagePushToQueueController {
	
	@Autowired
	private RabbitTemplate rabbitTemplate;
	
	@PostMapping("/push")
	public void pushNewBlockToQueue(@RequestBody Message message) {
		String messageString = new Gson().toJson(message); 
		rabbitTemplate.convertAndSend(MessagingRabbitmqApplication.topicExchangeName, "foo.bar.baz", messageString);
	}
	
}
