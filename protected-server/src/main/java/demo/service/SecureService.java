package demo.service;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/secure")
public class SecureService {

	@RequestMapping("secure")
	public String test()
	{
		return "{ message: \"Success!\"}";
	}
}
