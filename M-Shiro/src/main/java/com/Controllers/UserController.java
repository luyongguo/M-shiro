package com.Controllers;

import java.util.List;
import javax.annotation.Resource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import com.page.Message;
import com.page.UserValidate;
import com.pojo.Mapping_UR;
import com.pojo.User;
import com.service.IUserService;

@Controller
public class UserController {

	@Resource
	private IUserService userService;
	@Resource
	private User user;
	@Resource
	private DefaultPasswordService passwordService;

	@RequestMapping(value = "/login", method = RequestMethod.POST)
	@ResponseBody
	public Message login(@RequestBody UserValidate userValidate) {
		
		UsernamePasswordToken token = new UsernamePasswordToken(userValidate.getUsername(), userValidate.getPassword());
		token.setRememberMe(userValidate.getRememberme());
		try {
//			String newpwd = passwordService.encryptPassword(userValidate.getPassword());
//			System.out.println(newpwd);
			SecurityUtils.getSubject().login(token);
			return new Message("login success");
		} catch (UnknownAccountException uae) {
			return new Message("error username");
		} catch (IncorrectCredentialsException ice) {
			return new Message("error password");
		}
	}

	@RequiresRoles("admin")
	@RequestMapping(value = "/allUsers", method = RequestMethod.GET)
	@ResponseBody
	public List<User> getusers() {
		return userService.getallusers();
	}

	@RequestMapping(value = "/addUser", method = RequestMethod.POST)
	@ResponseBody
	public User adduser(@RequestBody User u) {
		String pwd = u.getPassword();
		String newpwd = passwordService.encryptPassword(pwd);
		u.setPassword(newpwd);
		System.out.println(newpwd);
		User user = userService.createUser(u);
		int uid = user.getUserid();
		List<Mapping_UR> urlist = u.getMapping_UR();
		if (urlist != null) {
			for (Mapping_UR ur : urlist) {
				if (ur != null) {
					int roleid = ur.getRole().getRoleid();
					userService.correlationRoles(uid, roleid);
				}
			}
		}

		return user;
	}

	@RequestMapping(value = "/updateUser/{uid}", method = RequestMethod.PUT)
	@ResponseBody
	public User updateuser(@PathVariable int uid, @RequestBody User u) {
		User user = userService.updateuser(u);
		if (u.getMapping_UR() != null && u.getMapping_UR().size() != 0) {
			userService.deleteuserroles(uid);
			List<Mapping_UR> urlist = u.getMapping_UR();
			for (Mapping_UR ur : urlist) {
				if (ur != null) {
					int roleid = ur.getRole().getRoleid();
					userService.correlationRoles(uid, roleid);
				}
			}
		}

		return user;
	}

	@RequestMapping(value = "/getUser/{uid}", method = RequestMethod.GET)
	@ResponseBody
	public User getuser(@PathVariable int uid) {
		User user = userService.getUser(uid);
		return user;
	}

	@RequiresRoles("admin")
	@RequestMapping(value = "/deleteUser/{uid}", method = RequestMethod.DELETE)
	@ResponseBody
	public Message deleteuser(@PathVariable int uid) throws UnauthorizedException {
		try {
			userService.deleteuserroles(uid);
			userService.deleteuser(uid);
			return new Message("delete success");
		} catch (Exception e) {
			e.printStackTrace();
			return new Message("delete failed");
		}
	}

	@RequestMapping(value = "/unauthorized", method = RequestMethod.GET)
	@ResponseBody
	public Message unauthorized() {
		return new Message("Unauthorized!");
	}

}
