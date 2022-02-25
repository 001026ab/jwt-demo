package com.pjb.springbootjjwt.api;

import com.alibaba.fastjson.JSONObject;
import com.pjb.springbootjjwt.annotation.PassToken;
import com.pjb.springbootjjwt.annotation.UserLoginToken;
import com.pjb.springbootjjwt.entity.User;
import com.pjb.springbootjjwt.service.TokenService;
import com.pjb.springbootjjwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * @author jinbin
 * @date 2018-07-08 20:45
 */
@RestController
@RequestMapping("api")
public class UserApi {
    @Autowired
    UserService userService;
    @Autowired
    TokenService tokenService;


    @PassToken
    //登录
    @PostMapping("/login")
    public Object login(User user) {
        user = new User("1", "zgr", "zgr1234");
        JSONObject jsonObject = new JSONObject();
        //User userForBase=userService.findByUsername(user);
        User userForBase = new User("1", "zgr", "zgr1234");
        if (userForBase == null) {
            jsonObject.put("message", "登录失败,用户不存在");
            return jsonObject;
        } else {
            if (!userForBase.getPassword().equals(user.getPassword())) {
                jsonObject.put("message", "登录失败,密码错误");
                return jsonObject;
            } else {
                //生成token，并且以用户密码作为秘钥进行加密
                String token = tokenService.getToken(userForBase);
                jsonObject.put("token", token);
                jsonObject.put("user", userForBase);
                return jsonObject;
            }
        }
    }

    //验证token，自定义注解
   // @UserLoginToken
    //不验证token
    //@PassToken
    @GetMapping("/getMessage")
    public String getMessage() {
        System.out.println("efefwrwrw");
        return "你已通过验证";
    }
}
